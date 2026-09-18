#![forbid(unsafe_code)]

//! Authenticate by oidc: verifies an ID token against the issuer's published
//! keys and the nonce.
//!
//! The first gate read an ID token's `sub` and presented it as the claim,
//! with the issuer beside it and the token itself riding as the `oidc.token`
//! proof. This gate does what `OpenID Connect` Core 3.1.3.7 asks of a relying
//! party: the signature is checked against the issuer's published keys, the
//! `iss` is the issuer the node trusts, the `aud` names the node's client id
//! and an `azp`, where there is one, is that client id too, `exp` has not
//! passed and `nbf` has come, with the configured leeway, and the subject is
//! the value that was claimed.
//!
//! The nonce is the node's own. Whoever sent the authentication request
//! tells this verifier the nonce with [`Verifier::issued`]; a token must then
//! carry a nonce that is outstanding, and the nonce is spent when the token
//! proves, so an ID token replayed later is refused. A node that takes ID
//! tokens it never asked for — a machine presenting one as a bearer — says so
//! with [`Verifier::without_nonce`], and gives replay protection up knowingly.
//!
//! Offline throughout (ADR-0045): the key set is configuration, a JWKS
//! document handed to [`Jwks::parse`], never fetched from `jwks_uri`, and
//! rotated by whoever rotates configuration. RS256 and ES256 are verified;
//! any other algorithm, `none` and the HMAC family included, is refused by
//! name. `at_hash` and `c_hash` are not checked, because no access token or
//! code reaches this gate; `acr` and `auth_time` are authorization's.
//!
//! A node that expects one account says so with
//! [`Verifier::expecting_principal`]: the token's `upn`, else its
//! `preferred_username`, is then read as the identify capability's
//! `UserPrincipalName` and must be the same account, whichever way either
//! was spelled (ADR-0054). Without it nothing about the name is asked.

pub mod jwks;

pub use jwks::{Algorithm, Jwks};

use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use identify::UserPrincipalName;
use identify::jwt::Compact;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
use xcore::{Mechanism, mechanism};

/// The proof the identify sibling attaches the compact ID token under.
pub const TOKEN: &str = "oidc.token";

/// How many nonces may be outstanding before the oldest is forgotten.
const OUTSTANDING: usize = 4096;

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Seconds since the Unix epoch, now.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The oidc authenticator: one issuer, its keys as the node holds them, and
/// the client id the node is known to that issuer by.
pub struct Verifier {
    keys: Jwks,
    issuer: String,
    client: String,
    nonces: Option<Mutex<Vec<String>>>,
    principal: Option<UserPrincipalName>,
    leeway: i64,
    clock: Clock,
}

impl Verifier {
    /// Verifies tokens from `issuer` for the client id `client` against
    /// `keys`, requiring an outstanding nonce, with sixty seconds of leeway.
    #[must_use]
    pub fn new(keys: Jwks, issuer: impl Into<String>, client: impl Into<String>) -> Self {
        Self {
            keys,
            issuer: issuer.into(),
            client: client.into(),
            nonces: Some(Mutex::new(Vec::new())),
            principal: None,
            leeway: 60,
            clock: Box::new(now),
        }
    }

    /// Take tokens the node never asked for: no nonce is expected, and a
    /// token may be presented again until it expires.
    #[must_use]
    pub fn without_nonce(mut self) -> Self {
        self.nonces = None;
        self
    }

    /// Expect the token to name this account in its `upn`, else in its
    /// `preferred_username`. Any spelling of the same account meets it.
    #[must_use]
    pub fn expecting_principal(mut self, principal: UserPrincipalName) -> Self {
        self.principal = Some(principal);
        self
    }

    /// How far a clock may be off before `exp` and `nbf` bite.
    #[must_use]
    pub const fn with_leeway(mut self, seconds: i64) -> Self {
        self.leeway = seconds;
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Record a nonce the node sent in an authentication request. It proves
    /// one token and is then spent. Nothing is recorded where the verifier
    /// was built [`without_nonce`](Self::without_nonce).
    pub fn issued(&self, nonce: impl Into<String>) {
        if let Some(nonces) = &self.nonces {
            let mut outstanding = locked(nonces);
            if outstanding.len() >= OUTSTANDING {
                outstanding.remove(0);
            }
            outstanding.push(nonce.into());
        }
    }

    fn check_claims(&self, compact: &Compact, subject: &str) -> Result<(), AuthenticateError> {
        let now = (self.clock)();

        if compact.claim("iss").as_deref() != Some(self.issuer.as_str()) {
            return Err(AuthenticateError::new(format!(
                "the ID token's issuer is not '{}'",
                self.issuer
            )));
        }
        if !compact.strings_claim("aud").contains(&self.client) {
            return Err(AuthenticateError::new(format!(
                "the ID token's audience does not name this node's client id '{}'",
                self.client
            )));
        }
        if let Some(party) = compact.claim("azp")
            && party != self.client
        {
            return Err(AuthenticateError::new(format!(
                "the ID token was issued to '{party}' (azp) and not to '{}'",
                self.client
            )));
        }
        let Some(expiry) = compact.numeric_claim("exp") else {
            return Err(AuthenticateError::new(
                "the ID token carries no `exp` and OIDC requires one",
            ));
        };
        if now > expiry.saturating_add(self.leeway) {
            return Err(AuthenticateError::new(format!(
                "the ID token expired at {expiry} and it is {now}"
            )));
        }
        if let Some(not_before) = compact.numeric_claim("nbf")
            && now.saturating_add(self.leeway) < not_before
        {
            return Err(AuthenticateError::new(format!(
                "the ID token is not valid before {not_before} and it is {now}"
            )));
        }
        if compact.claim("sub").as_deref() != Some(subject) {
            return Err(AuthenticateError::new(
                "the ID token's subject is not the claimed value",
            ));
        }
        Ok(())
    }

    /// Where an account is expected, the token names it.
    fn check_principal(&self, compact: &Compact) -> Result<(), AuthenticateError> {
        let Some(expected) = &self.principal else {
            return Ok(());
        };
        let read = |claim: &str| {
            compact
                .claim(claim)
                .and_then(|text| UserPrincipalName::parse(&text))
        };
        match read("upn").or_else(|| read("preferred_username")) {
            Some(named) if named.is(expected) => Ok(()),
            Some(named) => Err(AuthenticateError::new(format!(
                "the ID token names '{named}' and this node expects '{expected}'"
            ))),
            None => Err(AuthenticateError::new(format!(
                "the ID token carries no user principal name in `upn` or \
                 `preferred_username` and this node expects '{expected}'"
            ))),
        }
    }

    /// Spend the token's nonce. Last, so a token that fails another check
    /// does not cost the login its nonce.
    fn spend_nonce(&self, compact: &Compact) -> Result<(), AuthenticateError> {
        let Some(nonces) = &self.nonces else {
            return Ok(());
        };
        let Some(nonce) = compact.claim("nonce") else {
            return Err(AuthenticateError::new(
                "the ID token carries no nonce and this node expects the one it sent",
            ));
        };
        let mut outstanding = locked(nonces);
        match outstanding.iter().position(|held| *held == nonce) {
            Some(at) => {
                outstanding.remove(at);
                Ok(())
            }
            None => Err(AuthenticateError::new(
                "the ID token's nonce is not one this node has outstanding: \
                 never sent, or already spent",
            )),
        }
    }
}

fn locked(nonces: &Mutex<Vec<String>>) -> MutexGuard<'_, Vec<String>> {
    nonces.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::oidc()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies oidc"
            )));
        }
        let token = presented
            .proof(TOKEN)
            .ok_or_else(|| AuthenticateError::new(format!("no {TOKEN} proof was presented")))?;
        let compact =
            Compact::parse(token).map_err(|failure| AuthenticateError::new(failure.message))?;

        let named = compact.algorithm().unwrap_or_default();
        let algorithm = Algorithm::named(&named).ok_or_else(|| {
            AuthenticateError::new(format!(
                "the ID token's algorithm '{named}' is not one this node verifies: \
                 RS256 and ES256 are"
            ))
        })?;
        self.keys.verify(
            algorithm,
            compact.key_id().as_deref(),
            compact.signing_input.as_bytes(),
            &compact.signature,
        )?;
        self.check_claims(&compact, &presented.value)?;
        self.check_principal(&compact)?;
        self.spend_nonce(&compact)?;

        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::tests::p256_jwk;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::traits::PublicKeyParts;

    const NOW: i64 = 1_800_000_000;
    const ISSUER: &str = "https://issuer.example";

    fn mint(header: &str, claims: &str, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn claims(extra: &str, expiry: i64) -> String {
        format!(
            r#"{{"iss":"{ISSUER}","sub":"partner-x","aud":["xmip-node"],"exp":{expiry}{extra}}}"#
        )
    }

    struct Issuer {
        key: p256::ecdsa::SigningKey,
    }

    impl Issuer {
        fn new() -> Self {
            Self {
                key: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
            }
        }

        fn jwks(&self) -> Jwks {
            Jwks::parse(&format!(r#"{{"keys":[{}]}}"#, p256_jwk("e1", &self.key))).expect("a set")
        }

        fn token(&self, claims: &str) -> String {
            mint(r#"{"alg":"ES256","kid":"e1"}"#, claims, |input| {
                let signature: p256::ecdsa::Signature = self.key.sign(input);
                signature.to_vec()
            })
        }

        fn verifier(&self) -> Verifier {
            Verifier::new(self.jwks(), ISSUER, "xmip-node").with_clock(|| NOW)
        }
    }

    fn presented(token: &str) -> Presented {
        Presented::passed(mechanism::oidc(), "partner-x").with_proof(TOKEN, token)
    }

    #[test]
    fn a_token_from_the_issuer_with_the_nonce_the_node_sent_is_proven_once() {
        let issuer = Issuer::new();
        let gate = issuer.verifier();
        gate.issued("n-0S6_WzA2Mj");
        let token = issuer.token(&claims(r#","nonce":"n-0S6_WzA2Mj""#, NOW + 300));

        let verified = gate.verify(&presented(&token)).expect("proven");
        let replayed = gate.verify(&presented(&token)).expect_err("spent");

        assert_eq!(verified, Verified::Proven);
        assert!(replayed.message.contains("already spent"));
    }

    fn expecting(issuer: &Issuer, principal: &str) -> Verifier {
        let principal = UserPrincipalName::parse(principal).expect("a name");
        issuer
            .verifier()
            .without_nonce()
            .expecting_principal(principal)
    }

    #[test]
    fn a_token_naming_the_expected_account_in_either_claim_and_spelling_is_proven() {
        let issuer = Issuer::new();
        let gate = expecting(&issuer, "PARTNERX\\jane");
        let by_upn = claims(
            r#","upn":"Jane@PartnerX","preferred_username":"x@y""#,
            NOW + 300,
        );
        let by_username = claims(r#","preferred_username":"jane@partnerx""#, NOW + 300);

        for claims in [by_upn, by_username] {
            let verified = gate.verify(&presented(&issuer.token(&claims)));
            assert_eq!(verified.expect("proven"), Verified::Proven, "{claims}");
        }
    }

    #[test]
    fn a_token_naming_another_account_is_refused_naming_both_and_one_naming_none_says_so() {
        let issuer = Issuer::new();
        let gate = expecting(&issuer, "jane@partnerx");
        let other = issuer.token(&claims(r#","upn":"mallory@partnerx""#, NOW + 300));
        let bare = issuer.token(&claims(r#","preferred_username":"jane""#, NOW + 300));

        let refused = gate.verify(&presented(&other)).expect_err("refused");
        let unnamed = gate.verify(&presented(&bare)).expect_err("refused");

        assert_eq!(
            refused.message,
            "the ID token names 'mallory@partnerx' and this node expects 'jane@partnerx'"
        );
        assert!(unnamed.message.contains("carries no user principal name"));
    }

    #[test]
    fn a_token_without_the_nonce_is_refused_unless_the_node_expects_none() {
        let issuer = Issuer::new();
        let token = issuer.token(&claims("", NOW + 300));

        let failure = issuer
            .verifier()
            .verify(&presented(&token))
            .expect_err("refused");
        let unasked = issuer.verifier().without_nonce().verify(&presented(&token));

        assert!(failure.message.contains("carries no nonce"));
        assert_eq!(unasked.expect("proven"), Verified::Proven);
    }

    #[test]
    fn a_token_signed_by_a_key_the_issuer_did_not_publish_is_refused() {
        let issuer = Issuer::new();
        let token = Issuer::new().token(&claims("", NOW + 300));

        let failure = issuer
            .verifier()
            .without_nonce()
            .verify(&presented(&token))
            .expect_err("refused");

        assert!(failure.message.contains("signature does not verify"));
    }

    #[test]
    fn an_expired_token_and_one_without_an_expiry_are_each_refused() {
        let issuer = Issuer::new();
        let gate = issuer.verifier().without_nonce();
        let expired = issuer.token(&claims("", NOW - 300));
        let endless = issuer.token(&format!(
            r#"{{"iss":"{ISSUER}","sub":"partner-x","aud":"xmip-node"}}"#
        ));

        let past = gate.verify(&presented(&expired)).expect_err("refused");
        let none = gate.verify(&presented(&endless)).expect_err("refused");

        assert!(past.message.contains("expired"));
        assert!(none.message.contains("no `exp`"));
    }

    #[test]
    fn another_issuer_audience_or_authorized_party_is_refused_by_name() {
        let issuer = Issuer::new();
        let gate = issuer.verifier().without_nonce();
        let exp = NOW + 300;
        let foreign = issuer.token(&format!(
            r#"{{"iss":"https://other.example","sub":"partner-x","aud":"xmip-node","exp":{exp}}}"#
        ));
        let elsewhere = issuer.token(&format!(
            r#"{{"iss":"{ISSUER}","sub":"partner-x","aud":"another-client","exp":{exp}}}"#
        ));
        let lent = issuer.token(&claims(r#","azp":"another-client""#, exp));

        let failures = [foreign, elsewhere, lent]
            .map(|token| gate.verify(&presented(&token)).expect_err("refused"));

        assert!(failures[0].message.contains("issuer is not"));
        assert!(failures[1].message.contains("audience"));
        assert!(failures[2].message.contains("azp"));
    }

    #[test]
    fn a_subject_that_is_not_the_claim_and_an_hmac_token_are_refused() {
        let issuer = Issuer::new();
        let gate = issuer.verifier().without_nonce();
        let token = issuer.token(&claims("", NOW + 300));
        let claim = Presented::passed(mechanism::oidc(), "someone-else").with_proof(TOKEN, &token);
        let hmac = mint(r#"{"alg":"HS256"}"#, &claims("", NOW + 300), |_| {
            vec![0; 32]
        });

        let subject = gate.verify(&claim).expect_err("refused");
        let algorithm = gate.verify(&presented(&hmac)).expect_err("refused");

        assert!(subject.message.contains("subject"));
        assert!(algorithm.message.contains("'HS256'"));
    }

    #[test]
    fn another_mechanism_and_a_missing_proof_are_each_refused_by_name() {
        let gate = Issuer::new().verifier();
        let other = Presented::passed(mechanism::jwt(), "partner-x").with_proof(TOKEN, "x.y.z");
        let bare = Presented::passed(mechanism::oidc(), "partner-x");

        assert!(
            gate.verify(&other)
                .expect_err("refused")
                .message
                .contains("'jwt' was presented")
        );
        assert!(
            gate.verify(&bare)
                .expect_err("refused")
                .message
                .contains("oidc.token")
        );
    }

    #[test]
    fn an_rs256_token_verifies_with_the_rsa_key_the_set_publishes() {
        let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("a key");
        let document = format!(
            r#"{{"keys":[{{"kty":"RSA","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
            URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())
        );
        let signer = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private);
        let token = mint(r#"{"alg":"RS256"}"#, &claims("", NOW + 300), |input| {
            signer.sign(input).to_vec()
        });
        let gate = Verifier::new(Jwks::parse(&document).expect("a set"), ISSUER, "xmip-node")
            .without_nonce()
            .with_clock(|| NOW);

        assert_eq!(
            gate.verify(&presented(&token)).expect("proven"),
            Verified::Proven
        );
    }
}
