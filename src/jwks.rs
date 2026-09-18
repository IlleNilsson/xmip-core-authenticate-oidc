//! The issuer's published keys: a JSON Web Key Set, held and never fetched.
//!
//! RFC 7517 publishes keys as `{"keys":[...]}`, each a JSON object naming its
//! type, and `OpenID Connect` Discovery points at the document through
//! `jwks_uri`. This node is offline by default (ADR-0045), so the document is
//! configuration: whoever installs the issuer's trust copies the set in, and
//! rotates it the same way. Of what a set may carry, this reads RSA keys
//! (`kty` `RSA`, `n` and `e`) for RS256 and P-256 keys (`kty` `EC`, `crv`
//! `P-256`, `x` and `y`) for ES256. A key marked `"use":"enc"` is not a
//! signing key and is passed over, as is a key of any other type; a set with
//! no key this gate can use is refused when it is loaded, not at the first
//! token.

use authenticate::AuthenticateError;
use rsa::sha2::Sha256;
use rsa::signature::Verifier as _;
use serde_json::Value;

/// One of the two signature algorithms this gate verifies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 over SHA-256, which OIDC Core makes the default.
    Rs256,
    /// ECDSA on P-256 over SHA-256.
    Es256,
}

impl Algorithm {
    /// The algorithm an `alg` header names, where it is one of the two.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "RS256" => Some(Self::Rs256),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }

    /// The `alg` name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

#[derive(Clone)]
enum Material {
    Rsa(rsa::RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
}

#[derive(Clone)]
struct Key {
    id: Option<String>,
    material: Material,
}

impl Key {
    const fn algorithm(&self) -> Algorithm {
        match self.material {
            Material::Rsa(_) => Algorithm::Rs256,
            Material::P256(_) => Algorithm::Es256,
        }
    }

    fn holds(&self, input: &[u8], signature: &[u8]) -> bool {
        match &self.material {
            Material::Rsa(key) => {
                let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
                rsa::pkcs1v15::Signature::try_from(signature)
                    .is_ok_and(|signature| key.verify(input, &signature).is_ok())
            }
            Material::P256(key) => p256::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(input, &signature).is_ok()),
        }
    }
}

/// The signing keys an issuer published, as the node holds them.
#[derive(Clone)]
pub struct Jwks {
    keys: Vec<Key>,
}

impl Jwks {
    /// Read a key set document.
    ///
    /// # Errors
    ///
    /// Where the text is not JSON with a `keys` array, a key of a type this
    /// gate reads is malformed, or no key in the set is one it can use.
    pub fn parse(document: &str) -> Result<Self, AuthenticateError> {
        let value: Value = serde_json::from_str(document).map_err(|failure| {
            AuthenticateError::new(format!("the JWKS is not JSON: {failure}"))
        })?;
        let listed = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| AuthenticateError::new("the JWKS has no `keys` array"))?;

        let mut keys = Vec::new();
        for entry in listed {
            if entry.get("use").and_then(Value::as_str) == Some("enc") {
                continue;
            }
            let material = match entry.get("kty").and_then(Value::as_str) {
                Some("RSA") => rsa_key(entry)?,
                Some("EC") if entry.get("crv").and_then(Value::as_str) == Some("P-256") => {
                    p256_key(entry)?
                }
                _ => continue,
            };
            keys.push(Key {
                id: entry.get("kid").and_then(Value::as_str).map(str::to_string),
                material,
            });
        }

        if keys.is_empty() {
            return Err(AuthenticateError::new(
                "the JWKS holds no RSA or P-256 signing key",
            ));
        }
        Ok(Self { keys })
    }

    /// How many signing keys the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Never: a set with no usable key does not load.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Check `signature` over `input`, with the key the token names or,
    /// where it names none, with any key of the algorithm.
    ///
    /// # Errors
    ///
    /// Where the set holds no such key, the named key serves another
    /// algorithm, or the signature does not verify.
    pub fn verify(
        &self,
        algorithm: Algorithm,
        key_id: Option<&str>,
        input: &[u8],
        signature: &[u8],
    ) -> Result<(), AuthenticateError> {
        let candidates: Vec<&Key> = match key_id {
            Some(id) => {
                let key = self
                    .keys
                    .iter()
                    .find(|key| key.id.as_deref() == Some(id))
                    .ok_or_else(|| {
                        AuthenticateError::new(format!(
                            "the issuer's key set as the node holds it has no key '{id}': \
                             the issuer may have rotated its keys"
                        ))
                    })?;
                if key.algorithm() != algorithm {
                    return Err(AuthenticateError::new(format!(
                        "the key '{id}' serves {} and the token is signed {}",
                        key.algorithm().name(),
                        algorithm.name()
                    )));
                }
                vec![key]
            }
            None => self
                .keys
                .iter()
                .filter(|key| key.algorithm() == algorithm)
                .collect(),
        };
        if candidates.is_empty() {
            return Err(AuthenticateError::new(format!(
                "the issuer's key set holds no {} key and the token names none",
                algorithm.name()
            )));
        }

        if candidates.iter().any(|key| key.holds(input, signature)) {
            Ok(())
        } else {
            Err(AuthenticateError::new(format!(
                "the {} signature does not verify with the issuer's published key",
                algorithm.name()
            )))
        }
    }
}

/// One base64url member of a key, decoded by the capability's reader.
fn member(entry: &Value, name: &str) -> Result<Vec<u8>, AuthenticateError> {
    let text = entry
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| AuthenticateError::new(format!("a key in the JWKS has no `{name}`")))?;
    identify::jwt::decode(text, name).map_err(|_| {
        AuthenticateError::new(format!("a key's `{name}` in the JWKS is not base64url"))
    })
}

fn rsa_key(entry: &Value) -> Result<Material, AuthenticateError> {
    rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&member(entry, "n")?),
        rsa::BigUint::from_bytes_be(&member(entry, "e")?),
    )
    .map(Material::Rsa)
    .map_err(|_| AuthenticateError::new("an RSA key in the JWKS is not a usable key"))
}

fn p256_key(entry: &Value) -> Result<Material, AuthenticateError> {
    let (x, y) = (member(entry, "x")?, member(entry, "y")?);
    if x.len() != 32 || y.len() != 32 {
        return Err(AuthenticateError::new(
            "a P-256 coordinate in the JWKS is not thirty-two bytes",
        ));
    }
    let point = p256::EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        false,
    );
    p256::ecdsa::VerifyingKey::from_encoded_point(&point)
        .map(Material::P256)
        .map_err(|_| AuthenticateError::new("a P-256 key in the JWKS is not on the curve"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::signature::Signer;

    /// A P-256 key as a JWK, as an issuer would publish it.
    pub(crate) fn p256_jwk(id: &str, key: &p256::ecdsa::SigningKey) -> String {
        let point = key.verifying_key().to_encoded_point(false);
        format!(
            r#"{{"kty":"EC","crv":"P-256","use":"sig","kid":"{id}","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(point.x().expect("x")),
            URL_SAFE_NO_PAD.encode(point.y().expect("y"))
        )
    }

    fn signing_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng)
    }

    #[test]
    fn a_published_p256_key_verifies_what_its_private_half_signed() {
        let key = signing_key();
        let set = Jwks::parse(&format!(r#"{{"keys":[{}]}}"#, p256_jwk("e1", &key))).expect("set");
        let signature: p256::ecdsa::Signature = key.sign(b"input");

        assert_eq!(set.len(), 1);
        assert!(
            set.verify(Algorithm::Es256, Some("e1"), b"input", &signature.to_vec())
                .is_ok()
        );
        let failure = set
            .verify(Algorithm::Es256, Some("e1"), b"other", &signature.to_vec())
            .expect_err("refused");
        assert!(failure.message.contains("does not verify"));
    }

    #[test]
    fn a_key_the_set_does_not_hold_is_refused_as_a_possible_rotation() {
        let key = signing_key();
        let set = Jwks::parse(&format!(r#"{{"keys":[{}]}}"#, p256_jwk("e1", &key))).expect("set");

        let failure = set
            .verify(Algorithm::Es256, Some("e2"), b"input", b"sig")
            .expect_err("refused");

        assert!(failure.message.contains("no key 'e2'"));
        assert!(failure.message.contains("rotated"));
    }

    #[test]
    fn a_key_asked_to_serve_another_algorithm_is_refused_by_both_names() {
        let key = signing_key();
        let set = Jwks::parse(&format!(r#"{{"keys":[{}]}}"#, p256_jwk("e1", &key))).expect("set");

        let failure = set
            .verify(Algorithm::Rs256, Some("e1"), b"input", b"sig")
            .expect_err("refused");

        assert!(failure.message.contains("serves ES256"));
    }

    #[test]
    fn a_set_with_only_encryption_or_unknown_keys_does_not_load() {
        let document = r#"{"keys":[{"kty":"oct","k":"AA"},{"kty":"RSA","use":"enc"}]}"#;

        let failure = Jwks::parse(document).err().expect("refused");

        assert!(failure.message.contains("no RSA or P-256 signing key"));
    }

    #[test]
    fn a_document_that_is_not_a_key_set_is_refused_by_what_it_lacks() {
        let failure = Jwks::parse(r#"{"issuer":"x"}"#).err().expect("refused");

        assert!(failure.message.contains("`keys`"));
    }
}
