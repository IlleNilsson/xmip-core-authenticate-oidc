# xmip-core-authenticate-oidc

Authenticate by oidc: verifies an ID token against the issuer's published keys and the nonce. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It checks an ID token's RS256 or ES256 signature against a JWKS document held
as configuration, then issuer, audience, `azp`, expiry with leeway, the subject
and a nonce the node issued, spent once. It never fetches `jwks_uri` or a
discovery document (ADR-0045), and it does not check `at_hash` or `c_hash`.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
