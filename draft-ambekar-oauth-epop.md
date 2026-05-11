---
title: "JSON Web Token (JWT) Profile for OAuth 2.0 Enveloped Proof of Possession (EPOP)"
abbrev: "EPOP"
category: std

docname: draft-ambekar-oauth-epop-latest
submissiontype: IETF
number:
date:
consensus: false
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - EPOP
 - oauth
 - proof-of-possession
 - sender-constrained
 - token binding
 - jwt profile
 - token profile

venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "asambeka/epop"
  latest: "https://asambeka.github.io/epop/draft-ambekar-oauth-epop.html"

author:
 -
    fullname: Ashwin Ambekar
    organization: eBay
    email: [ambekar@gmail.com , aambekar@ebay.com]

normative:
  RFC2104:
  RFC3629:
  RFC4422:
  RFC4648:
  RFC5801:
  RFC5869:
  RFC6749:
  RFC7009:
  RFC7235:
  RFC7515:
  RFC7517:
  RFC7519:
  RFC7628:
  RFC7636:
  RFC7638:
  RFC7662:
  RFC8414:
  RFC8693:
  RFC8725:
  RFC9126:
  RFC9449:
  RFC9728:

informative:
  RFC8126:
  RFC8792:

...

--- abstract

This specification defines a profile for OAuth 2.0 sender-constrained credentials in which authorization codes, access tokens, and refresh tokens are cryptographically bound to the client's private key as a single inseparable envelope. The profile extends sender-constraining beyond HTTP to non-HTTP transports including MQTT, Kafka, the Model Context Protocol (MCP), gRPC, and SASL-based protocols such as those defined in {{RFC7628}}. It introduces atomic proof-of-possession key rotation, enabling clients to rotate key pairs without disrupting active sessions, and an offline-derived client nonce (`cnonce`) that eliminates the server-issued nonce round-trip required by existing mechanisms — enabling stateless proof validation critical for non-HTTP and high-throughput deployments. Authorization servers, resource servers, and clients from different vendors can implement this profile interoperably.

--- middle

# Introduction

OAuth 2.0 {{RFC6749}} access tokens are bearer tokens by default: any party in possession of a token can use it, regardless of whether that party is the legitimate client to which the token was issued. This property makes token theft a practical attack — intercepted tokens can be replayed without further credential material.

Sender-constraining mechanisms address this by cryptographically binding a token to the client's key pair so that possession of the token alone is insufficient to use it. Demonstrating Proof of Possession (DPoP) {{RFC9449}} introduced sender-constraining for HTTP-based OAuth flows. However, DPoP relies on HTTP-specific request parameters (`htm`, `htu`) and a server-issued nonce mechanism that requires an additional round-trip and imposes per-client nonce state management on servers — making it unsuitable for non-HTTP transports such as MQTT, Kafka, gRPC, and SASL-based protocols. No existing specification provides an interoperable sender-constraining profile that operates uniformly across both HTTP and non-HTTP transports.

A further deployment challenge with DPoP is the requirement to propagate two distinct HTTP headers — `Authorization: DPoP <token>` and `DPoP: <proof>` — as an inseparable pair through every layer of a distributed system. API gateways, reverse proxies, and service-mesh sidecars must each be updated to recognize and forward the `DPoP` header; many intermediaries strip non-standard headers by default. Every resource server onboarded to DPoP must separately implement dual-header awareness and proof validation. A single hop that discards the `DPoP` header silently invalidates the proof-of-possession guarantee for the entire request chain, creating a widespread integration burden across heterogeneous microservice deployments.

This document defines the Enveloped Proof of Possession (EPOP) profile for OAuth 2.0 credentials. In this profile, the OAuth credential — authorization code, access token, or refresh token — is nested within the `ntk` (Nested Token) claim ({{token-payload}}) of a signed JSON Web Token (JWT) {{RFC7519}} envelope. The entire structure, credential and proof together, is signed with the client's private key. The credential and the proof of possession are a single, inseparable cryptographic object: there is no credential without a proof.

The profile introduces a protocol-neutral `rctx` (Request Context) claim ({{token-payload}}) that replaces the HTTP-specific `htm`/`htu` claims of DPoP, enabling EPOP tokens to operate over any transport without protocol-specific adaptation. An offline-derived client nonce (`cnonce`) ({{cnonce}}) computed from public inputs eliminates the server-issued nonce round-trip required by {{RFC9449}}, enabling stateless proof validation particularly suited to non-HTTP and high-throughput transports. The profile further defines atomic proof-of-possession key rotation, in which a client introduces a new key pair during a token refresh without disrupting the active session, and extends coverage to the full OAuth token lifecycle including token revocation and token exchange.

For SASL-based protocols, this document defines `OAUTHEPOP`, a new SASL mechanism extending {{RFC7628}} with sender-constraining support. All behaviors defined in {{RFC7628}} remain in effect; this document adds only the EPOP-specific authentication type and key binding verification.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Conformance requirements for EPOP-issuing Authorization Servers, EPOP-validating Resource Servers, and EPOP Clients are summarized in {{conformance}}.

The following terms are used throughout this document:

EPOP Token:
: A signed JWT ({{RFC7519}}) with `typ: epop+jwt`, signed by the client's private key. Contains an OAuth 2.0 credential in the `ntk` claim when used for resource access, token refresh, token revocation, or token exchange. In authorization code exchange and PAR flows, contains only `cnf.jkt` for key binding; the authorization code travels as the standard `code` form parameter and is never embedded in `ntk`.

Nested Token (ntk):
: The OAuth 2.0 credential (access token, refresh token, or another EPOP token for key rotation) embedded inside an EPOP token's payload. Not present in EPOP tokens used for authorization code exchange.

Request Context (rctx):
: A JSON object in the EPOP payload that identifies the target resource and protocol action, replacing the HTTP-specific `htm`/`htu` claims of DPoP.

Client Nonce (cnonce):
: An HMAC value derived offline from the client's public key, an optional server-supplied seed, and a time-step counter, providing replay resistance without server-issued nonce state.

Authorization Server (AS):
: A server that issues OAuth 2.0 tokens to clients. As defined in {{RFC6749}}.

Resource Server (RS):
: A server that hosts protected resources and accepts OAuth 2.0 tokens. As defined in {{RFC6749}}.

Client:
: An application that requests OAuth 2.0 tokens and uses them to access protected resources. As defined in {{RFC6749}}.

JWK Thumbprint:
: The SHA-256 thumbprint of a JSON Web Key, computed as defined in {{RFC7638}}.

## Conformance {#conformance}

This specification defines normative requirements for three conformance roles:

EPOP-issuing Authorization Server:
: An AS that issues EPOP-bound tokens MUST bind all issued tokens to the client's public key via `cnf.jkt`, MUST validate EPOP tokens presented at the token endpoint per {{validating-epop}}, and MUST publish EPOP capability metadata per {{discovery}}.

EPOP-validating Resource Server:
: An RS that accepts EPOP tokens MUST verify the outer envelope signature, MUST validate `rctx` members when `rctx` is present, and MUST verify `cnf.jkt` against the key in the EPOP token header per {{validating-epop}}.

EPOP Client:
: A client producing EPOP tokens MUST sign each token with the private key whose public component appears in the EPOP token header, MUST NOT reuse `jti` values, and MUST derive `cnonce` per {{cnonce}} when the AS requires it.

# EPOP Token Profile {#token-profile}

An EPOP token is a signed JWT ({{RFC7519}}) with `typ: epop+jwt`.

## Header {#token-header}

`typ`
: REQUIRED. MUST be `epop+jwt`.

`alg`
: REQUIRED. Asymmetric signature algorithm. Edwards curve algorithms are RECOMMENDED for their superior security, performance, and payload compactness; see {{sec-algorithm-selection}}. Symmetric algorithms (`HS*`) and `none` MUST NOT be used.

`jwk`
: REQUIRED. The client's public key as a JWK ({{RFC7517}}). MUST NOT contain private key material.

Example header:

~~~json
{
  "typ": "epop+jwt",
  "alg": "EdDSA",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "<base64url-encoded-x>"
  }
}
~~~

## Payload {#token-payload}

`jti`
: REQUIRED. Unique JWT ID with high entropy (see {{sec-replay-prevention}}). Servers MUST maintain a replay cache keyed on `jti`.

`iat`
: REQUIRED. Issued-at Unix timestamp. Servers MUST reject tokens older than the server-defined maximum EPOP lifetime or issued in the future beyond clock skew. EPOP tokens MUST be short-lived, per-request credentials. The `exp` claim MUST NOT be included; the validity window is controlled entirely by the server's `iat`-based lifetime policy and, when `cnonce` is required, by `epop_cnonce_step_seconds`.

`ntk`
: CONDITIONAL. The nested OAuth 2.0 credential. REQUIRED for resource access, token refresh, token revocation, and introspection. OMITTED in authorization code exchange flows; the authorization code travels as the standard `code` form parameter. JWT credentials (access tokens, refresh tokens, and inner EPOP tokens for key rotation) are encoded as compact-serialized JWTs; opaque credentials are Base64URL-encoded opaque strings.

`cnonce`
: RECOMMENDED. Offline-derived client nonce (see {{cnonce}}). MUST be included when the server publishes `epop_cnonce_required: true`.

`rctx`
: OPTIONAL. Request context object. When present, all recognized members MUST be validated by the server. Unrecognized members MUST be ignored. Future `rctx` member names will be registered in the EPOP Request Context Members registry ({{iana-rctx}}).

`rctx.res`
: OPTIONAL. URI or URN of the target resource or endpoint.

`rctx.method`
: RECOMMENDED. Protocol action string. Case-insensitive for HTTP methods; case-sensitive otherwise.

`rctx.id`
: OPTIONAL. Client-generated correlation ID for async or multiplexed protocols.

`cnf.jkt`
: CONDITIONAL. SHA-256 JWK Thumbprint ({{RFC7638}}) of the client's public key. REQUIRED in authorization code exchange and in the inner envelope of a key rotation request. SHOULD be omitted on routine resource access and simple refresh where the key is already bound to the token.

Example payload:

~~~json
{
  "jti": "A8B2B026-6C81-4A8C-A403-0F225E3DFEED",
  "iat": 1775749791,
  "ntk": "<credential>",
  "cnonce": "<base64url-hmac-value>",
  "rctx": {
    "res": "https://api.example.com/orders",
    "method": "GET",
    "id": "req_5521"
  },
  "cnf": {
    "jkt": "<sha256-thumbprint-of-public-key>"
  }
}
~~~


# Issuing and Constructing EPOP Tokens {#creating-epop}

The client MUST have an asymmetric key pair (private key held exclusively by the client; public key embedded in every EPOP header), a reliable source of high-entropy identifiers for `jti`, and a trusted clock for `iat`.

An EPOP token is a JWS ({{RFC7515}}) signed with the client's private key, carrying the header and payload claims defined in {{token-header}} and {{token-payload}}. The compact serialization is transmitted as:

- **Token endpoint and PAR**: the `epop` form parameter in the POST body, preserving the `Authorization` header for client authentication.
- **Resource server**: `Authorization: EPOP <compact-serialized-epop-token>` per {{RFC7235}}.

When the AS issues tokens in response to a valid EPOP request, it MUST bind the issued credential to the client's public key by including `cnf.jkt` — the SHA-256 JWK Thumbprint ({{RFC7638}}) of the EPOP token's `jwk` — in the response. For opaque tokens, the AS MUST record this binding server-side for use by the introspection endpoint. The AS MUST NOT issue EPOP-bound tokens unless the EPOP token has been successfully validated per {{validating-epop}}.

The token endpoint response MUST include `"token_type": "EPOP"` for all EPOP-bound credentials, per {{RFC6749}} Section 5.1. This signals to the client that the issued token must be presented using the `Authorization: EPOP` scheme at the RS.

# Validating an EPOP Token {#validating-epop}

To validate an EPOP token, the receiving server MUST ensure all of the following:

1. The `typ` header value is `epop+jwt`.
2. The `jwk` header is a valid asymmetric public key with no private key material.
3. The JWS signature verifies with the public key in `jwk`.
4. The `iat` is within an acceptable window, accounting for clock skew and the server's maximum EPOP lifetime policy.
5. The `jti` has not been seen before; record it and reject any future token presenting the same value.
6. If the server requires `cnonce` (i.e., `epop_cnonce_required` is `true` in its discovery document), the `cnonce` claim MUST be present. If `cnonce` is present, it MUST be valid for the current time-step (see {{cnonce-validation}}).
7. If `rctx` is present, its members match the current request context; unrecognized members MUST be ignored.
8. If `ntk` is present, `sha256(jwk)` MUST equal `cnf.jkt` from the nested credential (see {{ntk-validation}}). This check MUST be performed after steps 1–3 pass.

These checks apply at both the AS (token endpoint, PAR) and RS (resource access). The server MUST reject the request with an appropriate error (see {{error-responses}}) if any check fails.

## Error Responses {#error-responses}

When a server rejects an EPOP token, it MUST respond as follows.

At the **token endpoint** (AS), validation failures MUST result in an HTTP 400 response with an OAuth error body per {{RFC6749}} Section 5.2. The `error` value MUST be `invalid_request` for structural failures (e.g., missing `typ`, invalid `jwk` format) and `invalid_grant` for credential failures (e.g., expired `iat`, replayed `jti`, invalid `cnonce`, `cnf.jkt` mismatch).

At the **resource server**, validation failures MUST result in an HTTP 401 response with a `WWW-Authenticate` challenge using the `EPOP` scheme per {{RFC7235}}:

~~~http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: EPOP error="invalid_token",
                  error_description="EPOP token validation failed"
~~~

The `error` parameter MUST be `invalid_token` for any EPOP envelope or key binding failure. Servers MAY include `error_description` with a human-readable explanation. Servers MUST NOT reveal which specific validation step failed, as such information could aid an attacker.

## Nested Credential Validation {#ntk-validation}

When `ntk` is present and the outer envelope has passed steps 1–7, the server MUST perform the key binding check (step 8) and then validate the nested credential:

- **JWT (access or refresh token)**: verify signature, `iss`, `exp`, `aud`, and scopes.
- **Opaque token**: introspect with the AS per {{RFC7662}}.
- **Inner EPOP (key rotation)**: apply steps 1–8 to the inner envelope; `cnf.jkt` in the inner envelope identifies the new key.

The key binding check requires `sha256(outer jwk) == cnf.jkt` from the nested credential. If this check fails, the server MUST reject the request with `invalid_token`.

# OAuth 2.0 Flows with EPOP {#flows}

## Authorization Server Flows {#as-flows}

### OAuth 2.0 Protocol Changes Summary {#as-protocol-changes}

| Element | Change | Impacted Flows |
|:---|:---|:---|
| `grant_type` | New values: `epop_code_grant`, `epop_refresh_token` | Authorization code exchange, token refresh |
| `epop` | New form parameter; carries compact-serialized EPOP token | Authorization code exchange, token refresh, PAR |
| `actor_token_type` | New values: `urn:ietf:params:oauth:token-type:epop_access_token`, `urn:ietf:params:oauth:token-type:epop_refresh_token` | Token exchange |
| `token_type_hint` | New value: `epop_token` | Token revocation, token introspection |
| Issued token response | AS MUST include `cnf.jkt` binding in all issued tokens | All grant flows |
| PKCE (`code_challenge`) | Elevated from RECOMMENDED to REQUIRED | Authorization code exchange, PAR |

### Authorization Code Flow with PKCE {#auth-code-flow}

PKCE ({{RFC7636}}) is REQUIRED in all EPOP authorization code flows. PKCE and EPOP protect complementary attack surfaces: PKCE binds the authorization request to the token request; EPOP binds the authorization code to the client's key pair. Without PKCE, an attacker who intercepts the authorization code could generate their own key pair and wrap the code in a valid EPOP token signed with their key. Together they provide end-to-end chain of trust from the authorization request through token issuance (see {{fig-auth-code-flow}}).

~~~
Client                           AS                         RS
  |                              |                           |
  |-- 1. Authorization Request ->|                           |
  |   (code_challenge, PKCE)     |                           |
  |                              |                           |
  |<-- 2. Authorization Code ----|                           |
  |                              |                           |
  |-- 3. Token Request (POST) -->|                           |
  |   grant_type=epop_code_grant |  (abbreviated; full URN)  |
  |   epop=<token: cnf.jkt,rctx>|                           |
  |   + code, code_verifier      |                           |
  |   (form parameters)          |                           |
  |                              |                           |
  |<-- 4. Access Token ----------|                           |
  |   (cnf.jkt bound to key)     |                           |
  |                              |                           |
  |-- 5. Resource Request ---------------------------------->|
  |   Authorization: EPOP <epop-token: AT in ntk, rctx>     |
  |                              |                           |
  |<-- 6. Protected Response --------------------------------|
~~~
{: #fig-auth-code-flow title="Authorization Code Flow with EPOP and PKCE"}

Token request (Step 3):

~~~ http
NOTE: '\' line wrapping per {{RFC8792}}

POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Aepop_code_grant
&code=SplxlOBeZQQYbYS6WxSbIA
&client_id=s6BhdRkqt3
&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
&code_verifier=bEaL42izcC-o-xBk0K2vuJ6U-y1p9r_wW2dFWIWgjz-
&epop=eyJ0eXAiOiJlcG9wK2p3dCIsImFsZyI6IkVkRFNBIiwiandrIjp7Imt0eSI6Ik9\
LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMTFxWUFZS3hDcmZWU183VHlXUUhPZzdoY3Z\
QYXBpTWxyd0lhYVBjSFVSbyJ9fQ.eyJqdGkiOiJBOEIyQjAyNi02QzgxLTRBOEMtQTQw\
My0wRjIyNUUzREZFRUQiLCJpYXQiOjE3NzU3NDk3OTEsImNuZiI6eyJqa3QiOiJrUHJL\
X3FteFZXYVlWQTl3d0JGNkl1bzN2Vnp6N1R4SENUd1hCeWdyUzRrIn0sInJjdHgiOnsi\
cmVzIjoiaHR0cHM6Ly9hcy5leGFtcGxlLmNvbS90b2tlbiIsIm1ldGhvZCI6IlBPU1Qi\
fX0.I45kzp-niCPrDZoHUA_n9vor9lqjBD7Pw3hNcaecAVkCKl2yyZIUqZseociCHt_U\
U60NFDLx6kEE8NWIR4aYAQ
~~~

Decoded EPOP token payload for this request (`cnf.jkt` declares the client's key binding; `ntk` is absent because the authorization code travels as the `code` form parameter per standard OAuth 2.0):

~~~json
{
  "jti": "A8B2B026-6C81-4A8C-A403-0F225E3DFEED",
  "iat": 1775749791,
  "cnf": {
    "jkt": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
  },
  "rctx": {
    "res": "https://as.example.com/token",
    "method": "POST"
  }
}
~~~

Token endpoint response (Step 4):

~~~json
{
  "access_token": "<compact-serialized-jwt-access-token>",
  "token_type": "EPOP",
  "expires_in": 3600
}
~~~

The issued access token returned by the AS carries the `cnf.jkt` binding:

~~~json
{
  "sub": "jdoe@acme.org",
  "aud": ["https://api.example.com"],
  "cnf": {
    "jkt": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
  },
  "iat": 1775749800,
  "exp": 1775753400
}
~~~

### Token Refresh Flow {#refresh-flow}

The client wraps the refresh token in the `ntk` claim of an EPOP token and submits it using the `epop_refresh_token` grant type:

~~~http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Aepop_refresh_token
&client_id=s6BhdRkqt3
&epop=<compact-serialized-epop-token>
~~~

#### Simple Refresh {#simple-refresh}

The EPOP token wraps the refresh token directly in `ntk`:

~~~json
{
  "jti": "<unique-id>",
  "iat": "<unix-time>",
  "ntk": "<refresh-token-opaque-or-jwt>",
  "rctx": { "res": "https://as.example.com/token", "method": "POST" }
}
~~~

After standard EPOP validation ({{validating-epop}}), the AS validates the nested refresh token. For an opaque token, the AS looks it up in the server-side store, verifies it is not revoked or expired, and confirms the associated key matches `sha256(outer jwk)`. For a JWT refresh token, the AS verifies the signature, `iss`, `exp`, and `jti`, then confirms `cnf.jkt == sha256(outer jwk)`.

#### Key Rotation Refresh {#key-rotation-refresh}

Key rotation uses a two-layer structure. The inner envelope is a Simple Refresh EPOP token (signed with the OLD key) with one addition: `cnf.jkt` set to the thumbprint of the NEW key. The outer envelope, signed with the NEW key, carries the compact-serialized inner EPOP token in `ntk`:

~~~json
{
  "jti": "<unique-id-outer>",
  "iat": "<unix-time>",
  "ntk": "<compact-serialized-inner-epop-token>"
}
~~~

Standard EPOP validation ({{validating-epop}}) applies to both envelopes. Beyond that, the AS verifies the key handoff chain: `sha256(inner jwk)` MUST match the key previously bound to the refresh token, and `sha256(outer jwk)` MUST equal `inner cnf.jkt`. On success, the AS issues new tokens bound to `sha256(outer jwk)`, atomically updates the server-side key binding, and revokes the old key for this session. The old key's authorization of the new key's introduction, combined with the new key's simultaneous proof of possession, provides a non-repudiable chain of custody.

### Token Introspection {#token-introspection}

Token introspection ({{RFC7662}}) for EPOP tokens supports two modes.

#### Mode 1: Inner Token Introspection {#introspection-inner}

The caller extracts the access token from the `ntk` claim of the received EPOP token and submits it to the introspection endpoint with the appropriate `token_type_hint` (e.g., `access_token`):

~~~http
POST /introspect HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <rs-credentials>

token=<access-token-extracted-from-ntk>
&token_type_hint=access_token
~~~

The introspection response includes `cnf.jkt`. The caller MUST verify that `sha256(EPOP token signing key)` equals the `cnf.jkt` returned in the response. This check confirms that the EPOP envelope was signed by the key legitimately bound to the nested token.

#### Mode 2: Full EPOP Token Introspection {#introspection-epop}

The caller sends the entire EPOP token to the introspection endpoint with `token_type_hint=epop_token`:

~~~http
POST /introspect HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <rs-credentials>

token=<epop-token-received-from-client>
&token_type_hint=epop_token
~~~

The AS validates the EPOP envelope signature, extracts the credential from `ntk`, and validates it. The AS MUST verify that `sha256(EPOP token signing key)` equals the `cnf.jkt` in the nested token before returning a response. This check prevents a caller from presenting a valid EPOP envelope wrapping a token not bound to that key.

In both modes the introspection response includes `cnf.jkt`. For opaque tokens, `cnf.jkt` is the server-side registered client EPOP public key; for JWT tokens it is extracted from the token's own `cnf.jkt` claim. The `token_type` field reflects the type of the inner access token in `ntk`, not the outer EPOP envelope.

~~~json
{
  "active": true,
  "token_type": "Bearer",
  "sub": "jdoe@acme.org",
  "iss": "https://as.example.com",
  "aud": ["https://api.example.com"],
  "scope": "read:orders",
  "iat": 1775748567,
  "exp": 1775752167,
  "cnf": {
    "jkt": "NLp8qGUJ1ywXs4ayYFLHfh8TA0crUe4g78UyBfx5j0Y"
  }
}
~~~

### Token Exchange {#token-exchange}

Clients can exchange an EPOP-wrapped token for a new token using the token exchange framework ({{RFC8693}}). In this flow the client is the actor — it acts on behalf of a subject and proves its identity by presenting the EPOP token as the `actor_token`. The `subject_token` carries the token being exchanged on behalf of the subject; `subject_token_type` identifies its format. The `actor_token_type` identifies the EPOP token format using the `epop_access_token` token type identifier ({{iana-token-types}}):

~~~http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&subject_token=<subject-access-token>
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
&actor_token=<compact-serialized-epop-token>
&actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aepop_access_token
&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aepop_access_token
~~~

The AS MUST validate the EPOP envelope per {{validating-epop}} before processing the exchange. The AS MUST also validate the `subject_token` independently per its token type. The AS issues a new EPOP-wrapped access token bound to the same client public key, or to a new key if the exchange request includes key rotation.

Token exchange response:

~~~json
{
  "access_token": "<compact-serialized-epop-bound-access-token>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:epop_access_token",
  "token_type": "EPOP",
  "expires_in": 3600
}
~~~

The issued access token carries `cnf.jkt` bound to the client's public key, as in all EPOP flows.

### Token Revocation {#token-revocation}

Clients revoke EPOP-wrapped tokens using the token revocation framework ({{RFC7009}}). The client constructs and signs the EPOP token containing the credential to be revoked, then submits it as the `token` parameter with a `token_type_hint` identifying the credential type:

~~~http
POST /revoke HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=<compact-serialized-epop-token>
&token_type_hint=epop_token
~~~

The AS MUST validate the EPOP envelope per {{validating-epop}} before processing revocation. The `token_type_hint` value MUST be `epop_token` ({{iana-token-type-hint}}).

The requirement that the client construct and sign the EPOP envelope provides proof-of-possession on revocation: an attacker who captured a token but does not hold the corresponding private key cannot revoke it. This is a deliberate security improvement over plain RFC 7009 revocation, where any party holding the raw token value can submit a revocation request.

### Pushed Authorization Requests {#par}

For PAR ({{RFC9126}}), the client MAY declare its public key fingerprint at the PAR endpoint to pre-bind the authorization code to the client's key before the browser redirect. The client includes the EPOP token as the `epop` form parameter — with `cnf.jkt` and `rctx` but no `ntk` — alongside the standard PAR request parameters. The `Authorization` header carries client authentication as usual. PKCE parameters (`code_challenge`, `code_challenge_method`) MUST be included in the PAR request (this specification elevates PKCE from RECOMMENDED in {{RFC9126}} to REQUIRED in all EPOP flows); the subsequent token endpoint request MUST include `code_verifier`.

EPOP token payload for the PAR request:

~~~json
{
  "jti": "<unique-id>",
  "iat": "<unix-time>",
  "cnf": { "jkt": "<client-public-key-thumbprint>" },
  "rctx": {
    "res": "https://as.example.com/par",
    "method": "POST"
  }
}
~~~

HTTP request:

~~~http
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

response_type=code
&client_id=s6BhdRkqt3
&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
&scope=read%3Aorders
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
&epop=<compact-serialized-epop-token>
~~~

The AS verifies the EPOP signature, extracts `cnf.jkt`, and records it against the `request_uri` it returns. Once a `cnf.jkt` is registered via PAR, that key binding is final for the lifetime of the resulting authorization code. If the EPOP token presented at the token endpoint declares a different `cnf.jkt` than the one recorded at the PAR endpoint, the AS MUST reject the request.

### Unsupported Flows {#unsupported-flows}

#### Client Credentials Flow {#client-credentials-flow}

Client credentials flow is not covered by this specification.

#### Authorization Request Key Binding Not Supported {#auth-request-binding}

Binding a public key thumbprint inside the authorization request URL (analogous to `dpop_jkt` in {{RFC9449}} Section 10) is not supported; see {{sec-auth-request-binding}} for the security rationale.

## Resource Server Flows {#rs-flows}

### Resource Access {#resource-access}

The client sends the EPOP token in the HTTP `Authorization` header using the `EPOP` authentication scheme ({{RFC7235}}). No `Authorization: Bearer` header is used.

EPOP token payload:

~~~json
{
  "jti": "626545DF-CD19-48EA-BB85-974130E012B5",
  "iat": 1775749791,
  "ntk": "<compact-serialized-access-token>",
  "rctx": {
    "res": "https://api.example.com/orders",
    "method": "GET"
  }
}
~~~

HTTP request:

~~~http
GET /orders HTTP/1.1
Host: api.example.com
Authorization: EPOP <compact-serialized-epop-token>
~~~

The RS verifies the outer envelope, then extracts and validates the access token from `ntk` as defined in {{ntk-validation}}.

### Non-HTTP and Agentic Protocols {#non-http-protocols}

The EPOP token structure is identical for non-HTTP protocols; only `rctx` values differ. The `rctx.res` field accommodates any URI or URN:

| Protocol | `rctx.res` | `rctx.method` |
|:---|:---|:---|
| HTTPS | `https://api.example.com/orders` | `GET` |
| MQTT | `urn:mqtt:broker:sensors/temperature` | `PUBLISH` |
| MCP | `urn:mcp:server:filesystem` | `tools/call` |
| Kafka | `urn:kafka:cluster:orders-topic` | `Produce` |
| gRPC | `urn:grpc:service:helloworld.Greeter` | `SayHello` |

The `rctx.id` field lets the server correlate the EPOP token with an asynchronous response — critical in multiplexed or streaming protocols where request/response pairs are not strictly sequential:

~~~json
{
  "jti": "9F3A1C22-4D87-4B3E-BC12-0A5E8D7F1234",
  "iat": 1775750000,
  "ntk": "<compact-serialized-access-token>",
  "rctx": {
    "res": "urn:mcp:server:filesystem",
    "method": "tools/call",
    "id": "req_5521"
  }
}
~~~

### SASL Integration {#sasl}

This section extends {{RFC7628}} to support Enveloped Proof of Possession. All behaviors defined in {{RFC7628}} — including the GS2 ({{RFC5801}}) message structure, connection-establishment scope, server error challenge format, and error handling — apply to `OAUTHEPOP` unless explicitly stated otherwise in this section.

#### OAUTHEPOP Mechanism {#oauthepop-mechanism}

`OAUTHEPOP` is a new SASL mechanism following the structure of {{RFC7628}} Section 3. Implementors should note that EPOP compact serializations (header, payload, and signature) may be significantly larger than a plain bearer token; SASL implementations MUST support initial client response buffers large enough to carry the full compact-serialized EPOP JWT. It introduces `EPOP` as the OAuth authentication type for the `auth` field of the GS2 initial client response.

The `auth` field for `OAUTHEPOP` is defined as:

~~~
auth-field = "auth" "=" "EPOP" SP epop-token kvsep
~~~

where `epop-token` is the compact-serialized EPOP JWT as defined in {{token-profile}} and `kvsep` is `%x01` per {{RFC7628}}. All other fields in the GS2 initial client response (`host`, `port`, GS2 header, final `kvsep`) are unchanged from {{RFC7628}} Section 3.

Example initial client response (using `%x01` represented as `<SOH>`):

~~~
n,,<SOH>auth=EPOP <compact-epop-token><SOH>host=mail.example.com<SOH>port=993<SOH><SOH>
~~~

#### OAUTHBEARER Backward Compatibility {#oauthbearer-compat}

Servers advertising `OAUTHBEARER` MAY also accept EPOP tokens by recognizing `auth=EPOP` in the initial client response. When a server receives `auth=EPOP` over the `OAUTHBEARER` mechanism, it MUST treat the value as a compact-serialized EPOP JWT and apply the key binding check defined in {{ntk-validation}}.

The server determines whether the nested access token in `ntk` is EPOP-bound as follows:

- **Opaque nested access token**: The server calls token introspection ({{RFC7662}}). If the introspection response includes `cnf.jkt`, the token is EPOP-bound; the server MUST verify `sha256(outer jwk) == cnf.jkt` before accepting the connection.
- **JWT nested access token**: The server inspects the `typ` claim of the access token extracted from `ntk`. If `typ == "epop+jwt"`, the token is EPOP-bound; the server MUST apply the same key binding check.

Servers SHOULD advertise `OAUTHEPOP` in SASL capability responses when EPOP is supported and SHOULD list it ahead of `OAUTHBEARER`. Clients that support EPOP MUST use `OAUTHEPOP` when the server advertises it.

### UserInfo Endpoint {#userinfo-endpoint}

The client presents an EPOP token wrapping the access token at the UserInfo endpoint:

~~~json
{
  "jti": "<unique-id>",
  "iat": "<unix-time>",
  "ntk": "<access-token>",
  "rctx": {
    "res": "https://as.example.com/userinfo",
    "method": "GET"
  }
}
~~~

~~~http
GET /userinfo HTTP/1.1
Host: as.example.com
Authorization: EPOP <compact-serialized-epop-token>
~~~

The AS validates the EPOP token per {{validating-epop}}, verifying `rctx.res` matches its UserInfo endpoint URI, then returns UserInfo claims.

### Resource Server Binding {#rs-binding}

#### Key Binding Enforcement {#key-binding-enforcement}

Every JWT access token issued under EPOP carries a `cnf.jkt` claim — the SHA-256 thumbprint of the client's EPOP public key. When the RS receives an EPOP-wrapped request:

1. It verifies the outer EPOP signature using the `jwk` embedded in the header.
2. It extracts the access token from `ntk` and validates it (signature, `exp`, `aud`, scopes).
3. It computes `sha256(outer jwk header key)` and compares it to `cnf.jkt` inside the access token.

If the two values differ, the RS MUST reject the request with `invalid_token`. This check prevents an attacker from wrapping a stolen access token in their own EPOP envelope.

#### Early-Exit Pattern {#early-exit}

The `rctx` check ({{validating-epop}} Step 7) SHOULD occur before nested credential validation ({{ntk-validation}}). If `rctx.res` or `rctx.method` does not match the current request, the RS SHOULD reject immediately without decoding or verifying the access token. This is the primary defense against replay of an EPOP token from one endpoint at another within the token's short validity window.

#### RS Handling of Opaque Access Tokens {#rs-opaque-tokens}

When the access token in `ntk` is opaque, the RS MUST introspect the received EPOP token with the AS ({{RFC7662}}), passing it as the `token` parameter with `token_type_hint=epop_token` so the AS can validate the envelope and extract the inner token:

~~~http
POST /introspect HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <rs-credentials>

token=<epop-token-received-from-client>
&token_type_hint=epop_token
~~~

The introspection response includes the `cnf.jkt` claim:

~~~json
{
  "active": true,
  "sub": "jdoe@acme.org",
  "scope": "read:orders",
  "cnf": {
    "jkt": "NLp8qGUJ1ywXs4ayYFLHfh8TA0crUe4g78UyBfx5j0Y"
  },
  "exp": 1775752167
}
~~~

#### RS State Management for Opaque Tokens {#rs-state-management}

The RS MUST NOT cache introspection results beyond the EPOP token's validity window. Since EPOP tokens are very short duration per-request credentials, a stale introspection cache could cause the RS to validate a post-rotation request against the pre-rotation key.

When the client performs key rotation ({{key-rotation-refresh}}), the AS MUST atomically update its server-side registry before issuing any new tokens. Introspection responses for access tokens issued after rotation MUST reflect the new client EPOP public key.

| Scenario | RS Obligation |
|:---|:---|
| Opaque access token, no caching | Call introspection per request; use returned `cnf.jkt` for binding check |
| Opaque access token, cached introspection | Cache MUST expire at or before the EPOP token validity window; MUST NOT reuse across key rotation |
| Key mismatch detected | Reject with `invalid_token`; MUST NOT fall back to a previously cached key |
| Opaque refresh token key rotation (AS-side) | AS MUST atomically update server-side key registration; partial update MUST NOT be possible |

# Client Nonce (cnonce) {#cnonce}

## Overview {#cnonce-overview}

`cnonce` is an offline-derived nonce that time-bounds each EPOP token to a discrete step window. Unlike the DPoP server-issued nonce ({{RFC9449}} Section 8), it requires no server round-trip and carries no server-side nonce state, making it particularly suited to non-HTTP transports and high-throughput deployments. `cnonce` reduces the replay opportunity within a window; the `jti` replay cache ({{validating-epop}} Step 5) remains the primary replay prevention mechanism and MUST be maintained regardless.

## Notation {#cnonce-notation}

The following notation is used in this section:

`SPKI`
: DER-encoded SubjectPublicKeyInfo of the client public key in the EPOP token header.

`X`
: Time-step duration in seconds, taken from `epop_cnonce_step_seconds`.

`seed`
: Optional 32-byte deployment seed from `epop_cnonce_seed`. When absent, treated as the empty octet string.

`HKDF-SHA256(ikm, salt, info, len)`
: HKDF with SHA-256 per {{RFC5869}}, producing `len` octets.

`HMAC-SHA256(key, data)`
: HMAC with SHA-256 per {{RFC2104}}.

`BASE64URL(octets)`
: Base64url encoding without padding per {{RFC4648}} Section 5.

`UTF8(str)`
: UTF-8 encoding of string `str` per {{RFC3629}}.

`UINT64BE(n)`
: 8-octet big-endian encoding of integer `n`.

`||`
: Octet string concatenation.

## Computation {#cnonce-computation}

The time-step counter is:

~~~
T = floor(CurrentUnixTime / X)
~~~

The per-client key material is derived once per key pair and re-derived on seed rotation:

~~~
key_material = HKDF-SHA256(seed || SPKI, SHA256(SPKI), "epop-cnonce-v1", 32)
~~~

When `seed` is absent, `ikm = SPKI`. The optional `seed` scopes derivation per deployment so that cnonce values from clients under different seeds are non-interchangeable.

The cnonce value is:

~~~
cnonce = BASE64URL(HMAC-SHA256(key_material, UTF8(jti) || UINT64BE(T)))
~~~

where `jti` is the EPOP token's own unique identifier.

## Verification {#cnonce-validation}

The server (AS or RS) derives `key_material` identically and verifies:

~~~
cnonce == BASE64URL(HMAC-SHA256(key_material, UTF8(jti) || UINT64BE(t)))
~~~

for any `t` ∈ `{T-1, T, T+1}`. This window absorbs clock skew of up to one step. If no value of `t` satisfies the equality, the server MUST reject the token. A cnonce satisfying the time-window check but carrying a replayed `jti` is caught by the replay cache ({{validating-epop}} Step 5).

When `epop_cnonce_seed` is rotated, the server MUST update `epop_cnonce_seed_id` simultaneously so that clients re-derive `key_material`.

# Discovery Metadata {#discovery}

Authorization Servers that support EPOP MUST publish their capabilities in the OAuth Authorization Server Metadata document ({{RFC8414}}), available at `/.well-known/oauth-authorization-server` (or `/.well-known/openid-configuration` for OpenID Connect providers). Resource Servers publish EPOP capabilities in the OAuth Protected Resource Metadata document ({{RFC9728}}), available at `/.well-known/oauth-protected-resource`.

## Metadata Fields {#epop-metadata-fields}

The `epop_cnonce_seed`, `epop_cnonce_seed_id`, and `epop_cnonce_step_seconds` values MUST be identical in the AS and RS discovery documents. Clients SHOULD validate this consistency on startup and after any seed rotation.

`epop_supported`
: String; AS and RS. REQUIRED when EPOP is active. Server EPOP posture: `"disabled"` — clients MUST NOT send EPOP tokens; `"recommended"` — EPOP accepted but non-EPOP requests also accepted; `"required"` — requests without a valid EPOP token MUST be rejected.

`epop_ntk_types_supported`
: Array of strings; AS and RS. REQUIRED when `epop_supported` is not `"disabled"`. Credential formats accepted inside `ntk`: `"jwt"` and/or `"opaque"`.

`epop_key_rotation_supported`
: Boolean; AS only. Default: `false`. When `true`, the server supports the two-layer EPOP key rotation flow ({{key-rotation-refresh}}). Clients MUST check this field before attempting key rotation.

`epop_cnonce_required`
: Boolean; AS and RS. Default: `false`. When `true`, the server MUST reject EPOP tokens that omit `cnonce`. Clients MUST include `cnonce` if either the AS or RS sets this to `true`.

`epop_cnonce_step_seconds`
: Integer; AS and RS. REQUIRED when `epop_cnonce_required` is `true`. Time-step duration in seconds; both client and server compute `T = floor(utc_now() / epop_cnonce_step_seconds)`. MUST be identical in AS and RS documents.

`epop_cnonce_seed`
: String (Base64URL, 32 bytes); AS and RS. OPTIONAL. Namespace discriminator for multi-tenant deployments; mixed into the per-client HKDF derivation so cnonce values across tenants are non-interchangeable. Not a secret. MUST be identical in AS and RS documents when present. Rotated in coordination with `epop_cnonce_seed_id`.

`epop_cnonce_seed_id`
: String; AS and RS. REQUIRED when `epop_cnonce_seed` is present; OPTIONAL otherwise. Opaque identifier for the current `epop_cnonce_seed`. Clients MUST cache the discovery document keyed on this value and re-derive `key_material` only when it changes. MUST be identical in AS and RS documents.

## AS Metadata Example {#as-metadata-example}

~~~json
{
  "issuer": "https://as.example.com",
  "token_endpoint": "https://as.example.com/token",
  "epop_supported": "recommended",
  "epop_ntk_types_supported": ["jwt", "opaque"],
  "epop_key_rotation_supported": true,
  "epop_cnonce_required": true,
  "epop_cnonce_step_seconds": 30,
  "epop_cnonce_seed": "<base64url-32-bytes>",
  "epop_cnonce_seed_id": "seed-2026-q2"
}
~~~

## RS Metadata Example {#rs-metadata-example}

~~~json
{
  "resource": "https://api.example.com",
  "authorization_servers": ["https://as.example.com"],
  "epop_supported": "required",
  "epop_ntk_types_supported": ["jwt", "opaque"],
  "epop_cnonce_required": true,
  "epop_cnonce_step_seconds": 30,
  "epop_cnonce_seed": "<base64url-32-bytes>",
  "epop_cnonce_seed_id": "seed-2026-q2"
}
~~~

# Relationship to Other Specifications {#related-specs}

| RFC | Title | Relationship |
|:---|:---|:---|
| {{RFC7628}} | A Set of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth | EPOP extends RFC 7628 by introducing `EPOP` as a new OAuth authentication type for the SASL `auth` field and defining `OAUTHEPOP` as a new SASL mechanism. All behaviors defined in RFC 7628 remain in effect; this document adds only the `auth=EPOP` field value and the key binding check that `OAUTHBEARER` servers apply when they encounter it. |
| {{RFC9449}} | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | EPOP generalizes the DPoP proof model: replaces `htm`/`htu` with `rctx` for protocol agnosticism; replaces the `ath` hash with `ntk` embedding so credential and proof travel as one object; extends coverage to authorization codes and refresh tokens; adds atomic key rotation and the offline `cnonce`. Additionally, DPoP's requirement to carry two coordinated HTTP headers (`Authorization` and `DPoP`) imposes a propagation burden on every intermediary and resource server in a distributed system; EPOP eliminates this by enveloping the proof inside the token, so a single `Authorization` header carries the inseparable credential-and-proof object through all hops without requiring middleware changes. |
| {{RFC7636}} | Proof Key for Code Exchange (PKCE) | EPOP elevates PKCE from RECOMMENDED to REQUIRED in all authorization code flows. |
| {{RFC8414}} | OAuth 2.0 Authorization Server Metadata | EPOP adds new discovery fields to the well-known document: `epop_supported`, `epop_ntk_types_supported`, `epop_key_rotation_supported`, and the `epop_cnonce_*` family. |
| {{RFC7638}} | JSON Web Key (JWK) Thumbprint | EPOP uses the SHA-256 JWK thumbprint (`cnf.jkt`) as its primary key binding primitive — embedded in every issued token and checked by the RS as its main defense against token substitution. |
| {{RFC7662}} | OAuth 2.0 Token Introspection | EPOP extends introspection responses to include `cnf.jkt`. For opaque tokens the AS returns the server-side registered client EPOP public key; for JWT tokens it is extracted from the token's own claim. |
| {{RFC9126}} | OAuth 2.0 Pushed Authorization Requests (PAR) | EPOP extends PAR to let the client declare `cnf.jkt` at the earliest point in the flow, pre-binding the authorization code before the browser redirect. |
| {{RFC5869}} | HMAC-based Key Derivation Function (HKDF) | EPOP uses HKDF-SHA256 to derive a per-client key from the optional server-controlled `epop_cnonce_seed` and the client's public key, enabling stateless offline cnonce computation. |


# Performance Considerations {#performance}

## Token Size {#perf-token-size}

EPOP consolidates the access token and the proof of possession into a single
token, eliminating the separate DPoP proof header. The net effect on wire size
depends on the access token format in use.

The table below compares the combined size of an AT+DPoP pair against an EPOP
token for representative algorithm combinations, and shows the percentage
change (negative = EPOP is smaller; positive = EPOP is larger). Sizes include
the full Base64url-encoded token strings as they would appear on the wire.
The compressed figures approximate HTTP/2 header-compression (Huffman coding)
applied to the token value.

| AT Format   | Proof Algorithm | AT+DPoP / EPOP Raw (B) | Raw Δ% | AT+DPoP / EPOP Compressed (B) | Compressed Δ% |
|---|---|--:|--:|--:|--:|
| Opaque      | Ed25519 | 599 / 553   | −7.7%  | 437 / 398   | −8.9%  |
| Opaque      | RSA-256 | 1247 / 1201 | −3.7%  | 918 / 880   | −4.1%  |
| JWT Ed25519 | Ed25519 | 1030 / 1128 | +9.5%  | 745 / 811   | +8.9%  |
| JWT Ed25519 | RSA-256 | 1678 / 1776 | +5.8%  | 1230 / 1291 | +5.0%  |
| JWT RSA-256 | Ed25519 | 1288 / 1472 | +14.3% | 950 / 1050  | +10.5% |
| JWT RSA-256 | RSA-256 | 1936 / 2120 | +9.5%  | 1429 / 1536 | +7.5%  |
{: #tbl-token-size title="Token size comparison: AT+DPoP vs EPOP"}

EPOP is 4–9% smaller than AT+DPoP when the access token is opaque, because
eliminating the separate DPoP proof token removes its JOSE header, claims, and
signature overhead. When the access token is a JWT, EPOP is 6–14% larger, as
the full AT payload must be re-encoded inside the EPOP envelope; the overhead
is highest with RSA keys, where large key material is effectively carried
twice. Header compression (e.g., HPACK in HTTP/2) reduces the gap in all
cases but does not reverse the direction of the comparison.

The absolute size differences in the table (46–184 bytes uncompressed) are
small relative to typical HTTP request sizes. On networks with standard MTUs
(1500 bytes) or jumbo frames (9000 bytes), these differences are unlikely to
cause additional TCP segment fragmentation for most requests. However,
deployments on legacy or constrained networks with smaller effective MTUs, or
requests already near the fragmentation boundary due to large URL paths or
other headers, may see an additional packet fragment introduced in JWT AT
configurations where EPOP is larger. Implementers with strict packet-budget
requirements on such networks should prefer opaque access tokens with Ed25519
proofs, which yield the smallest EPOP tokens.

## Computational Overhead {#perf-computation}

EPOP validation replaces the two independent verification steps required for
AT+DPoP (verify the access token, then verify the DPoP proof) with a single
nested-token validation. The cryptographic cost depends on the algorithms
chosen and is equivalent to the sum of one AT signature verification and one
proof signature verification in both approaches; EPOP does not introduce
additional cryptographic operations relative to AT+DPoP.

Resource servers that implement the early-exit optimization described in
{{early-exit}} can skip inner-token decoding when the outer EPOP signature
fails, achieving better average-case performance under adversarial or
malformed-token conditions.

## Latency and Header Processing {#perf-latency}

Because EPOP is presented as a single `Authorization` header value, resource
servers process one token per request rather than parsing and validating two
separate headers (`Authorization: DPoP ...` and `DPoP: <proof>`). This
reduces per-request HTTP header parsing overhead and simplifies the
validation state machine on the resource server.

For deployments using token introspection, the reduction from two
network-visible tokens to one also halves the number of token values the
resource server must convey to the introspection endpoint per request (when
full-token introspection is used; see {{introspection-epop}}).

## Deployment Guidance {#perf-guidance}

Implementers should select the EPOP deployment profile that best matches their
token format:

- **Opaque AT deployments** gain a measurable wire-size reduction (4–9%) and
  simplified transport with no increase in computational cost. EPOP is the
  preferred choice.
- **JWT AT deployments** should weigh the modest size increase (6–14%) against
  the reduced parsing complexity and unified validation logic. For deployments
  where header size is a significant constraint (e.g., HTTP/1.1 without
  compression, constrained-device networks), issuers may consider switching to
  opaque access tokens or choosing compact proof algorithms (Ed25519 over RSA)
  to limit overhead.
- **Algorithm selection** has a larger impact on total token size than the
  choice between AT+DPoP and EPOP. RSA-based algorithms produce tokens
  2–3× larger than elliptic-curve equivalents regardless of the token
  binding mechanism used.

# Security Considerations {#security}

## Token Lifetime {#sec-token-lifetime}

EPOP tokens MUST be short-lived, per-request credentials. The server defines the maximum acceptable age of the `iat` claim; when `cnonce` is required, `epop_cnonce_step_seconds` imposes an additional validity bound enforced independently by both the AS and RS. Short lifetimes limit the window during which a captured token remains usable and reduce the cost of maintaining the `jti` replay cache.

## Replay Prevention {#sec-replay-prevention}

Each EPOP token MUST include a `jti` value of at least 128 bits of entropy (e.g., a UUID v4 or CSPRNG-generated value) to make collisions computationally infeasible. Servers MUST maintain a replay cache keyed on `jti` with a TTL of at least `max_epop_lifetime + clock_skew`; any token whose `jti` appears in the cache MUST be rejected. When `cnonce` is also required, the time-step window narrows the effective validity period further but does not replace the cache.

## Token Substitution {#token-substitution}

The key binding check — `sha256(outer jwk) == cnf.jkt` from the nested credential — is the primary defense against token substitution. An attacker who captures an access token and wraps it in an EPOP envelope signed with their own key will produce a thumbprint that does not match the `cnf.jkt` embedded by the AS; the RS MUST reject the mismatch.

For opaque access tokens, the RS MUST NOT cache introspection results beyond the EPOP token's validity window. When a client performs key rotation ({{key-rotation-refresh}}), the AS MUST atomically update its server-side key binding before issuing new tokens; a stale cached result could cause the RS to validate a post-rotation request against the pre-rotation key.

## Cross-Protocol Replay {#cross-protocol-replay}

Without `rctx` validation, an EPOP token captured from one protocol or endpoint could be replayed at another within the token's validity window. Servers MUST validate `rctx.res` and `rctx.method` when those claims are present. Clients SHOULD always include `rctx` to maximize replay resistance.

## Credential Confidentiality {#sec-credential-confidentiality}

The `ntk` claim embeds the full OAuth 2.0 credential inside the EPOP envelope. Unlike bearer token flows where only the token value is sensitive, the entire compact serialization carries sensitive material. TLS is REQUIRED for all EPOP token transmissions; JWE MAY be applied for additional confidentiality over transports that cannot guarantee channel security. Refresh tokens embedded in `ntk` are particularly sensitive. Servers and intermediaries MUST NOT log EPOP token values in plaintext; the `jti` claim SHOULD be used as the audit correlation identifier instead.

## Key Rotation Security {#key-rotation-security}

The AS MUST validate both the outer and inner EPOP envelopes completely before issuing new tokens or updating key bindings. Partial validation would allow an attacker who holds a captured refresh token to inject a new key by constructing a valid outer envelope while providing an invalid inner envelope.

## PKCE Requirement {#sec-pkce}

PKCE ({{RFC7636}}) is REQUIRED in all EPOP authorization code flows. Without PKCE, an attacker who intercepts the authorization code can generate their own key pair and wrap the code in a valid EPOP token signed with that key, bypassing key binding entirely. PKCE and EPOP protect complementary surfaces: PKCE binds the authorization request to the token request; EPOP binds the code to the client's key pair.

## Authorization Request Key Binding {#sec-auth-request-binding}

Binding a public key thumbprint inside the authorization request URL (as defined for DPoP in {{RFC9449}} Section 10) is not supported by this specification. Authorization requests travel through the browser redirect — an untrusted channel where a parameter can be silently replaced before the AS sees it. EPOP establishes key binding exclusively at endpoints where the client communicates directly with the AS over TLS: the token endpoint and, optionally, the PAR endpoint ({{par}}).

## Algorithm Selection {#sec-algorithm-selection}

EPOP tokens are generated per-request at high frequency; algorithm choice directly affects signing latency, token size, and security posture. The `jwk` embedded in every EPOP header makes key footprint particularly significant for constrained transports. Edwards curve algorithms are RECOMMENDED. Ed25519 is the primary choice — smallest public key, fastest deterministic signing, and 128-bit security adequate for short-lived credentials. Ed448 is appropriate for high-assurance environments requiring a larger security margin. `ES256` is acceptable where Edwards curves are unavailable. RSA algorithms SHOULD NOT be used in new implementations. Implementations MUST follow {{RFC8725}}.

## Intermediary Transparency {#sec-intermediary-transparency}

Because the EPOP proof is embedded within the token rather than transmitted as a separate header, EPOP tokens are transparent to intermediaries that forward the `Authorization` header without modification. Unlike DPoP, where loss of the `DPoP` header at any hop silently breaks proof-of-possession, EPOP's enveloped structure ensures that the proof travels with the credential through every layer of a distributed system. Resource servers MUST NOT accept EPOP tokens from which the outer envelope signature has been stripped or replaced by an intermediary; the full compact-serialized EPOP token MUST be forwarded unchanged.

## Private Key Protection {#private-key-protection}

The security of EPOP depends entirely on the client's private key remaining secret. Private key material MUST never be logged, serialized into application state, or transmitted over any channel. Implementations MUST verify that no private key fields (`d`, `p`, `q`, `dp`, `dq`, `qi`) are present in the `jwk` header parameter before accepting or forwarding an EPOP token.

On native and mobile platforms, clients MUST use platform secure storage (e.g., Android Keystore, iOS Secure Enclave), with private key operations performed inside the secure element where available so that key material never enters application memory.

In browser environments, private keys MUST be generated as non-extractable `CryptoKey` objects via the Web Crypto API (`extractable: false`). Clients MUST NOT store private keys in `localStorage`, `sessionStorage`, `IndexedDB`, or any JavaScript-readable store; this prevents exfiltration by XSS or injected scripts running in the same origin.

EPOP tokens MUST use asymmetric signature algorithms. Symmetric algorithms such as `HS256` require the verifier to hold the same secret as the signer, making independent third-party verification impossible and introducing shared-secret distribution risk.

# Privacy Considerations {#privacy}

## Credential Visibility in Logs

Because the `ntk` claim embeds the full OAuth 2.0 credential, an EPOP token is more privacy-sensitive than a typical bearer token: its compact serialization reveals the credential type, issuer, audience, and scope to any party that receives or stores it. Servers SHOULD apply data-minimization practices to audit logs — retaining only the `jti` and `iat` claims rather than the full token value. See {{sec-credential-confidentiality}} for the normative logging and TLS requirements.

## Key Identifier as Tracking Vector

The `cnf.jkt` claim is a stable, long-lived public key thumbprint. If the same key pair is used across multiple authorization server or resource server deployments, the thumbprint functions as a cross-context tracking identifier. Clients SHOULD use distinct key pairs per authorization server to limit cross-context correlation. Key rotation ({{key-rotation-refresh}}) provides a mechanism for periodic key refresh independent of active sessions.

## Resource URI Disclosure

The `rctx.res` field encodes the target resource URI or URN and is part of the signed EPOP envelope, visible to any party that receives or logs the token. Clients MUST use TLS for all EPOP token transmissions to limit exposure to on-path observers. Resource identifiers that encode sensitive information (e.g., user identifiers embedded in path parameters) SHOULD be avoided in `rctx.res`.

## Minimal Disclosure

This profile does not require the EPOP envelope to carry user identity claims. User identity information belongs in the nested access token (`ntk`), not in the outer EPOP envelope. Implementations MUST NOT add user identity claims to the EPOP token header or payload unless required by a specific profile extension.

# IANA Considerations {#iana}

## HTTP Authentication Scheme Registration {#iana-http-scheme}

This specification requests registration of the following entry in the "Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry" ({{RFC7235}}):

Authentication Scheme Name:
: `EPOP`

Pointer to specification text:
: {{resource-access}} and {{token-profile}} of this document.

## OAuth Grant Type Registration {#iana-grant-types}

This specification requests registration of the following entries in the "OAuth Parameters" registry (grant type sub-table) established by {{RFC6749}} Section 11.3:

Grant Type Name:
: `urn:ietf:params:oauth:grant-type:epop_code_grant`

Change Controller:
: IETF

Specification Document(s):
: {{auth-code-flow}} of this document

Grant Type Name:
: `urn:ietf:params:oauth:grant-type:epop_refresh_token`

Change Controller:
: IETF

Specification Document(s):
: {{refresh-flow}} of this document

## OAuth Parameters Registration {#iana-oauth-params}

This specification requests registration of the following entry in the "OAuth Parameters" registry established by {{RFC6749}} Section 11.2:

Parameter Name:
: `epop`

Parameter Usage Location:
: token request, pushed authorization request

Change Controller:
: IETF

Specification Document(s):
: {{creating-epop}}, {{auth-code-flow}}, {{refresh-flow}}, and {{par}} of this document

## OAuth Token Type Registration {#iana-token-type-value}

This specification requests registration of the following value in the "OAuth Access Token Types" registry established by {{RFC6749}} Section 11.1:

Type Name:
: `EPOP`

Additional Token Endpoint Response Parameters:
: (none)

HTTP Authentication Scheme(s):
: `EPOP`

Change Controller:
: IETF

Specification Document(s):
: {{creating-epop}} and {{resource-access}} of this document

## OAuth Token Type Identifiers {#iana-token-types}

This specification requests registration of the following entries in the "OAuth URI" subregistry of the "OAuth Parameters" registry established by {{RFC8693}} Section 7.1:

URI:
: `urn:ietf:params:oauth:token-type:epop_access_token`

Change Controller:
: IETF

Specification Document(s):
: {{token-exchange}} of this document

URI:
: `urn:ietf:params:oauth:token-type:epop_refresh_token`

Change Controller:
: IETF

Specification Document(s):
: {{token-exchange}} of this document

## OAuth Token Type Hint Registration {#iana-token-type-hint}

This specification requests registration of the following value in the "OAuth Token Type Hints" registry established by {{RFC7009}} Section 4.1:

Token Type Hint Name:
: `epop_token`

Change Controller:
: IETF

Specification Document(s):
: {{token-introspection}}, {{token-revocation}}, and {{rs-opaque-tokens}} of this document

## JWT Claims Registration {#iana-jwt-claims}

This specification requests registration of the following JWT claims in the "JSON Web Token Claims" registry established by {{RFC7519}}:

Claim Name: `ntk`
: Claim Description: Nested Token — the OAuth 2.0 credential embedded inside the EPOP envelope.
: Change Controller: IETF
: Specification Document(s): {{token-payload}} of this document

Claim Name: `rctx`
: Claim Description: Request Context — a JSON object identifying the target resource and protocol action.
: Change Controller: IETF
: Specification Document(s): {{token-payload}} of this document

Claim Name: `cnonce`
: Claim Description: Client Nonce — offline-derived HMAC value for replay resistance without server-issued nonce state.
: Change Controller: IETF
: Specification Document(s): {{cnonce}} of this document

## JWT Type Registration {#iana-jwt-type}

This specification requests registration of the following `typ` header parameter value in the "JSON Web Signature and Encryption Header Parameters" registry established by {{RFC7515}}, in accordance with {{RFC8725}} Section 3.11:

Type Name: `epop+jwt`
: Description: Enveloped Proof of Possession JWT.
: Change Controller: IETF
: Specification Document(s): {{token-header}} of this document

## OAuth Authorization Server Metadata {#iana-as-metadata}

This specification requests registration of the following names in the "OAuth Authorization Server Metadata" registry ({{RFC8414}}):

- `epop_supported`
- `epop_ntk_types_supported`
- `epop_key_rotation_supported`
- `epop_cnonce_seed`
- `epop_cnonce_step_seconds`
- `epop_cnonce_seed_id`
- `epop_cnonce_required`

## OAuth Protected Resource Metadata {#iana-rs-metadata}

This specification requests registration of the following names in the "OAuth Protected Resource Metadata" registry ({{RFC9728}}):

- `epop_supported`
- `epop_ntk_types_supported`
- `epop_cnonce_seed`
- `epop_cnonce_step_seconds`
- `epop_cnonce_seed_id`
- `epop_cnonce_required`

## EPOP Request Context Members Registry {#iana-rctx}

This specification requests creation of a new registry, "EPOP Request Context Members", under the "OAuth Parameters" registry group. The registry is to be maintained as Specification Required per {{RFC8126}}.

Initial registrations:

| Member Name | Type | Description | Specification |
|:---|:---|:---|:---|
| `res` | String | URI or URN of the target resource or endpoint | {{token-payload}} of this document |
| `method` | String | Protocol action string | {{token-payload}} of this document |
| `id` | String | Client-generated correlation ID | {{token-payload}} of this document |

## SASL Mechanism Registration {#iana-sasl}

This specification requests registration of the following entry in the "SASL Mechanisms" registry established by {{RFC4422}}:

Mechanism Name:
: `OAUTHEPOP`

Security Considerations:
: See {{sasl}} of this document.

Published Specification:
: This document.

Intended Usage:
: COMMON

Owner/Change Controller:
: IETF

--- back

# Acknowledgments
{:numbered="false"}

The author thanks the OAuth Working Group for their foundational work on DPoP ({{RFC9449}}), PKCE ({{RFC7636}}), and the related specifications that this document extends.

The author thanks Joe DeCock (Duende Software) for observations on token size implications across access token formats and algorithm combinations.
