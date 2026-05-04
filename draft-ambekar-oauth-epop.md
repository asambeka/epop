---
title: "Enveloped Proof of Possession (EPOP) for OAuth 2.0"
abbrev: "EPOP"
category: std

docname: draft-ambekar-oauth-epop-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - EPOP
 - oauth
 - proof-of-possession
 - sender-constrained
 - token binding

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
    email: ambekar@gmail.com

normative:
  RFC4422:
  RFC5869:
  RFC7235:
  RFC7515:
  RFC7517:
  RFC7519:
  RFC7628:
  RFC7636:
  RFC7638:
  RFC7662:
  RFC8414:
  RFC8725:
  RFC9449:
  RFC9728:

informative:
  RFC6749:
  RFC7009:
  RFC8252:
  RFC8693:
  RFC9126:

...

--- abstract

This document specifies Enveloped Proof of Possession (EPOP), a "proof-first" security model for OAuth 2.0 in which an EPOP JWT (type `epop+jwt`) serves as the outer cryptographic envelope, nesting the OAuth credential — an authorization code, access token, or refresh token — within its `ntk` (Nested Token) claim. By decoupling the cryptographic proof from transport-specific headers, EPOP produces a single, unified credential that operates transparently across HTTP and non-HTTP transports alike, including MQTT, Kafka, the Model Context Protocol (MCP), and SASL-based protocols such as those defined in {{RFC7628}}. EPOP extends {{RFC9449}} (DPoP) by replacing HTTP-specific `htm`/`htu` claims with a protocol-neutral `rctx` (Request Context) object, embedding the credential within the proof rather than alongside it, and introducing an offline-derived client nonce (`cnonce`) that eliminates the server-issued nonce acquisition round-trip and enables stateless nonce handling and validation; to support SASL-based protocols, this document further defines `OAUTHEPOP`, a new mechanism extending {{RFC7628}} with sender-constraining support. EPOP also defines a mechanism for cryptographic key rotation during the refresh token exchange, enabling secure long-term key management without interrupting active sessions.

--- middle

# Introduction

Enveloped Proof of Possession (EPOP) functions as a proof-first credential model for OAuth 2.0 ({{RFC6749}}) in which the OAuth credential — an authorization code, access token, or refresh token — is embedded *inside* a signed JSON Web Token (JWT) ({{RFC7519}}) proof rather than transmitted alongside it. The client constructs an EPOP token, a JWT with `typ: epop+jwt`, nesting the credential within its `ntk` (Nested Token) claim and signing the entire envelope with the client's private key. Because the credential is bound inside the signed structure, recipients verifying the EPOP token authenticate both key possession and the credential in a single operation: there is no credential without a proof, and no proof without a credential.

OAuth 2.0 access tokens are bearer tokens by default: any party in possession of a token can use it until it expires. DPoP ({{RFC9449}}) addressed token theft in HTTP environments by binding access tokens to a client's public key and requiring a fresh signed proof on each request. However, DPoP has structural limitations that prevent it from serving as a general proof-of-possession mechanism: its `htm` and `htu` claims are HTTP-specific and carry no meaning over MQTT, Kafka, gRPC, SASL, or the Model Context Protocol (MCP); the credential and proof travel as separate objects in distinct headers and can be intercepted and recombined independently; proof-of-possession is not extended to authorization codes or refresh tokens; and server-issued nonces require an initial round-trip and distributed server-side nonce state. SASL-based deployments built on {{RFC7628}} face an additional gap: bearer tokens reach non-HTTP servers with no mechanism for the client to prove it is the intended holder.

EPOP addresses these limitations through a single architectural shift: embedding the credential inside the proof. Because the credential lives inside the signed `epop+jwt` envelope, it is inseparable from the proof and covers authorization codes, access tokens, and refresh tokens alike. The HTTP-specific `htm`/`htu` claims are replaced by a protocol-neutral `rctx` (Request Context) object — a URI or URN identifying the resource and a free-form action string — enabling operation across any transport without protocol-specific adaptation. An offline-derived `cnonce` eliminates the server-issued nonce round-trip and enables stateless nonce validation. For SASL-based protocols, this document defines `OAUTHEPOP`, a new SASL mechanism extending {{RFC7628}} with sender-constraining support via a new `EPOP` auth type; all behaviors defined in {{RFC7628}} remain unchanged. EPOP further defines cryptographic key rotation during the refresh token exchange, enabling secure long-term key management without interrupting active sessions.

## Comparison with DPoP {#comparison-dpop}

| Feature | RFC 9449 (DPoP) | EPOP |
|:---|:---|:---|
| Token type header | `dpop+jwt` | `epop+jwt` |
| Credential binding | `ath` (SHA-256 hash of access token) | `ntk` (credential embedded) |
| Target resource | `htu` (HTTP URI only) | `rctx.res` (URI or URN, any protocol) |
| Action context | `htm` (HTTP method only) | `rctx.method` (any action string) |
| Request correlation | Not defined | `rctx.id` (optional) |
| Key rotation | Not defined | Recursive EPOP envelope with `cnf.jkt` |
| Covered token types | Access tokens only | Authorization codes, access tokens, refresh tokens |
| Credential transport | `Authorization: Bearer` (separate) | `Authorization: EPOP` header for all endpoints |
| PKCE requirement | Recommended | REQUIRED in authorization code flows |
| Replay protection | `jti` + `iat` | Same |
| Nonce | Server-issued (requires round-trip and server state) | `cnonce`: offline TOTP-style (no round-trip, no server state) |
| Authorization request key binding | `dpop_jkt` parameter (supported) | Not supported (see {{auth-request-binding}}) |

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used throughout this document:

EPOP Token:
: A signed JWT ({{RFC7519}}) with `typ: epop+jwt`, signed by the client's private key, that contains an OAuth 2.0 credential in the `ntk` claim.

Nested Token (ntk):
: The OAuth 2.0 credential (authorization code, access token, refresh token, or another EPOP token) embedded inside an EPOP token's payload.

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

# EPOP Token Structure {#token-structure}

An EPOP token is a signed JWT ({{RFC7519}}) with `typ: epop+jwt`.

## Header {#token-header}

The EPOP token JOSE header MUST include the following parameters:

| Parameter | Required | Description |
|:---|:---|:---|
| `typ` | REQUIRED | MUST be `epop+jwt`. |
| `alg` | REQUIRED | Asymmetric signature algorithm. `EdDSA` (Ed25519 or Ed448) is RECOMMENDED. `ES256` is acceptable. RSA algorithms SHOULD NOT be used in new implementations. Symmetric algorithms (`HS*`) and `none` MUST NOT be used. |
| `jwk` | REQUIRED | The client's public key as a JWK ({{RFC7517}}). MUST NOT contain private key material. |

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

### Algorithm Selection {#algorithm-selection}

`EdDSA` with an Edwards curve is the RECOMMENDED algorithm for EPOP tokens. EPOP tokens are generated per-request at high frequency — algorithm choice directly impacts signing latency, token size, and security posture. The `jwk` is embedded in every EPOP token header, making smaller key footprint particularly valuable for constrained transports (MQTT, MCP, Kafka).

| Property | EdDSA / Ed25519 | EdDSA / Ed448 | ES256 (P-256) | RS256 (RSA-2048) |
|:---|:---|:---|:---|:---|
| Security level | 128-bit | 224-bit | 128-bit | 112-bit |
| Signature size | 64 bytes | 114 bytes | 64 bytes | 256 bytes |
| Public key size | 32 bytes | 57 bytes | 64 bytes | ~256 bytes |
| Signing speed | Very fast (deterministic) | Fast (deterministic) | Moderate | Slow |
| Side-channel resistance | Strong (constant-time) | Strong (constant-time) | Moderate | Weak |

Ed25519 is the primary recommendation: smallest public key, fastest deterministic signing, and 128-bit security adequate for short-lived per-request credentials. Ed448 is appropriate when a higher security margin is required (e.g., long-lived sessions, high-assurance environments). Both EdDSA variants are deterministic, eliminating per-signature CSPRNG dependency and a common signing vulnerability in constrained environments. Implementations MUST follow the guidance in {{RFC8725}}.

## Payload {#token-payload}

| Claim | Required | Description |
|:---|:---|:---|
| `jti` | REQUIRED | Unique JWT ID. MUST be generated with sufficient entropy (e.g., UUID v4 or CSPRNG-generated value). Servers MUST maintain a replay cache keyed on `jti`. |
| `iat` | REQUIRED | Issued-at Unix timestamp. Servers MUST reject tokens older than the server-defined maximum EPOP lifetime or issued in the future beyond clock skew. EPOP tokens MUST be treated as very short duration per-request credentials. |
| `ntk` | REQUIRED | The nested OAuth 2.0 credential. A compact-serialized JWT or a Base64URL-encoded opaque string. See {{ntk-values}}. |
| `cnonce` | RECOMMENDED | Offline-derived client nonce. See {{cnonce}}. When the server publishes `epop_cnonce_required: true`, the client MUST include this claim. |
| `rctx` | OPTIONAL | Request context object. When present, all recognized members MUST be validated by the server. |
| `rctx.res` | OPTIONAL | URI or URN of the target resource or endpoint. |
| `rctx.method` | RECOMMENDED | Protocol action string. Case-insensitive for HTTP methods; case-sensitive otherwise. |
| `rctx.id` | OPTIONAL | Client-generated correlation ID. Useful in async or multiplexed protocols. |
| `cnf.jkt` | CONDITIONAL | SHA-256 JWK Thumbprint ({{RFC7638}}) of the client's public key. REQUIRED in authorization code exchange and in the inner envelope of a key rotation request. SHOULD be omitted on routine resource access and simple refresh requests where the key is already bound to the token. |

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

## ntk Claim Values {#ntk-values}

| Credential Type | `ntk` Value |
|:---|:---|
| JWT access token | Compact-serialized JWT (`header.payload.sig`) |
| JWT refresh token | Compact-serialized JWT |
| Opaque access token | Base64URL-encoded opaque string |
| Opaque refresh token | Base64URL-encoded opaque string |
| Opaque authorization code | Base64URL-encoded opaque string |
| Inner EPOP token (key rotation) | Compact-serialized EPOP JWT |

# Creating an EPOP Token {#creating-epop}

## Prerequisites {#creation-prerequisites}

The client MUST have:

- An asymmetric key pair. The private key is held exclusively by the client; the public key is embedded in every EPOP token header.
- A reliable source of high-entropy identifiers for `jti` (e.g., UUID v4 or CSPRNG-generated value).
- A trusted clock for `iat`.

## Construction {#token-construction}

Step 1 — Prepare the JOSE header with `typ: epop+jwt`, the signing algorithm, and the public key JWK.

Step 2 — Prepare the payload. Encode the credential in `ntk`:

- If the credential is a JWT: use its compact serialization directly.
- If the credential is opaque: Base64URL-encode it.

Include `cnf.jkt` only when establishing or rotating the key binding (authorization code exchange, PAR, or key rotation), not on every resource access.

Step 3 — Compute the JWS signature over `ASCII(BASE64URL(UTF8(header)) || '.' || BASE64URL(payload))` using the client's private key with the declared algorithm.

Step 4 — Produce the compact serialization:

~~~
epop_token = BASE64URL(header) + "." + BASE64URL(payload) + "." + BASE64URL(signature)
~~~

Step 5 — Transmit the EPOP token in the HTTP `Authorization` header using the `EPOP` authentication scheme ({{RFC7235}}) for all endpoints — AS endpoints (token, introspection, revocation, PAR), resource server access, and the UserInfo endpoint:

~~~http
Authorization: EPOP <compact-serialized-epop-token>
~~~

## Inner EPOP Token for Key Rotation {#inner-epop-key-rotation}

When rotating keys, the client constructs a two-layer structure. The inner envelope is signed with the OLD private key:

~~~json
{
  "jti": "<unique-id-inner>",
  "iat": "<unix-time>",
  "ntk": "<refresh-token>",
  "cnf": { "jkt": "<thumbprint-of-NEW-public-key>" },
  "rctx": {
    "res": "https://as.example.com/token",
    "method": "POST"
  }
}
~~~

The outer envelope is signed with the NEW private key:

~~~json
{
  "jti": "<unique-id-outer>",
  "iat": "<unix-time>",
  "ntk": "<compact-serialized-inner-epop-token>"
}
~~~

The outer token is submitted as the `epop` parameter in a `refresh_token` grant request.

# Validating an EPOP Token {#validating-epop}

## Authorization Server Validation {#as-validation}

The AS MUST perform the following steps in order. Failure at any step MUST result in rejection of the request with an appropriate OAuth 2.0 error response.

1. **Parse**: Confirm `typ == "epop+jwt"`.

2. **Extract public key**: Read the `jwk` header parameter. Confirm it is a valid asymmetric public key. MUST NOT contain private key fields (`d`, `p`, `q`, `dp`, `dq`, `qi`).

3. **Verify JWS signature**: Verify the outer signature using the extracted public key.

4. **Validate freshness**:
   - Reject if `iat > now + clock_skew`.
   - Reject if `iat < now - max_epop_lifetime` (server-defined; MUST be treated as very short).
   - If `cnonce` is present, additionally enforce the `epop_cnonce_step_seconds` time-step window (see {{cnonce-validation}}).

5. **Replay protection**:
   - Look up `jti` in the replay cache. Reject if found.
   - Record `jti` with TTL = `max_epop_lifetime + clock_skew`.

6. **Validate rctx** (if present):
   - Confirm `rctx.res` matches the token endpoint URI.
   - Confirm `rctx.method == "POST"`.

7. **Decode and validate ntk**:
   - If authorization code (JWT): verify signature, expiry, and PKCE `code_verifier`.
   - If authorization code (opaque): look up in server-side store; verify not expired, not used; verify PKCE `code_verifier`.
   - If refresh token (single layer): verify validity and expiry.
   - If inner EPOP token (key rotation): repeat steps 1–6 for the inner envelope; verify inner `jwk` is a valid asymmetric public key; confirm inner `rctx.res` matches token endpoint.

8. **Verify key binding**:
   - Authorization code (JWT): `sha256(outer jwk) == cnf.jkt` in the JWT code.
   - Authorization code (opaque, with PAR): `sha256(outer jwk) == cnf.jkt` stored server-side from the PAR request.
   - Authorization code (opaque, without PAR): no prior key bound — treat `cnf.jkt` in the outer EPOP as first-time declaration; PKCE `code_verifier` validates client identity; bind issued tokens to `sha256(outer jwk)`.
   - Refresh token (single layer): `sha256(outer jwk) == client EPOP public key` bound to the refresh token.
   - Key rotation (two layers): `sha256(outer jwk) == inner cnf.jkt` AND `sha256(inner jwk) == client EPOP public key` bound to the refresh token.

9. **Issue tokens**: Bind all issued tokens to `sha256(outer jwk)` via `cnf.jkt`.

## Resource Server Validation {#rs-validation}

The RS MUST apply an early-exit strategy: validate the outer envelope and request binding before decoding the nested credential.

1. **Parse**: Confirm `typ == "epop+jwt"`.

2. **Verify outer signature**: Extract `jwk` header parameter; verify JWS signature.

3. **Validate freshness and replay**: Apply the same `iat`, `jti`, and cnonce time-step checks as the AS.

4. **Validate rctx** (early-exit):
   - Confirm `rctx.res` matches the resource being accessed.
   - Confirm `rctx.method` matches the operation.
   - Mismatch: reject immediately with `invalid_token`.

5. **Decode and validate nested access token**:
   - If JWT: verify signature, `iss`, `exp`, `aud`, scopes.
   - If opaque: introspect with the AS ({{RFC7662}}).

6. **Verify key binding**:
   - Extract `cnf.jkt` from the nested access token (or from the introspection response for opaque tokens).
   - Compute `sha256(outer jwk header key)`.
   - The two values MUST be equal. A mismatch indicates token substitution; reject with `invalid_token`.

# OAuth 2.0 Flows with EPOP {#flows}

## Authorization Code Flow with PKCE {#auth-code-flow}

PKCE ({{RFC7636}}) is REQUIRED in all EPOP authorization code flows. PKCE and EPOP protect complementary attack surfaces: PKCE binds the authorization request to the token request; EPOP binds the authorization code to the client's key pair. Without PKCE, an attacker who intercepts the authorization code could generate their own key pair and wrap the code in a valid EPOP token signed with their key. Together they provide end-to-end chain of trust from the authorization request through token issuance.

~~~
Client                           AS                         RS
  |                              |                           |
  |-- 1. Authorization Request ->|                           |
  |   (code_challenge, PKCE)     |                           |
  |                              |                           |
  |<-- 2. Authorization Code ----|                           |
  |                              |                           |
  |-- 3. Token Request (POST) -->|                           |
  |   Authorization: EPOP <token:|                           |
  |     code in ntk, cnf.jkt,    |                           |
  |     code_verifier>           |                           |
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

~~~http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: EPOP <compact-serialized-epop-token>

grant_type=authorization_code
&client_id=s6BhdRkqt3
&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
&code_verifier=bEaL42izcC-o-xBk0K2vuJ6U-y1p9r_wW2dFWIWgjz-
~~~

EPOP token payload for this request (opaque authorization code Base64URL-encoded in `ntk`; `cnf.jkt` is the first-time key declaration since no PAR was used):

~~~json
{
  "jti": "A8B2B026-6C81-4A8C-A403-0F225E3DFEED",
  "iat": 1775749791,
  "cnf": {
    "jkt": "NLp8qGUJ1ywXs4ayYFLHfh8TA0crUe4g78UyBfx5j0Y"
  },
  "ntk": "QjM3Qjc3NDQtRjJDNS00RjY3LTkwMkQtMTVFNjIwOTMxNkE5",
  "rctx": {
    "res": "https://as.example.com/token",
    "method": "POST"
  }
}
~~~

The issued access token carries the `cnf.jkt` binding:

~~~json
{
  "sub": "jdoe@acme.org",
  "aud": ["https://api.example.com"],
  "cnf": {
    "jkt": "NLp8qGUJ1ywXs4ayYFLHfh8TA0crUe4g78UyBfx5j0Y"
  },
  "iat": 1775748567,
  "exp": 1775752167
}
~~~

## Client Credentials Flow {#client-credentials-flow}

Client credentials flow is not covered by this specification.

## Resource Access {#resource-access}

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

The RS verifies the outer envelope, then extracts and validates the access token from `ntk` as defined in {{rs-validation}}.

## Non-HTTP and Agentic Protocols {#non-http-protocols}

The EPOP token structure is identical for non-HTTP protocols; only `rctx` values differ. The `rctx.res` field accommodates any URI or URN:

| Protocol | `rctx.res` | `rctx.method` |
|:---|:---|:---|
| HTTPS | `https://api.example.com/orders` | `GET` |
| MQTT | `urn:mqtt:broker:sensors/temperature` | `PUBLISH` |
| MCP | `urn:mcp:server:filesystem` | `tools/call` |
| Kafka | `urn:kafka:cluster:orders-topic` | `Produce` |

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

# SASL Integration {#sasl}

This section extends {{RFC7628}} to support Enveloped Proof of Possession. All behaviors defined in {{RFC7628}} — including the GS2 message structure, connection-establishment scope, server error challenge format, and error handling — apply to `OAUTHEPOP` unless explicitly stated otherwise in this section.

## OAUTHEPOP Mechanism {#oauthepop-mechanism}

`OAUTHEPOP` is a new SASL mechanism following the structure of {{RFC7628}} Section 3. It introduces `EPOP` as the OAuth authentication type for the `auth` field of the GS2 initial client response.

The `auth` field for `OAUTHEPOP` is defined as:

~~~
auth-field = "auth" "=" "EPOP" SP epop-token kvsep
~~~

where `epop-token` is the compact-serialized EPOP JWT as defined in {{token-structure}} and `kvsep` is `%x01` per {{RFC7628}}. All other fields in the GS2 initial client response (`host`, `port`, GS2 header, final `kvsep`) are unchanged from {{RFC7628}} Section 3.

Example initial client response (using `%x01` represented as `<SOH>`):

~~~
n,,<SOH>auth=EPOP <compact-epop-token><SOH>host=mail.example.com<SOH>port=993<SOH><SOH>
~~~

## OAUTHBEARER Backward Compatibility {#oauthbearer-compat}

Servers advertising `OAUTHBEARER` MAY also accept EPOP tokens by recognizing `auth=EPOP` in the initial client response. When a server receives `auth=EPOP` over the `OAUTHBEARER` mechanism, it MUST treat the value as a compact-serialized EPOP JWT and apply the key binding check defined in {{rs-validation}}.

The server determines whether the nested access token in `ntk` is EPOP-bound as follows:

- **Opaque nested access token**: The server calls token introspection ({{RFC7662}}). If the introspection response includes `cnf.jkt`, the token is EPOP-bound; the server MUST verify `sha256(outer jwk) == cnf.jkt` before accepting the connection.
- **JWT nested access token**: The server inspects the `typ` claim of the access token extracted from `ntk`. If `typ == "epop+jwt"`, the token is EPOP-bound; the server MUST apply the same key binding check.

Servers SHOULD advertise `OAUTHEPOP` in SASL capability responses when EPOP is supported and SHOULD list it ahead of `OAUTHBEARER`. Clients that support EPOP MUST use `OAUTHEPOP` when the server advertises it.

# Token Refresh Flow {#refresh-flow}

## Simple Refresh (Same Key) {#simple-refresh}

Whether the refresh token is opaque or a JWT, the client wraps it in a single-layer EPOP token and submits a standard `refresh_token` grant:

~~~json
{
  "jti": "<unique-id>",
  "iat": "<unix-time>",
  "ntk": "<refresh-token-opaque-or-jwt>",
  "rctx": {
    "res": "https://as.example.com/token",
    "method": "POST"
  }
}
~~~

~~~http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: EPOP <compact-serialized-epop-token>

grant_type=refresh_token
&client_id=s6BhdRkqt3
~~~

AS validation differs by refresh token type:

| Refresh Token Type | AS Validation of `ntk` |
|:---|:---|
| Opaque | Look up in server-side store; verify not revoked, not expired; confirm associated EPOP public key matches `sha256(outer jwk)` |
| JWT | Verify JWT signature, `iss`, `exp`, `jti`; extract `cnf.jkt` and compare against `sha256(outer jwk)` |

## Key Rotation Refresh {#key-rotation-refresh}

Key rotation uses a two-layer EPOP structure. The inner envelope is signed with the OLD key and declares the thumbprint of the NEW key in `cnf.jkt`:

~~~json
{
  "jti": "<unique-id-inner>",
  "iat": "<unix-time>",
  "ntk": "<refresh-token-opaque-or-jwt>",
  "cnf": { "jkt": "<thumbprint-of-NEW-public-key>" },
  "rctx": {
    "res": "https://as.example.com/token",
    "method": "POST"
  }
}
~~~

The outer envelope is signed with the NEW key and contains the compact-serialized inner EPOP token:

~~~json
{
  "jti": "<unique-id-outer>",
  "iat": "<unix-time>",
  "ntk": "<compact-serialized-inner-epop-token>"
}
~~~

AS validation chain for key rotation:

1. Verify outer EPOP signature with outer `jwk` (NEW key).
2. Decode outer `ntk` → inner EPOP token.
3. Verify inner EPOP signature with inner `jwk` (OLD key).
4. Decode inner `ntk` → refresh token.
5. Validate refresh token (opaque: lookup; JWT: signature and claims).
6. Confirm `sha256(inner jwk) == client EPOP public key` previously bound to the refresh token.
7. Confirm `sha256(outer jwk) == inner cnf.jkt` (outer key is the client's declared new key).
8. Issue new tokens bound to `sha256(outer jwk)`.
9. Atomically update server-side client EPOP public key binding to the new key.
10. Revoke old client EPOP public key for this session.

The atomic construction provides non-repudiable chain of custody: the old key authorizes introduction of the new key, and the new key proves possession simultaneously.

# Resource Server Binding {#rs-binding}

## Key Binding Enforcement {#key-binding-enforcement}

Every JWT access token issued under EPOP carries a `cnf.jkt` claim — the SHA-256 thumbprint of the client's EPOP public key. When the RS receives an EPOP-wrapped request:

1. It verifies the outer EPOP signature using the `jwk` embedded in the header.
2. It extracts the access token from `ntk` and validates it (signature, `exp`, `aud`, scopes).
3. It computes `sha256(outer jwk header key)` and compares it to `cnf.jkt` inside the access token.

If the two values differ, the RS MUST reject the request with `invalid_token`. This check prevents an attacker from wrapping a stolen access token in their own EPOP envelope.

## Early-Exit Pattern {#early-exit}

The `rctx` check ({{rs-validation}} Step 4) SHOULD occur before nested token validation (Step 5). If `rctx.res` or `rctx.method` does not match the current request, the RS SHOULD reject immediately without decoding or verifying the access token. This is the primary defense against replay of an EPOP token from one endpoint at another within the token's short validity window.

## RS Handling of Opaque Access Tokens {#rs-opaque-tokens}

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

## RS State Management for Opaque Tokens {#rs-state-management}

The RS MUST NOT cache introspection results beyond the EPOP token's validity window. Since EPOP tokens are very short duration per-request credentials, a stale introspection cache could cause the RS to validate a post-rotation request against the pre-rotation key.

When the client performs key rotation ({{key-rotation-refresh}}), the AS MUST atomically update its server-side registry before issuing any new tokens. Introspection responses for access tokens issued after rotation MUST reflect the new client EPOP public key.

| Scenario | RS Obligation |
|:---|:---|
| Opaque access token, no caching | Call introspection per request; use returned `cnf.jkt` for binding check |
| Opaque access token, cached introspection | Cache MUST expire at or before the EPOP token validity window; MUST NOT reuse across key rotation |
| Key mismatch detected | Reject with `invalid_token`; MUST NOT fall back to a previously cached key |
| Opaque refresh token key rotation (AS-side) | AS MUST atomically update server-side key registration; partial update MUST NOT be possible |

# Authorization Server Bound Flows {#as-bound-flows}

EPOP extends proof-of-possession to AS-hosted endpoints. In each case, `rctx.res` identifies the AS endpoint being called.

## UserInfo Endpoint {#userinfo-endpoint}

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

The AS validates the EPOP token exactly as a resource server would ({{rs-validation}}), verifying `rctx.res` matches its UserInfo endpoint URI, then returns UserInfo claims.

## Token Introspection {#token-introspection}

The RS sends the EPOP token received from the client as the `token` parameter with `token_type_hint=epop_token`. The AS validates the EPOP envelope, extracts the credential from `ntk`, and returns a standard {{RFC7662}} response extended with `cnf.jkt`:

~~~http
POST /introspect HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <rs-credentials>

token=<epop-token-received-from-client>
&token_type_hint=epop_token
~~~

For opaque tokens, `cnf.jkt` in the response is the server-side registered client EPOP public key; for JWT tokens it is extracted from the token's own `cnf.jkt` claim.

Access token introspection response:

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

## Token Exchange {#token-exchange}

Token exchange ({{RFC8693}}) is performed on nested tokens: the token to be exchanged travels inside the `ntk` claim of an EPOP envelope, and the form parameters defined in {{RFC8693}} (e.g., `grant_type`, `subject_token`, `subject_token_type`, `audience`) are unchanged. A client of the token exchange MAY use an EPOP token in the `Authorization` header in place of a bearer token when authenticating to the token endpoint.

## Token Revocation {#token-revocation}

The token to be revoked travels inside the EPOP envelope ({{RFC7009}}):

~~~json
{
  "jti": "<unique-id>",
  "iat": "<unix-time>",
  "ntk": "<access-or-refresh-token>",
  "rctx": {
    "res": "https://as.example.com/revoke",
    "method": "POST"
  }
}
~~~

~~~http
POST /revoke HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

client_id=s6BhdRkqt3
&epop=<compact-serialized-epop-token>
~~~

The AS MUST confirm `sha256(outer jwk) == cnf.jkt` in the token before revoking. This prevents third-party revocation of another client's tokens.

## Pushed Authorization Requests {#par}

For PAR ({{RFC9126}}), the client MAY declare `cnf.jkt` at the PAR endpoint to pre-bind the authorization code to the client's key before the browser redirect:

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

Once a `cnf.jkt` is registered via PAR, that key binding is final for the lifetime of the resulting authorization code. If the EPOP token presented at the token endpoint declares a different `cnf.jkt` than the one recorded at the PAR endpoint, the AS MUST reject the request.

## Authorization Request Key Binding Not Supported {#auth-request-binding}

{{RFC9449}} Section 10 defines the `dpop_jkt` authorization request parameter, which lets a client declare its key thumbprint inside the authorization request so the AS can pre-bind the resulting authorization code. EPOP does not support this mechanism.

Authorization requests travel via browser redirect — an untrusted, user-controlled channel. A parameter in the authorization request URL can be intercepted and replaced by an attacker (or a malicious browser extension) who substitutes their own key thumbprint before the AS sees it. The AS has no way to verify that the thumbprint in the redirect matches the legitimate client's key.

EPOP instead establishes key binding exclusively at endpoints where the client communicates directly with the AS over TLS: at the token endpoint ({{as-validation}}), where `cnf.jkt` in the EPOP token is cryptographically proven by the outer JWS signature, and optionally at the PAR endpoint ({{par}}).

# Discovery Metadata {#discovery}

Authorization Servers that support EPOP MUST publish their capabilities in the OAuth Authorization Server Metadata document ({{RFC8414}}), available at `/.well-known/oauth-authorization-server` (or `/.well-known/openid-configuration` for OpenID Connect providers). Resource Servers publish EPOP capabilities in the OAuth Protected Resource Metadata document ({{RFC9728}}), available at `/.well-known/oauth-protected-resource`.

## Authorization Server Metadata {#as-metadata}

### epop_supported

Type: String. REQUIRED when EPOP is in any state.

| Value | Meaning |
|:---|:---|
| `"disabled"` | Server does not support EPOP. Clients MUST NOT send EPOP tokens. |
| `"recommended"` | Server supports EPOP but will also accept non-EPOP requests. Clients SHOULD use EPOP. |
| `"required"` | Server requires EPOP. Requests without a valid EPOP token MUST be rejected. |

### epop_ntk_types_supported

Type: Array of strings. REQUIRED when `epop_supported` is not `"disabled"`.

Lists the credential types the server accepts inside the `ntk` claim: `"jwt"` and/or `"opaque"`. A server that issues only opaque tokens can still support EPOP by accepting `"opaque"` in `ntk`.

### epop_key_rotation_supported

Type: Boolean. Default: `false`.

Indicates whether the server supports the recursive two-layer EPOP key rotation flow ({{key-rotation-refresh}}). Clients MUST check this field before attempting key rotation.

### epop_cnonce_seed

Type: String (Base64URL-encoded, 32 bytes). Optional.

An optional shared secret used as additional input key material for per-client HMAC key derivation. When absent, derivation uses only the client's public key. Clients MUST NOT expose this value. Rotated in coordination with `epop_cnonce_seed_id`.

### epop_cnonce_step_seconds

Type: Integer. REQUIRED when `epop_cnonce_required` is `true`.

Time-step duration in seconds for the cnonce time window. Both client and server use `T = floor(utc_now() / epop_cnonce_step_seconds)` when computing or verifying the cnonce. Clients MUST treat a missing value as a configuration error when `epop_cnonce_required` is `true`.

### epop_cnonce_seed_id

Type: String. Optional.

An opaque identifier for the current seed. Clients SHOULD cache the discovery document keyed on this value and refetch only when it changes or the document expires.

### epop_cnonce_required

Type: Boolean. Default: `false`.

When `true`, the server MUST reject EPOP tokens that omit the `cnonce` claim.

## AS Metadata Example {#as-metadata-example}

~~~json
{
  "issuer": "https://as.example.com",
  "authorization_endpoint": "https://as.example.com/authorize",
  "token_endpoint": "https://as.example.com/token",
  "userinfo_endpoint": "https://as.example.com/userinfo",
  "introspection_endpoint": "https://as.example.com/introspect",
  "revocation_endpoint": "https://as.example.com/revoke",
  "pushed_authorization_request_endpoint": "https://as.example.com/par",

  "epop_supported": "recommended",
  "epop_ntk_types_supported": ["jwt", "opaque"],
  "epop_key_rotation_supported": true,

  "epop_cnonce_seed": "<base64url-32-bytes>",
  "epop_cnonce_seed_id": "seed-2026-q2",
  "epop_cnonce_step_seconds": 30,
  "epop_cnonce_required": true
}
~~~

## Resource Server Metadata {#rs-metadata}

| Field | Type | Required | Description |
|:---|:---|:---|:---|
| `epop_supported` | String | Yes (when EPOP active) | RS EPOP posture. Same values as the AS field. Clients MUST check this before sending EPOP-wrapped resource requests. |
| `epop_ntk_types_supported` | Array of strings | Yes, when supported | Access token formats the RS accepts in `ntk`: `"jwt"` and/or `"opaque"`. |
| `epop_cnonce_seed` | String | No | MUST match the AS's `epop_cnonce_seed` when present. The AS and RS share the same seed so either can verify cnonce independently. |
| `epop_cnonce_seed_id` | String | No | MUST match the AS's `epop_cnonce_seed_id`. Clients compare AS and RS values to confirm both are operating on the same seed. |
| `epop_cnonce_step_seconds` | Integer | REQUIRED when `epop_cnonce_required` is `true` | MUST match the AS's `epop_cnonce_step_seconds`. |
| `epop_cnonce_required` | Boolean | No (default: false) | When `true`, the RS rejects EPOP tokens omitting `cnonce`. MAY be set independently of the AS's value; the client MUST include `cnonce` if either requires it. |

The `epop_cnonce_seed`, `epop_cnonce_seed_id`, and `epop_cnonce_step_seconds` values MUST be identical to those in the AS discovery document. Clients SHOULD validate this consistency on startup and after any seed rotation before submitting requests to the RS.

RS metadata example:

~~~json
{
  "resource": "https://api.example.com",
  "authorization_servers": ["https://as.example.com"],

  "epop_supported": "required",
  "epop_ntk_types_supported": ["jwt", "opaque"],

  "epop_cnonce_seed": "<base64url-32-bytes>",
  "epop_cnonce_seed_id": "seed-2026-q2",
  "epop_cnonce_step_seconds": 60,
  "epop_cnonce_required": true
}
~~~

# Client Nonce (cnonce) {#cnonce}

## Motivation {#cnonce-motivation}

{{RFC9449}} Section 8 requires a server-issued nonce with a mandatory extra HTTP round-trip: the client makes a request, receives a nonce in the `DPoP-Nonce` response header, and retries with the nonce included. This creates server-side nonce issuance state that must be managed and distributed across nodes, and lookup-dependent validation.

EPOP replaces this with a `cnonce` (Client Nonce) derived entirely offline from public inputs. No round-trip is required; no server state is issued or tracked.

## Derivation {#cnonce-derivation}

Both client and server perform the same two-step computation:

**Step 1 — Per-client key derivation (one-time per seed rotation):**

When `epop_cnonce_seed` is present:

~~~
key_material = HKDF-SHA256(
    ikm  = epop_cnonce_seed || client_public_key_spki,
    salt = SHA-256(client_public_key_spki),
    info = "epop-cnonce-v1",
    len  = 32
)
~~~

When `epop_cnonce_seed` is absent:

~~~
key_material = HKDF-SHA256(
    ikm  = client_public_key_spki,
    salt = SHA-256(client_public_key_spki),
    info = "epop-cnonce-v1",
    len  = 32
)
~~~

`client_public_key_spki` is the DER-encoded SubjectPublicKeyInfo of the key embedded in the EPOP header. `epop_cnonce_seed` is optional; when present it is prepended to the HKDF `ikm` to add server-controlled entropy. HKDF is defined in {{RFC5869}}.

**Step 2 — Per-token nonce computation:**

~~~
T         = floor(utc_now() / epop_cnonce_step_seconds)
T_bytes   = T.to_bytes(8, big-endian)
jti_bytes = utf8(jti)

cnonce = base64url(HMAC-SHA256(key_material, jti_bytes || T_bytes))
~~~

The `jti` is the EPOP token's own unique identifier.

## Server Validation {#cnonce-validation}

The server (AS or RS) recomputes cnonce using the same inputs and compares it to the received value. To absorb clock skew, the server MUST check `T-1`, `T`, and `T+1`:

~~~
for t in [T-1, T, T+1]:
    expected = base64url(HMAC-SHA256(key_material, jti_bytes || t.to_bytes(8)))
    if received_cnonce == expected:
        accept
reject
~~~

Because `jti` is already protected by the EPOP replay cache (TTL = `epop_cnonce_step_seconds` per RS node), a cnonce that passes the time-window check but carries a replayed `jti` is caught before the cache write step.

## Advantages over RFC 9449 Nonce {#cnonce-advantages}

| Property | RFC 9449 nonce | EPOP cnonce |
|:---|:---|:---|
| Server round-trip | Required | None |
| Server issuance state | Required | None |
| Validation method | Lookup-dependent | Deterministic recomputation |
| Token binding | Not bound to specific token | Bound to `jti` |
| Client identity | Not in nonce | Client public key is HKDF input |
| Distributed cache needed | Yes | No — local `jti` cache sufficient |

## Seed Rotation {#cnonce-seed-rotation}

When the server rotates `epop_cnonce_seed`, it MUST increment `epop_cnonce_seed_id` to signal the change. Rotation MUST be an overlap-aware process:

1. Generate a new seed and publish it alongside an incremented `epop_cnonce_seed_id` in the discovery document.
2. Accept cnonce values derived from both the old and new seeds for at least one full `epop_cnonce_step_seconds` overlap window, allowing in-flight requests to complete.
3. Retire the old seed only after the overlap window has elapsed.

Clients detect rotation by comparing the cached `epop_cnonce_seed_id` against the current discovery document on their next request. On a mismatch, the client MUST rederive `key_material` using the new seed before constructing the next EPOP token.

Note: The mechanism by which the server generates, distributes, and coordinates seed rotation across AS and RS nodes is out of scope for this document.

# Security Considerations {#security}

## Summary {#security-summary}

| Consideration | Requirement |
|:---|:---|
| EPOP token lifetime | Very short; server-defined. When `cnonce` is required, `epop_cnonce_step_seconds` provides an additional server-enforced validity bound applied by both AS and RS. |
| Replay prevention | MUST maintain `jti` replay cache. TTL MUST cover max lifetime + clock skew. |
| Algorithm policy | `EdDSA` (Ed25519 or Ed448) RECOMMENDED; `ES256` acceptable; RSA SHOULD NOT be used; `HS*` and `none` MUST NOT be used. See {{algorithm-selection}}. |
| PKCE in code flows | REQUIRED. Without PKCE, an attacker who captures the code can wrap it in their own EPOP token. |
| Private key storage | Platform-appropriate secure storage. See {{private-key-protection}}. |
| `rctx` validation | MUST validate when present. Skipping allows cross-resource replay within the token validity window. |
| `ntk` confidentiality | TLS REQUIRED; JWE optional for extra confidentiality. `ntk` is Base64URL-encoded, not encrypted. Refresh tokens and authorization codes are sensitive. |
| Key rotation atomicity | AS MUST validate both envelopes completely before issuing new tokens. Partial validation allows key injection. |
| RS opaque token key state | RS MUST NOT cache introspection results beyond the EPOP token validity window; AS MUST atomically update server-side key binding on rotation. |
| Token binding check | `sha256(outer jwk) == ntk.cnf.jkt` is REQUIRED. Primary defense against token substitution. |
| cnonce freshness | RECOMMENDED when server publishes seed. Offline-derived nonce binds each EPOP token to its `jti` and current time step. |

## Private Key Protection {#private-key-protection}

The security of EPOP depends entirely on the client's private key remaining secret.

**Native and mobile applications:** Clients MUST use platform secure storage facilities (e.g., Android Keystore, iOS Secure Enclave). Private key operations SHOULD be performed inside the secure element where the platform supports it, so that key material never enters application memory.

**Browser environments:** Private keys MUST be generated as non-extractable `CryptoKey` objects via the Web Crypto API (`extractable: false`). This prevents JavaScript running in the same origin — including code injected via XSS — from exporting the raw key bytes. Clients MUST NOT store private keys in `localStorage`, `sessionStorage`, `IndexedDB`, or any JavaScript-readable store.

**Symmetric algorithm prohibition:** EPOP tokens MUST use asymmetric digital signature algorithms. Symmetric algorithms (e.g., `HS256`) are forbidden because they require the verifier to hold the same secret as the signer, making independent third-party verification impossible and creating shared-secret distribution risk.

**General:** Private key material MUST never be logged, serialized into application state, or transmitted over any channel. The `jwk` embedded in the EPOP header carries the public key only. Implementations MUST verify that no private key fields (`d`, `p`, `q`, `dp`, `dq`, `qi`) are present in the `jwk` header parameter before accepting or forwarding an EPOP token.

## Token Substitution Attacks {#token-substitution}

The key binding check in {{rs-validation}} Step 6 is the primary defense against token substitution. An attacker who captures an access token and wraps it in an EPOP envelope signed with their own key will produce a `sha256(outer jwk)` value that does not match the `cnf.jkt` embedded in the token by the AS. The RS MUST reject this mismatch.

## Cross-Protocol Replay {#cross-protocol-replay}

Without `rctx` validation, an EPOP token captured from one protocol or endpoint could be replayed at another within the token's validity window. Servers MUST validate `rctx.res` and `rctx.method` when these claims are present. Clients SHOULD always include `rctx` to maximize replay resistance.

## Key Rotation Security {#key-rotation-security}

The AS MUST validate both envelopes completely before issuing new tokens or updating key bindings. Partial validation would allow an attacker who holds a captured refresh token to inject a new key by constructing a valid outer envelope while providing an invalid inner envelope.

# IANA Considerations {#iana}

## HTTP Authentication Scheme Registration {#iana-http-scheme}

This specification requests registration of the following entry in the "Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry" ({{RFC7235}}):

Authentication Scheme Name:
: `EPOP`

Pointer to specification text:
: {{resource-access}} and {{token-structure}} of this document.

## JWT Claims Registration {#iana-jwt-claims}

This specification requests registration of the following JWT claims in the "JSON Web Token Claims" registry established by {{RFC7519}}:

Claim Name: `ntk`
: Claim Description: Nested Token — the OAuth 2.0 credential embedded inside the EPOP envelope.
: Change Controller: IETF
: Specification Document(s): {{ntk-values}} of this document

Claim Name: `rctx`
: Claim Description: Request Context — a JSON object identifying the target resource and protocol action.
: Change Controller: IETF
: Specification Document(s): {{token-payload}} of this document

Claim Name: `cnonce`
: Claim Description: Client Nonce — offline-derived HMAC value for replay resistance without server-issued nonce state.
: Change Controller: IETF
: Specification Document(s): {{cnonce}} of this document

## JWT Type Registration {#iana-jwt-type}

This specification requests registration of the `epop+jwt` media type suffix:

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

# Relationship to Other Specifications {#related-specs}

| RFC | Title | How EPOP Extends It |
|:---|:---|:---|
| {{RFC7628}} | A Set of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth | EPOP extends RFC 7628 by introducing `EPOP` as a new OAuth authentication type for the SASL `auth` field and defining `OAUTHEPOP` as a new SASL mechanism. All behaviors defined in RFC 7628 remain in effect; this document adds only the `auth=EPOP` field value and the key binding check that `OAUTHBEARER` servers apply when they encounter it. |
| {{RFC9449}} | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | EPOP generalizes the DPoP proof model: replaces `htm`/`htu` with `rctx` for protocol agnosticism; replaces the `ath` hash with `ntk` embedding so credential and proof travel as one object; extends coverage to authorization codes and refresh tokens; adds atomic key rotation and the offline `cnonce`. |
| {{RFC7636}} | Proof Key for Code Exchange (PKCE) | EPOP elevates PKCE from RECOMMENDED to REQUIRED in all authorization code flows. |
| {{RFC8414}} | OAuth 2.0 Authorization Server Metadata | EPOP adds new discovery fields to the well-known document: `epop_supported`, `epop_ntk_types_supported`, `epop_key_rotation_supported`, and the `epop_cnonce_*` family. |
| {{RFC7638}} | JSON Web Key (JWK) Thumbprint | EPOP uses the SHA-256 JWK thumbprint (`cnf.jkt`) as its primary key binding primitive — embedded in every issued token and checked by the RS as its main defense against token substitution. |
| {{RFC7662}} | OAuth 2.0 Token Introspection | EPOP extends introspection responses to include `cnf.jkt`. For opaque tokens the AS returns the server-side registered client EPOP public key; for JWT tokens it is extracted from the token's own claim. Introspection requests may themselves be EPOP-wrapped to authenticate the caller. |
| {{RFC8693}} | OAuth 2.0 Token Exchange | The `subject_token` travels inside EPOP `ntk`, requiring the requesting service to prove possession of the key bound to that token before an exchange is granted. |
| {{RFC7009}} | OAuth 2.0 Token Revocation | The token to be revoked travels inside EPOP `ntk`; the AS verifies key binding before revoking, preventing third-party revocation. |
| {{RFC9126}} | OAuth 2.0 Pushed Authorization Requests (PAR) | EPOP extends PAR to let the client declare `cnf.jkt` at the earliest point in the flow, pre-binding the authorization code before the browser redirect. |
| {{RFC5869}} | HMAC-based Key Derivation Function (HKDF) | EPOP uses HKDF-SHA256 to derive a per-client key from the optional server-controlled `epop_cnonce_seed` and the client's public key, enabling stateless offline cnonce computation. |

# Acknowledgments
{:numbered="false"}

The author thanks the OAuth Working Group for their foundational work on DPoP ({{RFC9449}}), PKCE ({{RFC7636}}), and the related specifications that this document extends.
