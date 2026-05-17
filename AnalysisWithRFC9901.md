# EPOP and RFC 9901 SD-JWT+KB: A Comparative Analysis

## Why EPOP Is Needed Despite RFC 9901

RFC 9901 (SD-JWT) and EPOP address different problems in different security domains, even though both involve cryptographic key binding at token presentation time. This document provides a precise technical analysis of where these mechanisms differ, where each is stronger, and why both are necessary in a complete OAuth/identity ecosystem.

The short answer: **RFC 9901 SD-JWT+KB provides holder-binding for identity credential presentation. EPOP provides sender-constraining for OAuth API authorization.** These sound similar but operate in distinct trust domains, address different attack surfaces, and integrate with different protocol ecosystems. Neither subsumes the other.

---

## 1. Problem Statements Are Categorically Different

### RFC 9901 SD-JWT+KB Solves

The issuer signs a credential asserting claims about a subject. At presentation time, the holder must prove:

> "I am the legitimate holder of this credential — I control the private key recorded in the credential's `cnf` claim — and I am choosing to disclose exactly these claims to this verifier."

The primary threats addressed are:
- Credential theft and presentation by a non-holder
- Linkability across presentations (via selective disclosure)
- Oversharing (holder chooses minimal disclosure set)

This is the verifiable credentials / digital identity space.

### EPOP Solves

The authorization server issues an access token to a specific client, binding it to the client's public key. At API invocation time, the client must prove:

> "I am the legitimate sender of this access token — I control the private key to which the AS bound this token — and I am invoking this specific resource in this specific request context."

The primary threats addressed are:
- Token theft and replay (bearer token vulnerability)
- Proof stripping and header loss in intermediary-heavy deployments
- Sender-constraining across non-HTTP transports
- Stateless proof validation for high-throughput and agentic systems

This is the OAuth 2.0 / API authorization space.

These problem statements share a surface-level resemblance (both use key binding at presentation) but differ in actors, trust relationships, and ecosystem integration requirements.

---

## 2. Key Binding: Semantic Differences

This is the most important section for readers familiar with RFC 9901. The key binding models differ in four dimensions: **what is being bound**, **who establishes the binding**, **when the proof is constructed**, and **what the proof commits to**.

### 2.1 RFC 9901 KB-JWT Key Binding

The key binding structure in RFC 9901 is:

```
SD-JWT  (issuer-signed)
  └─ cnf.jwk  →  holder public key embedded by issuer

KB-JWT  (holder-signed, created fresh per presentation)
  ├─ aud        →  verifier identity
  ├─ nonce      →  verifier-supplied, prevents replay
  ├─ iat        →  issuance time of this KB-JWT
  └─ sd_hash    →  hash(SD-JWT issuer sig || selected disclosures)
```

The full presentation wire format is:

```
<SD-JWT>~<Disclosure_1>~...~<Disclosure_n>~<KB-JWT>
```

**What the KB-JWT proves:** The presenter controls the private key corresponding to the public key (`cnf.jwk`) embedded in the SD-JWT by the issuer, and they are committing to a specific disclosed subset of claims (`sd_hash`) for a specific verifier (`aud`) with a specific nonce.

**Who establishes the binding:** The issuer, at credential issuance time, by embedding `cnf.jwk` in the SD-JWT. The holder cannot change this binding after issuance.

**Credential-proof relationship:** The SD-JWT and KB-JWT are **separate cryptographic objects**. The SD-JWT can exist and be transmitted without a KB-JWT (KB-JWT is defined as optional in RFC 9901 when the verifier does not require holder binding). The KB-JWT references the SD-JWT via `sd_hash` but is not structurally inseparable from it. A verifier must correlate three artifacts: the SD-JWT, the disclosure set, and the KB-JWT.

**Nonce source:** Verifier-supplied. The holder cannot create a valid KB-JWT without first receiving a nonce from the verifier, which requires a verifier-online interaction prior to presentation.

### 2.2 EPOP Key Binding

The EPOP structure is:

```
EPOP Token  (client-signed, created fresh per request)
  Header:
    ├─ jwk     →  client public key (embedded by client)
    └─ alg     →  signing algorithm
  Payload:
    ├─ ntk     →  nested OAuth credential (access/refresh token)
    ├─ rctx    →  request context {res, method, id}
    ├─ jti     →  per-request unique identifier (replay cache key)
    ├─ iat     →  token issuance time
    └─ cnonce  →  offline-derived replay bound (optional)

Access Token (AS-issued, embedded in ntk):
    └─ cnf.jkt →  sha256(client public key) — bound by AS at issuance
```

**What the EPOP proves:** The client controls the private key whose public component is embedded in the EPOP header (`jwk`), the nested access token was issued by the AS to a client presenting exactly that key (`cnf.jkt` match), and the credential is being presented for a specific resource and method in this specific request (`rctx`).

**Who establishes the binding:** The authorization server, at token issuance time, by embedding `cnf.jkt` (SHA-256 thumbprint of the client's public key) in the issued access token. The client cannot forge this binding; any attempt to wrap a stolen token with a different key produces a `cnf.jkt` mismatch detected by the RS.

**Credential-proof relationship:** The credential (`ntk`) and the proof (the outer JWT signature) are **the same cryptographic object**. There is no credential without a proof — the access token can only be used inside a signed EPOP envelope. The verifier processes a single compact serialization.

**Nonce source:** Offline-derived (client-generated via HKDF + HMAC from the client's public key and a time-step counter). No server round-trip required. The `jti` replay cache is the primary replay prevention mechanism; `cnonce` provides an additional time-window bound without server state.

### 2.3 Summary of Semantic Differences

| Dimension | RFC 9901 KB-JWT | EPOP |
|:---|:---|:---|
| **What is bound** | Identity credential to holder | Authorization credential to authorized sender |
| **Who the holder/sender is** | The human or entity the credential was issued *about* | The OAuth client authorized to *use* the credential |
| **Who establishes the binding** | Issuer (at credential issuance) | Authorization Server (at token issuance) |
| **Credential-proof relationship** | Separate artifacts, linked by `sd_hash` | Single inseparable cryptographic object |
| **Proof freshness** | KB-JWT created per presentation | EPOP envelope created per request |
| **Nonce source** | Verifier-supplied (requires verifier interaction) | Offline-derived (no round-trip) |
| **What the proof commits to** | Which claims are disclosed (`sd_hash`) and to which verifier party (`aud`) — purpose or operation within the verifier's domain is not bound | Specific resource URI and protocol method (`rctx`) — both the target and the operation are cryptographically bound |
| **What the proof carries** | Hash of the presentation artifact (`sd_hash`); the credential itself is NOT embedded — the RS cannot extract or validate the credential from the KB-JWT alone | The actual OAuth credential embedded directly (`ntk`); the RS extracts and validates it from the single compact serialization |
| **Proof optionality** | KB-JWT is OPTIONAL when verifier doesn't require holder binding | Outer envelope is REQUIRED; there is no bare access token |
| **Claim disclosure control** | Holder selects minimal disclosure set | AS controls what claims appear in the nested token |
| **Protocol scope of binding** | Verifier party identity (`aud`) — does not scope to a sub-resource or operation within that verifier | Resource URI, method, and protocol action (`rctx`) |
| **Transport definition** | Not defined by RFC 9901 — delegated to higher-level specifications (e.g., OpenID4VP) | Normative: `Authorization: EPOP <compact-serialized-epop-token>` per RFC 7235 |
| **Cross-protocol applicability** | Primarily HTTP/browser flows | Explicitly HTTP and non-HTTP (MQTT, Kafka, MCP, gRPC, SASL) |

---

## 3. Validation Pipeline Complexity

The `~`-delimited serialization format of SD-JWT and the `ntk`-nesting model of EPOP produce materially different validation pipelines. This difference matters for implementers, for intermediaries that must forward credentials without stripping them, and for the robustness of partial-validation attacks.

### 3.1 Parsing Requires Non-Standard Logic

The SD-JWT wire format is:

```
<Issuer-signed-JWT>~<Disclosure_1>~<Disclosure_2>~...~<Disclosure_N>~[KB-JWT]
```

A validator cannot delegate parsing to a standard JWT library. It must:

1. Split the string on `~` — producing a variable-length array.
2. Identify which element is the KB-JWT and which are disclosures. Both are Base64url strings. The distinguishing heuristic is that a compact JWT contains exactly two `.` characters (header.payload.signature); a disclosure contains none. This is an implicit structural convention, not a typed or length-prefixed field.
3. Handle the zero-disclosure edge case: `<SD-JWT>~<KB-JWT>` collapses the presentation to two `~`-delimited parts, where the second part is the KB-JWT, not a disclosure — the same position as a first disclosure in the non-zero case. The parser must apply the `.`-count heuristic to disambiguate.

EPOP's `ntk` is a named JSON claim in a standard JWT payload. Any RFC 7519-compliant library extracts it as `payload["ntk"]`. No custom tokenizer is needed, and the structure is unambiguous regardless of what the claim's value looks like.

**Ecosystem tooling divergence.** This distinction has a direct consequence for RS implementors. JWT, JOSE, and JWS are baseline infrastructure: every major language ecosystem has mature, battle-tested JWT libraries (e.g., `python-jose`, `nimbus-jose-jwt`, `go-jose`, `jsonwebtoken`). DPoP proof tokens are standard JWTs — RS operators validate them with the same libraries they already use. EPOP tokens are standard JWTs — RS operators validate them with the same libraries. SD-JWT is structurally not a JWT: it is a `~`-delimited compound string for which standard JWT/JOSE/JWS libraries provide no built-in support. RS adoption of SD-JWT as an access token format requires introducing a new SD-JWT-specific library dependency that DPoP and EPOP do not. The `~` format is not a minor extension of JWT parsing; it is a different serialization format.

### 3.2 The `sd_hash` Reconstruction Is a Byte-Exact String Operation

The KB-JWT's `sd_hash` is defined as:

```
sd_hash = BASE64URL(SHA-256(ASCII(<SD-JWT>~<D1>~<D2>~...~<Dn>~)))
```

Three subtleties compound here:

**The trailing `~` is mandatory.** The hash input ends with `~` even when a KB-JWT follows immediately after. A parser that reconstructs the input string from parsed parts must append this trailing delimiter before hashing. Omitting it produces an incorrect `sd_hash` for every presentation that is actually valid.

**Disclosure bytes must be preserved from the wire, not re-encoded.** The hash is computed over the raw bytes as received. If a validator decodes a disclosure from Base64url into its JSON `[salt, name, value]` array and then re-encodes it (e.g., with normalized JSON whitespace or different Base64url padding), the resulting hash will not match `sd_hash` even though the disclosure content is identical. Implementations must retain the original wire bytes for every disclosure in parallel with the decoded values.

**Disclosure order is significant.** Disclosures must appear in the hash input in the same order as in the presentation. There is no defined canonical ordering in RFC 9901; the presenter's ordering is authoritative for the purpose of `sd_hash`. A validator that sorts disclosures before hashing (a plausible normalization attempt) will produce incorrect results.

EPOP's key binding check is:

```
sha256(canonicalized JWK bytes from outer header) == cnf.jkt from ntk
```

This is a comparison of two thumbprints — one computed from a structured JWK object using the canonical algorithm defined in RFC 7638, one extracted from a JWT claim. No string reconstruction, no byte-preservation requirement, no ordering dependency.

### 3.3 Multiple Independent Trust Chains Must Be Correlated

SD-JWT+KB validation involves three distinct cryptographic operations over three separate objects:

```
1. Verify issuer signature over <SD-JWT> using issuer public key
2. For each Disclosure_i:
     a. Decode Base64url → parse JSON array [salt, claim_name, claim_value]
     b. Compute SHA-256(raw wire bytes of Disclosure_i)
     c. Locate matching digest in _sd[] arrays within SD-JWT payload
     d. Accumulate reconstructed claim set
3. Verify KB-JWT JWS signature using holder key (from SD-JWT cnf.jwk)
4. Assert KB-JWT.sd_hash == SHA-256(<SD-JWT>~<D1>~...~<Dn>~)
5. Assert KB-JWT.aud matches expected verifier identity
6. Assert KB-JWT.nonce matches the verifier-issued challenge
```

Steps 1 and 3 use different keys (issuer vs. holder). Steps 2 and 4 use the same disclosure bytes but for different purposes (claim reconstruction vs. hash input). The structural dependency means step 3 cannot begin until step 2 is complete (the `sd_hash` input requires all disclosure bytes in order), but step 1 is independent of steps 2–4. A validator that completes step 1 and exits early — having verified the issuer's signature — has not verified holder binding at all. This partial-validation trap is non-obvious and has been a source of implementation defects in SD-JWT deployments.

EPOP validation:

```
1. Verify outer EPOP JWS signature using public key from jwk header
2. Assert iat within acceptable window; assert jti not in replay cache; record jti
3. If cnonce required: verify cnonce for current time-step
4. If rctx present: assert rctx.res and rctx.method match current request
5. If ntk present: validate inner token (JWT verification or introspection call)
6. Assert sha256(outer jwk) == cnf.jkt from inner token
```

All claims covered by step 6 are already authenticated by step 1 — the outer signature covers the `jwk` header and the entire payload including `ntk`. There is no analogous risk of accepting a structurally valid but partially-verified envelope: if step 1 passes, the `jwk` used in step 6 is the one the client signed with, and `ntk` is the credential the client chose to present.

### 3.4 Validation Ordering Constraints

In SD-JWT+KB, disclosure parsing (step 2) must complete before KB-JWT verification (step 3–4) can begin, because the `sd_hash` input depends on the full disclosure byte sequence. This creates a mandatory sequential dependency: the validator cannot pipeline or parallelize the two signature verifications.

In EPOP, the outer signature (step 1) and inner token signature (step 5) use independent keys and independent inputs. An implementation can verify both in parallel and perform the key binding check (step 6) after both complete. The ordering constraint is relaxed.

### 3.5 Comparison Table

| Validation Dimension | RFC 9901 SD-JWT+KB | EPOP |
|:---|:---|:---|
| Parsing model | Custom `~`-split parser; structural heuristic to identify KB-JWT | Standard JWT library; `ntk` is a typed JSON claim |
| Signature operations | Two independent (issuer key + holder key) | Two independent (client key + AS key or introspection) |
| Claim extraction | Per-disclosure digest matching against `_sd[]` arrays | Direct JWT claim access |
| Integrity binding | `sd_hash` over reconstructed byte string with trailing `~` | `cnf.jkt` thumbprint equality — no reconstruction |
| Byte-preservation requirement | Yes — raw disclosure bytes must be retained for `sd_hash` | No |
| Ordering dependency | Yes — disclosure order is significant for `sd_hash` | No |
| Partial-validation risk | High — issuer signature can pass independently of holder binding | Low — single outer signature covers all credential material |
| Zero-disclosure edge case | Parser must apply `.`-count heuristic to distinguish KB-JWT | Not applicable |
| Standard library reuse | Requires SD-JWT-specific parser beyond JWT library | Standard JWT library sufficient for outer envelope |

---

## 4. Why EPOP Is Needed Despite RFC 9901 SD-JWT+KB

This section makes the constructive case for EPOP's necessity — not as a critique of RFC 9901, which is a well-designed specification for its domain, but to explain precisely where its design leaves an unaddressed gap in the OAuth ecosystem.

### 4.1 RFC 9901 Does Not Integrate with the OAuth Token Lifecycle

RFC 9901 defines a credential format and a holder-binding mechanism for presentation. It does not define:

- How the credential-bound key is established during **authorization code exchange**
- How key binding is preserved across **token refresh**
- How a client performs **atomic key rotation** without disrupting active sessions
- How a relying party performs **token introspection** with key binding validation
- How a client performs **token revocation** with proof-of-possession (i.e., only the legitimate key holder can revoke)
- How key binding is declared in **Pushed Authorization Requests (PAR)**

EPOP defines normative behavior for all of these. Without a specification that covers the full OAuth token lifecycle with consistent key binding semantics, each deployment must invent its own protocol-specific adaptations — which is precisely the interoperability problem EPOP is designed to solve.

### 4.2 The Verifier-Nonce Requirement Is a Deployment Constraint

RFC 9901 KB-JWT requires a verifier-supplied `nonce`. This is sound for interactive credential presentation flows (wallets, browsers) where the verifier can issue a nonce challenge before presentation. It is architecturally incompatible with:

- **High-throughput API deployments** where a pre-flight nonce round-trip doubles latency per request
- **Non-HTTP transports** (MQTT, Kafka, gRPC, SASL) where there is no request-response channel at the application layer for nonce exchange
- **Asynchronous and event-driven systems** where requests may be queued and processed without a synchronous verifier-client channel
- **Agentic systems** where an autonomous agent may invoke tools across multiple transport types without a human-in-the-loop for nonce coordination

EPOP's `cnonce` is derived offline from the client's public key and a time-step counter (HKDF + HMAC), requiring no server round-trip. The server derives the same value independently for verification. This is a deliberate design choice for the non-HTTP / agentic deployment context that RFC 9901 does not target.

### 4.3 The Dual-Header Propagation Problem Is Not Addressed by KB-JWT

DPoP (RFC 9449), the existing OAuth sender-constraining mechanism, requires two coordinated HTTP headers — `Authorization: DPoP <token>` and `DPoP: <proof>` — to travel together through every intermediary. Loss of the `DPoP` header at any hop silently breaks the proof-of-possession guarantee without an error visible to the resource server. This is a documented deployment barrier in heterogeneous microservice environments.

RFC 9901 SD-JWT+KB does not address this problem. The KB-JWT is also a separate artifact that must travel alongside the SD-JWT. In an HTTP API context using SD-JWT as an access token format, the same dual-artifact propagation problem would apply.

EPOP's envelope model — where the proof is structurally inside the credential — means the `Authorization: EPOP <epop-token>` header carries the inseparable credential-and-proof pair as a single value. Any intermediary that forwards the `Authorization` header forwards both the credential and its proof. This is a meaningful operational improvement over both DPoP and any analogous SD-JWT+KB-for-API-access pattern.

### 4.4 The `sd_hash` Mechanism and `rctx` Serve Different Purposes

The KB-JWT's `sd_hash` field commits the holder to a specific **disclosure set** — it prevents the holder from presenting different claims while reusing the same KB-JWT. This is the right design for identity credential presentations where the verifier cares about which claims are being asserted.

EPOP's `rctx` commits the client to a specific **request context** — it binds the proof to a specific resource URI, protocol method, and optionally a correlation identifier. This prevents an attacker who captures a valid EPOP token from replaying it at a different endpoint or with a different method within the token's short validity window.

These are orthogonal security properties. Neither mechanism provides the other's guarantee:

- KB-JWT + `sd_hash` does not bind the presentation to a specific resource URI or protocol method
- EPOP + `rctx` does not commit to a specific disclosure set or provide selective disclosure

An SD-JWT-based access token presented with a KB-JWT would prove holder binding but would not bind the presentation to the specific API endpoint being called. An `rctx`-less EPOP token would bind sender identity but would not protect against cross-endpoint replay (which is why `rctx` is strongly RECOMMENDED in the EPOP draft).

**`aud` is verifier identity, not purpose binding.** The KB-JWT's `aud` claim identifies the verifier as a party — typically a domain or service (`"aud": "https://example.com"`). It does not identify the specific resource, endpoint, or operation within that party's domain. A single verifier may host hundreds of distinct API resources. A KB-JWT presented to `https://example.com` cannot be restricted to `GET /orders` versus `POST /payments` at the protocol level — both requests satisfy the same `aud` constraint. EPOP's `rctx` = `{res: "https://example.com/orders", method: "GET"}` binds to both the resource and the operation, making cross-resource replay within a verifier's domain detectable. The KB-JWT model proves *to whom* the holder is presenting; the EPOP model proves *to whom and for what specific purpose*.

**`sd_hash` commits to a hash of the presentation artifact, not the credential the RS validates.** The KB-JWT's `sd_hash` is the SHA-256 of the `~`-delimited presentation byte string (SD-JWT + disclosures + trailing `~`). It is a commitment that the holder constructed that exact presentation — it is not the credential itself, nor does it contain any extractable token value. From a KB-JWT alone, the RS cannot reconstruct the claim set, cannot verify the issuer's signature, and cannot determine whether the credential is active or expired. The RS must independently receive and process the full `~`-delimited SD-JWT presentation alongside the KB-JWT; the KB-JWT's role is to prove that the holder was the one who assembled that presentation. In EPOP, the `ntk` claim IS the OAuth credential: the RS extracts it with `payload["ntk"]`, validates it (JWT verification or introspection), and checks `cnf.jkt` against the outer key. The RS has everything it needs in the single compact serialization. There is no parallel artifact to receive, no presentation string to reconstruct, and no hash to recompute from parts.

### 4.5 Non-HTTP Transport Support Is a Gap Neither RFC 9901 nor RFC 9449 Fills

RFC 9449 DPoP uses `htm` (HTTP method) and `htu` (HTTP URI) claims that are HTTP-specific by definition. No existing specification defines a sender-constraining mechanism with interoperable semantics for MQTT, Kafka, gRPC, SASL, or the Model Context Protocol.

RFC 9901 KB-JWT uses `aud` (verifier identity) and verifier-supplied `nonce`, which are protocol-neutral in principle but have no defined semantics for non-HTTP transports. There is no standardized way to express "this KB-JWT is valid for publishing to this MQTT topic" or "this KB-JWT is valid for producing to this Kafka partition."

EPOP's `rctx` is protocol-neutral by design. The `rctx.res` field accepts any URI or URN:

| Protocol | `rctx.res` example | `rctx.method` |
|:---|:---|:---|
| HTTPS | `https://api.example.com/orders` | `GET` |
| MQTT | `urn:mqtt:broker:sensors/temperature` | `PUBLISH` |
| MCP | `urn:mcp:server:filesystem` | `tools/call` |
| Kafka | `urn:kafka:cluster:orders-topic` | `Produce` |
| gRPC | `urn:grpc:service:helloworld.Greeter` | `SayHello` |

This is not a marginal improvement — it is the only standardized mechanism that extends OAuth sender-constraining beyond HTTP.

### 4.6 Atomic Key Rotation During Active Sessions

RFC 9901 does not define a mechanism for rotating the holder's key pair without renegotiating the credential with the issuer (which typically means re-issuing the entire credential). For long-lived credentials this is a significant operational burden.

EPOP defines atomic key rotation using a two-envelope structure: the inner envelope (signed with the old key) introduces the new key via `cnf.jkt`; the outer envelope (signed with the new key) wraps the inner. The AS verifies the chain of custody — old key authorized the new key's introduction, new key simultaneously demonstrates possession — and atomically updates the server-side binding. Active sessions experience no disruption.

This is specifically designed for the OAuth use case where a client may hold long-lived refresh tokens that outlive individual key pair lifecycles, a scenario that does not arise in the verifiable credentials context that RFC 9901 addresses.

### 4.7 RFC 9901 Defines Encoding, Not Transport

RFC 9901 is explicitly a credential format specification. Section 1 of RFC 9901 states that the document defines the SD-JWT format and the Key Binding JWT structure; it does not define how an SD-JWT presentation reaches a verifier or resource server. Transport is intentionally delegated to higher-level specifications — OpenID for Verifiable Presentations (OpenID4VP) defines one HTTP-based transport; other ecosystems define their own.

This has two concrete consequences for RS implementors considering SD-JWT as an OAuth access token format:

**No normative transport.** There is no RFC 9901-defined mechanism for an RS to signal that it expects an SD-JWT presentation, no defined HTTP scheme analogous to `Bearer` or `DPoP`, and no standardized way for a client to know where to send the `~`-delimited presentation string. Each deployment must import a transport specification from a different standards body or invent its own convention — exactly the fragmentation that a complete OAuth profile is designed to prevent.

**The `~`-format parsing burden falls on the RS with no transport guidance.** An RS that receives an SD-JWT presentation inherits all the parsing complexity described in Section 3 of this document — the `~`-split tokenizer, the `.`-count heuristic, the byte-preservation requirement for `sd_hash` — without any RFC 9901 guidance on the surrounding transport protocol. The RS must implement both a non-standard parser and infer the delivery mechanism from a higher-level specification that RFC 9901 does not normatively reference.

EPOP is a complete, self-contained profile: it defines the token format, the `Authorization: EPOP` HTTP scheme (RFC 7235), the `epop` form parameter for token endpoint submissions, and the `OAUTHEPOP` SASL mechanism for non-HTTP transports. An RS implementor has a single specification to implement. The parsing model is standard JWT; the transport is normative. Nothing needs to be imported from a separate credential presentation protocol.

---

## 5. Advantages and Disadvantages

### 5.1 RFC 9901 SD-JWT+KB

**Advantages:**

- **Selective disclosure:** Holder controls which claims are revealed to which verifier. Verifiers receive the minimum necessary claim set. EPOP has no equivalent mechanism.
- **Verifier unlinkability:** Different disclosure sets with different nonces prevent verifiers from correlating presentations. EPOP's `cnf.jkt` is a stable thumbprint that creates cross-context linkability (the EPOP draft acknowledges this as a privacy consideration).
- **Issuer-independent presentation:** Once issued, the SD-JWT can be presented to any verifier without AS involvement. EPOP's opaque token flow requires AS introspection.
- **Credential portability:** The SD-JWT is a self-contained credential suitable for wallets, cross-domain identity federation, and decentralized identity ecosystems.
- **Human-centric design:** Designed for credentials issued to (and controlled by) natural persons, with corresponding privacy protections.
- **Ecosystem fit:** Directly usable in OpenID4VC, ISO 18013-5, and W3C Verifiable Credentials contexts.

**Disadvantages (relative to the EPOP use case):**

- **No OAuth token lifecycle integration:** Does not define behavior for authorization code exchange, token refresh, revocation with PoP, introspection, or PAR key binding.
- **Verifier-nonce dependency:** Pre-flight nonce exchange is required, which is incompatible with high-throughput and non-HTTP deployments.
- **Separate proof artifact:** The KB-JWT is a distinct object from the SD-JWT, creating the same multi-artifact correlation burden that EPOP eliminates.
- **No request context binding:** KB-JWT does not bind the presentation to a specific resource URI or protocol method; cross-endpoint replay is not prevented at the protocol level.
- **No non-HTTP transport semantics:** No standardized `rctx`-equivalent for MQTT, Kafka, gRPC, or SASL.
- **No key rotation during active sessions:** Key rotation requires credential re-issuance.

### 5.2 EPOP

**Advantages:**

- **Inseparable credential-and-proof:** The access token and its proof of possession are a single signed JWT. There is no dual-artifact synchronization problem; any intermediary that forwards the `Authorization` header forwards the complete proof-of-possession structure.
- **Full OAuth token lifecycle coverage:** Defines normative behavior for authorization code exchange, token refresh, atomic key rotation, revocation with PoP, token introspection, token exchange, and PAR.
- **Transport-neutral `rctx`:** Sender-constraining with consistent semantics across HTTP, MQTT, Kafka, gRPC, SASL, and MCP. The only standardized mechanism in this category.
- **Offline `cnonce`:** Replay resistance without a server round-trip; compatible with stateless servers, non-HTTP transports, and high-throughput deployments.
- **Atomic key rotation:** Non-disruptive key pair rotation during active sessions without credential re-issuance.
- **Revocation with proof-of-possession:** Only the client holding the private key can revoke its own tokens; a token thief cannot perform revocation as a denial-of-service.
- **Intermediary transparency:** The proof survives through intermediaries that forward the `Authorization` header, unlike DPoP which is silently broken by header stripping.

**Disadvantages (relative to the RFC 9901 use case):**

- **No selective disclosure:** The nested access token carries the full claim set issued by the AS. EPOP provides no mechanism for the client to selectively disclose claims to different resource servers.
- **Key identifier tracking:** `cnf.jkt` is a stable public key thumbprint. Reuse across multiple AS/RS deployments creates a cross-context correlation identifier. The draft recommends per-AS key pairs, but this is guidance, not enforcement.
- **Higher token size:** The EPOP envelope (header with embedded JWK + payload with nested token) is larger than a plain bearer token or a DPoP-protected token. The draft recommends Ed25519 for key compactness.
- **Client key management burden:** Clients must manage asymmetric key pairs, including secure storage, rotation, and platform-specific secure element integration. This is a higher implementation burden than bearer tokens.
- **Identity credential limitation:** Not designed for human-centric identity presentation, selective disclosure, or verifiable credential ecosystems.

---

## 6. Security Property Comparison

| Security Property | RFC 9901 SD-JWT+KB | EPOP |
|:---|:---|:---|
| Holder/sender-binding strength | Strong (issuer-embedded cnf.jwk) | Strong (AS-embedded cnf.jkt + envelope signature) |
| Credential-proof atomicity | Weak (separate KB-JWT, sd_hash linkage) | Strong (single signed envelope, ntk embedding) |
| Replay resistance | Moderate (verifier nonce; no jti replay cache defined) | Strong (mandatory jti replay cache; optional cnonce time-window) |
| Request context binding | None (KB-JWT binds to verifier aud, not resource+method) | Strong (rctx.res + rctx.method, validated at RS) |
| Cross-endpoint replay prevention | Not addressed | Strong (rctx validated; early-exit pattern defined) |
| Intermediary resilience | Moderate (separate KB-JWT can be stripped) | Strong (proof inside Authorization header value) |
| Token theft resistance | Moderate (KB-JWT prevents replay but requires nonce exchange) | Strong (cnf.jkt mismatch immediately detectable) |
| Selective disclosure | Excellent | None |
| Verifier unlinkability | Excellent (different disclosure sets per verifier) | Weak (cnf.jkt is stable across resource servers) |
| Non-HTTP transport support | None standardized | Core design goal |
| OAuth flow integration | None | Complete lifecycle coverage |
| Offline proof generation | No (requires verifier nonce) | Yes (cnonce is client-derived) |

---

## 7. Architectural Summary: Complementary, Not Competing

RFC 9901 is a **credential presentation architecture** optimized for privacy-preserving selective disclosure of identity claims.

EPOP is a **capability invocation security architecture** optimized for sender-constrained OAuth credentials across heterogeneous transports.

The most precise description of the relationship: RFC 9901 asks "which claims about this subject should be revealed to this verifier?" EPOP asks "is the entity presenting this access token the same entity the AS issued it to, and is it presenting it for the right resource and operation?"

These are questions in different layers of the identity and authorization stack. A complete deployment serving both identity presentation and API authorization would use both:

- SD-JWT (RFC 9901) for portable, selectively disclosed identity credentials in wallet and verifiable credential flows
- EPOP for sender-constrained OAuth access tokens in API authorization, service-to-service, and agentic workloads

They can be directly composed. An SD-JWT verifiable credential could be embedded inside an EPOP envelope's `ntk` claim (if the SD-JWT is the access token format), combining selective disclosure of identity claims with sender-constrained API authorization and transport-neutral deployment.

---

## 8. EPOP's Contribution to the OAuth Ecosystem

For the benefit of readers evaluating EPOP as a standards contribution, its primary innovations relative to the existing landscape are:

1. **Envelope atomicity for OAuth credentials.** The credential and its proof are a single cryptographic object. Neither DPoP nor any existing sender-constraining mechanism achieves this; all require separate proof artifacts.

2. **Protocol-neutral request context (`rctx`).** A standardized, extensible binding between an OAuth credential and a protocol-specific resource invocation, applicable uniformly to HTTP, MQTT, Kafka, gRPC, SASL, and MCP. No existing specification fills this role.

3. **Offline `cnonce` for stateless proof validation.** Replay resistance without server-issued nonce state, enabling stateless servers, high-throughput deployments, and non-HTTP transport support. DPoP's server-issued nonce (RFC 9449 Section 8) and RFC 9901's verifier-supplied nonce both require online interaction.

4. **Full OAuth token lifecycle coverage with consistent key binding.** Authorization code exchange, token refresh, atomic key rotation, revocation with PoP, introspection, token exchange, and PAR — all defined with consistent key binding semantics under a single profile.

5. **Atomic key rotation during active sessions.** Non-disruptive cryptographic key rotation using nested EPOP envelopes, with a verifiable chain of custody from old key to new key.

None of these properties are provided by RFC 9901 SD-JWT+KB. Conversely, RFC 9901's selective disclosure and verifier unlinkability properties are not provided by EPOP. The specifications address distinct problems and represent additive contributions to the ecosystem.
