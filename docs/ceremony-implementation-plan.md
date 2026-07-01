# WebAuthnX — Ceremony Plan (the porcelain)

_Created 2026-07-01. Follows on from [`implementation-plan.md`](implementation-plan.md), whose
scope (the low-level "plumbing") is complete._

## 0. Context & goal

The plumbing is done: raw browser/authenticator JSON parses into fully-typed, validated value
objects, COSE keys convert to SPKI, and `Crypto\SignatureVerifier` verifies ES256/384/512,
RS256 and EdDSA signatures. What's missing is the **relying-party ceremony layer** — the
orchestration in WebAuthn §7.1 (registration) and §7.2 (authentication) that turns a parsed
`PublicKeyCredential` into a trustworthy "this user registered / authenticated" decision, plus
the **attestation-statement verification** in §8.

This document plans that layer. It is deliberately opinionated about phasing so the
highest-value, lowest-risk piece (making passkey login actually work for the common
`attestation: "none"` case) ships first, and the hard, low-usage pieces (TPM, MDS) come last.

## 1. What already exists (the seams we build on)

| Need | Provided by |
|---|---|
| Parse registration/authentication JSON | `PublicKeyCredential::fromRegistrationResponseJson()` / `fromAuthenticationResponseJson()` (generic over response type) |
| Client data (`type`, `challenge`, `origin`, `topOrigin`, `crossOrigin`) | `AuthenticatorResponse::parseClientData()` → `CollectedClientData` |
| Attestation object (`fmt`, `authData`, `attStmt`) | `AuthenticatorAttestationResponse::parseAttestationObject()` → `AttestationObject` |
| Authenticator data (rpIdHash, flags, signCount, ext) + flag accessors | `AttestationObject::parseAuthenticatorData()` / `AuthenticatorData` |
| Credential id + AAGUID + COSE public key | `AuthenticatorData->attestedCredentialData` → `AttestedCredentialData` |
| Assertion fields (`authenticatorData`, `signature`, `userHandle`) | `AuthenticatorAssertionResponse` |
| Signature verification | `Crypto\SignatureVerifier::verify(CoseKey, message, signature)` |
| Hashing | `Crypto\Hash::sha256(Bytes)` |
| base64url, CBOR decode, DER **encode**, JSON access | `Base64`, `Cbor`, `Der\DerEncoder`, `Json` |

**Not yet available (prerequisites for parts of this plan):**

- **DER/ASN.1 _decoder_.** We only encode DER (for SPKI). Every x5c-based attestation format
  needs to read X.509 certificate extensions by OID (FIDO AAGUID, Apple nonce, Android
  attestation record), which `openssl_x509_parse()` returns as raw DER for unknown OIDs → we
  need a minimal ASN.1 DER decoder. Not needed for `none` or `packed`-self.
- **X.509 helpers.** Thin wrappers over `openssl_x509_parse()` / `openssl_x509_verify()` /
  chain validation; certificate public key → we already have COSE→SPKI but need cert→pubkey.
- **Caller state abstractions.** The library must not own persistence; it needs narrow
  interfaces the RP implements (credential store, challenge/expectations per ceremony).

## 2. Scope

**In scope**

- A relying-party façade that performs the full §7.1 and §7.2 verification procedures.
- Caller-facing abstractions for the state the RP owns (expected challenge/origin/RP ID, and a
  credential record store) — as interfaces, with simple value implementations for tests.
- Rich, typed results and a fail-closed error model.
- **Committed near-term target: Phase P1** (the `none`-attestation ceremony core). Attestation-
  statement verification (Phases P2/P3) is planned here but **deferred until a concrete need**.

**Out of scope (may become follow-ups)**

- FIDO Metadata Service (MDS) blob download/parsing and automatic trust-anchor management
  (we expose the trust path + attestation type and a pluggable trust-anchor hook; acceptance
  policy stays with the caller).
- `tpm` attestation (very hard; TPM2 structure parsing) — deferred to the end, behind a flag.
- `android-safetynet` — **won't implement**: deprecated in Level 3 and being removed.
- ECDAA — removed from the spec.

## 3. Key design decisions

1. **Attestation scope & default policy — DECIDED (2026-07-01): P1 only for now.** Most passkey
   deployments run `attestation: "none"` and never verify a statement. The façade defaults to a
   "no attestation required" policy that accepts `none` (and `packed`-self) without trust
   evaluation. Statement verification for `packed`(x5c)/`fido-u2f`/`apple`/`android-key` (Phases
   P2/P3) is **deferred until a concrete need appears** — P1 ships a working login with no
   x5c/DER work at all.
2. **Error model — DECIDED (2026-07-01): fail-closed exceptions.** Verification failures throw a
   typed `Ceremony\VerificationException` carrying a machine-readable reason; success returns a
   rich result object. No boolean "false-means-maybe" surface. (`SignatureVerifier::verify()`
   keeps its bool contract internally; the façade translates a `false` into the exception.)
3. **State ownership — adopted.** Define `CredentialStore` (lookup by id; the record carries
   publicKey, signCount, uvInitialized, backupEligible/State, userHandle, transports) and pass
   per-ceremony *expectations* (challenge, origin(s), RP ID, UV requirement) into the verify
   call. The library never touches a database.
4. **Trust anchors — deferred with P2/P3.** When statement verification lands: verify cert
   chains cryptographically and return the attestation type + trust path; accept/reject of the
   root is a caller-supplied `TrustAnchorPolicy`. MDS is a later, separate module.
5. **signCount / clone detection — adopted.** Per §7.2 step 22 the counter check is a *signal*,
   not a hard fail. Return the observed vs. stored counts and a `possibleClone` flag in the
   result; let the caller decide, but update the stored count on success.

## 4. Phased plan

### Phase P1 — Ceremony core (no attestation trust) — the crux — ✅ DONE (2026-07-01)
Goal: a working `RelyingParty` that fully verifies §7.2 authentication and §7.1 registration for
the `attestation: "none"` case, end-to-end, with no X.509/DER work.

**Delivered:** `WebAuthnX\RelyingParty` façade (root namespace) + `WebAuthnX\Ceremony\`
(`RegistrationExpectations`, `AuthenticationExpectations`, `CredentialRecord`, `CredentialStore`,
`RegistrationResult`, `AuthenticationResult`, `VerificationException`). Full §7.1/§7.2 including
topOrigin (§7.1 s11 / §7.2 s14). Fail-closed: the façade throws only `VerificationException`
(machine-readable `reason`); decode failures and stored-key faults are repacked into it. Library
stays stateless (caller owns persistence, challenge single-use, and the signCount/`possibleClone`
decision). Reviewed by 3 fresh-eyes agents and hardened. During P1 the codebase also adopted
PHPStan **checked-exception** enforcement (see `implementation-plan.md` tooling notes).
Deferred within P1 scope, if a need arises: thread `authenticatorAttachment` into
`RegistrationResult`; enforce a 1–64-byte bound on stored `userHandle`.

- **P1.1 State & expectations API.** `Ceremony\RegistrationExpectations` /
  `AuthenticationExpectations` (challenge `Bytes`, expected origins, RP ID, UV requirement,
  allowed algorithms, cross-origin policy). `Ceremony\CredentialRecord` value object +
  `CredentialStore` interface.
- **P1.2 Registration verification (§7.1 steps 3–20, 25–26).** type=`webauthn.create`,
  constant-time challenge compare (`hash_equals`), origin allow-list, `rpIdHash ==
  SHA-256(rpId)`, UP (unless conditional), UV if required, BE/BS invariant (`!BE ⇒ !BS`),
  `alg ∈ pubKeyCredParams`, credentialId ≤ 1023 bytes, credentialId not already registered.
  Returns a `RegistrationResult` (credentialId, COSE public key, signCount, BE/BS, aaguid,
  transports, attestationType=`None`). Attestation format dispatch is present but only `none`
  is wired (P2 adds the rest).
- **P1.3 Authentication verification (§7.2 steps 5–24).** allowCredentials membership;
  credential lookup + userHandle branching (pre-identified vs. usernameless); challenge/origin/
  rpIdHash/UP/UV/BE-BS checks; reconstruct `authData ‖ SHA-256(clientDataJSON)` and
  `SignatureVerifier::verify`; signCount comparison (skip when both 0; strictly-greater rule;
  `possibleClone` signal); return `AuthenticationResult` (userHandle, new signCount, BS, uv).
- **P1.4 Tests.** Reuse the `CeremonyEndToEndTest` fixtures (all 5 algs) but now drive the real
  façade; add negatives for every check (wrong challenge/origin/rpId, cleared UP/UV, BE/BS
  violation, unknown credential, signCount regression, tampered signature).

### Phase P2 — `packed` + self attestation, and the X.509 substrate
Goal: verify the most common real attestation statements; build the DER-decode/X.509 substrate.

- **P2.1 ASN.1 DER decoder** (mirror of `Der\DerEncoder`): SEQUENCE/SET/INTEGER/OID/OCTET
  STRING/BIT STRING/etc., enough to read cert extension values. _(spec: X.690 / RFC 5280)_
- **P2.2 X.509 helpers** over `ext-openssl` (`openssl_x509_parse`, `_verify`, chain build) +
  certificate-public-key extraction and extension-by-OID access (via P2.1).
- **P2.3 `packed` verifier** (§8.2): self (no x5c — verify `sig` with the credential public key,
  `alg` match) and Basic/AttCA (x5c — verify `sig` over `authData ‖ hash` with the leaf cert,
  check the AAGUID extension OID `1.3.6.1.4.1.45724.1.1.4`, validate the chain).
- **P2.4 Attestation result plumbing:** `AttestationType` (None/Self/Basic/AttCA/AnonCA), trust
  path, and the `TrustAnchorPolicy` hook. Wire into P1's registration dispatch.
- **P2.5 Tests:** real `packed` registration blobs (self + x5c) as fixtures; negative cert/sig.

### Phase P3 — Remaining formats + trust anchors (opt-in, lower usage)
- **P3.1 `fido-u2f`** (§8.6): rebuild `0x00 ‖ rpIdHash ‖ clientDataHash ‖ credentialId ‖
  (0x04‖x‖y)`, verify with the P-256 leaf cert. Reuses P2 substrate + the EC point we already
  hold on `CoseEc2Key`.
- **P3.2 `apple`** (§8.8): nonce = SHA-256(`authData ‖ hash`); compare to the cert extension
  OID `1.2.840.113635.100.8.2`; match cert public key to the credential key.
- **P3.3 `android-key`** (§8.4): attestation-challenge extension == clientDataHash; AuthorizationList
  checks (OID `1.3.6.1.4.1.11129.2.1.17`) — heavier ASN.1.
- **P3.4 Pluggable trust-anchor store** + (optional, separate module) **FIDO MDS** integration.
- **P3.5 `tpm`** (§8.3) — **last, behind a flag**: TPM2 `TPMT_PUBLIC`/`TPMS_ATTEST`/`TPMT_SIGNATURE`
  parsing. Only if a concrete need appears.

### Cross-cutting
- **Security hardening:** constant-time challenge compare; strict origin matching (scheme+host+
  port, no substring); decide ECDSA **low-S** enforcement (currently not enforced — matters for
  assertion malleability/replay, i.e. exactly this layer); confirm EC on-curve reliance on OpenSSL.
- **Fresh-eyes multi-agent review** at the end of P1 and P2 (as done for Phases A–C).
- **Fixtures:** collect real registration/assertion blobs per format (Windows Hello RSA, a
  security-key `packed` x5c, an Apple platform credential) as regression vectors.

## 5. Suggested order & sizing

P1 is the high-value core and needs **no** new crypto/DER — it's mostly careful spec-following
and state wiring; ship it first and the library becomes usable for passkeys. P2 unlocks
attestation trust for the common `packed` case and builds the X.509 substrate the rest reuse.
P3 is a long tail of individually-small formats (except TPM) gated on real demand.

## 6. Spec references (already in `spec/`)

`webauthn-3.html` §7.1 (registration), §7.2 (authentication), §8.2–8.8 (attestation formats);
`ctap-2.1.html` (attestation/AAGUID); `rfc5280-x509.txt` (certs); `rfc8017`/`rfc5480` (key DER).
For §8.3 TPM: TPMv2 Part 2 structures (not in `spec/`; fetch if/when P3.5 is scheduled).
