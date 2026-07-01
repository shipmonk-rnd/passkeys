# WebAuthnX — Implementation Plan (finish the plumbing)

_Last updated: 2026-07-01_

## 0. Context & goal

`WebAuthnX` (`src/`, namespace `WebAuthnX\`) is a from-scratch, spec-compliant WebAuthn
library for PHP with **zero/very few runtime dependencies**. The current code has a
solid, well-tested **low-level primitive layer** (binary I/O, CBOR decode, DER encode,
base64url, JSON) but the **WebAuthn layer on top is partial and in places broken**, and
there is **no signature verification and no ceremony logic** yet.

This document plans the work to **finish the plumbing** — i.e. all the low-level,
spec-defined building blocks and the data-parsing layer — so that the "porcelain" (the
registration/authentication ceremony API) can later be built cleanly on top. Ceremony
orchestration and attestation-statement format verification are explicitly **out of scope
here** (see §6), except for the primitives they depend on (COSE keys, signature
verification), which are in scope.

Reference specs are checked into `spec/` (see §7).

## 1. Baseline captured on 2026-07-01

- **Tests:** 2114 passing, 2222 assertions. 2 risky (empty stub) tests.
- **Coverage:** Lines 48% (132/274), Methods 22% (17/77), Classes 9% (2/22).
  - High: `CborDecoder`, `BytesReader`, `Bytes`, `DerEncoder` (~90–100%).
  - ~0%: the entire WebAuthn data layer (`AuthenticatorData`, `AttestationObject`,
    `Authenticator*Response`, `CollectedClientData`, `CoseKey`, options, entities).
- **PHPStan (level max):** ~45 findings; the load-bearing ones:
  - `Cose/CoseKey.php:34-37` — calls undefined `CborMap::getOptionalBytes()` → **COSE key parsing cannot run**.
  - `AttestationObject`, `Authenticator*Response`, `CoseKey` — `new static()` in an
    abstract/private-ctor context → **these classes cannot be instantiated**.
  - `Base64/Base64.php:23` — `=== false` is always false → **base64url decoding never
    validates its input** (dead error branch).
- **Tooling now in place:** PHPStan 2.2.3 (`phpstan.neon`, level max), `shipmonk/coverage-guard`
  1.0.2, `phpunit.xml` (was missing), composer.json reduced to zero runtime deps.

## 2. Scope of "plumbing"

**In scope**

| Layer | Package | Status today |
|---|---|---|
| Binary I/O | `Binary\` | Reader done; `BytesWriter` a stub (no output method) |
| CBOR decode | `Cbor\CborDecoder` | Done & tested |
| CBOR map accessors | `Cbor\CborMap` | Missing `getOptional*`, `getArray`, int-key COSE access |
| Base64url | `Base64\` | Decode does not validate (bug) |
| JSON access | `Json\JsonObject` | OK; needs `getInt`/`getArray`/`getObject` + serialization |
| DER encode | `Der\DerEncoder` | Done & tested but **orphaned** (nothing calls it) |
| COSE keys | `Cose\` | **Broken & orphaned**; no key-type modelling, no SPKI conversion |
| Signature verify | (new) | **Does not exist** — the crux |
| WebAuthn parsing | `AuthenticatorData`, `AttestationObject`, `Authenticator*Response`, `CollectedClientData`, `AttestedCredentialData`, top-level `PublicKeyCredential` | Partial / buggy / top-level parser missing |
| Options model + JSON serialization | `PublicKeyCredential*Options`, entities, enums | DTOs exist; no `RequestOptions`; no serialization to client |

**Out of scope (the "porcelain", planned separately)**

- Registration ceremony verification (WebAuthn §7.1) and authentication ceremony
  verification (§7.2) — challenge/origin/rpIdHash/flags checks, sign-count handling.
- Attestation statement format verification: `none`, `packed`, `tpm`, `android-key`,
  `android-safetynet`, `fido-u2f`, `apple`.
- FIDO Metadata Service integration.
- A public `RelyingParty`/server facade.

## 3. Phased plan

### Phase A — Fix correctness bugs in existing plumbing
Goal: everything that exists compiles, is type-clean at PHPStan max, and behaves per spec.

1. **`Base64::urlDecode`** — use strict decoding and actually reject invalid input;
   fix padding restoration (`strlen % 4` is wrong for the no-padding case). Add tests for
   invalid alphabet, wrong length, non-canonical padding. _(spec: RFC 4648 §5)_
2. **Response classes** (`AuthenticatorAttestationResponse`, `AuthenticatorAssertionResponse`)
   — remove `abstract`, keep `private __construct` + `self` named constructors (drop
   `new static`). Fix the copy-paste bug reading `attestationObject` into
   `authenticatorData` in the assertion response.
3. **`CborMap`** — add the missing typed accessors used across the codebase:
   `getOptionalBytes/String/Int/Bool`, `getArray`, `getOptionalMap`; ensure **integer**
   keys work (COSE uses negative int labels, not the string `'-1'`). Fill in
   `CborMapTest` (currently empty). _(spec: RFC 8949; CTAP2 canonical CBOR)_
4. **PHPStan cleanup** — resolve the `unpack()` `returns mixed`, iterable value-type, and
   test-provider typing findings at the source (no baseline, no ignores).
5. **De-risk stub tests** — give `AuthenticatorDataTest` real assertions; either implement
   or remove the empty `CborMapTest::testGetInt`. Keep `failOnRisky=true`.

### Phase B — COSE keys, DER wiring, and signature verification (the crux)
Goal: given a COSE key and signed bytes, verify a signature with `ext-openssl`.

6. **Rework `Cose\CoseKey`** into a proper hierarchy parsed from `CborMap`:
   - `CoseKey::fromCborMap()` dispatches on `kty` (1) → `CoseEc2Key` (kty=2),
     `CoseRsaKey` (kty=3), optionally `CoseOkpKey` (kty=1 / Ed25519).
   - EC2 labels: `crv`(-1), `x`(-2), `y`(-3). RSA labels: `n`(-1), `e`(-2). OKP: `crv`(-1), `x`(-2).
   - Validate `alg` against key type and against curve/coordinate lengths.
   _(spec: RFC 9052 §7, RFC 9053 §2, RFC 8230 §4; WebAuthn §5.8.5)_
7. **COSE → SubjectPublicKeyInfo (DER/PEM)** using the existing `DerEncoder` (finally used):
   - EC2: `ecPublicKey` OID + named-curve OID + uncompressed point (`0x04‖X‖Y`) BIT STRING.
   - RSA: `rsaEncryption` OID + `RSAPublicKey ::= SEQUENCE { n, e }` BIT STRING.
   Add `Der` OID constants. _(spec: RFC 5480 §2 for EC, RFC 8017 App. A/C for RSA)_
8. **`Crypto\SignatureVerifier`** (new, tiny): map COSE `alg` → OpenSSL algo + hash, load
   the SPKI PEM, `openssl_verify(...)`. Cover ES256/384/512 (DER ECDSA sig, verified as-is),
   RS256, and EdDSA (Ed25519) if we choose to support it. Add `ext-openssl` to composer
   `require`. _(spec: RFC 9053; WebAuthn §7.2 step 19)_
9. **Hashing helpers** — thin wrappers for `sha256(rpId)` and `sha256(clientDataJSON)`.

### Phase C — Complete the WebAuthn parsing layer
Goal: turn raw browser JSON into fully-typed, validated value objects.

10. **Top-level `PublicKeyCredential`** parser (missing today): `{id, rawId, type,
    response, authenticatorAttachment?, clientExtensionResults?}` → attestation or
    assertion response. _(spec: WebAuthn §5.1)_
11. **`AuthenticatorData`** — add flag accessors (`isUserPresent`, `isUserVerified`,
    `isBackupEligible`, `isBackupState`) and enforce the flag/section invariants
    (AT/ED bits vs presence of attested-credential-data/extensions). _(spec: §6.1)_
12. **`AttestedCredentialData`** — return a parsed `CoseKey` (not a raw `CborMap`).
13. **Options model** — add the missing `PublicKeyCredentialRequestOptions` (login side)
    and **JSON serialization** for both creation and request options (base64url for
    binary members), so the library can produce what the browser consumes without a
    third-party lib. _(spec: §5.4, §5.5, §5.1.3/§5.1.4)_
14. **`BytesWriter`** — either finish it (add `toBytes()`/output) if needed by DER/CBOR
    encoding, or delete it as dead code. Decide based on whether we add a CBOR encoder.

### Phase D — Coverage, fixtures, and tooling completion
Goal: near-100% coverage enforced in CI, backed by real spec vectors.

15. **Spec test vectors** — build fixtures from the WebAuthn/CTAP2 examples and known
    authenticator outputs (EC2 + RSA registration and assertion blobs) as snapshot inputs;
    the `assertSnapshot` harness already exists in `WebAuthnTestCase`.
16. **Coverage-guard config** — wire `shipmonk/coverage-guard` to require coverage of the
    core parsing/crypto methods; run it in CI against a clover report.
17. **CI** — GitHub Actions: `composer test` (with `XDEBUG_MODE=coverage`), `composer
    phpstan`, `composer audit`, coverage-guard. Target: PHPStan max clean, ~100% line
    coverage on `src/`.
18. **README** — document scope, supported algorithms, and the (eventual) public API.

## 4. Suggested order & rough sizing

Phase A (bug-fix + type-clean) → Phase B (COSE/DER/crypto) → Phase C (parsing/options) →
Phase D (coverage/CI). A and B are the highest-value: they unblock the first
**end-to-end ES256 registration + assertion signature check**, which validates the whole
architecture. RSA and EdDSA can follow the same seams.

## 5. Go-forward git strategy (recommendation, not yet executed)

- `wip/snapshot-2026-07-01` — immutable backup of the pre-work state. **Do not build on it.**
- Do real work on `master` (or a fresh `main`), committing the existing good code as a
  clean, reviewed first commit (not parented on the WIP commit), then proceed by phase.
- Decisions to confirm: (a) commit `spec/` into the repo or keep it local/git-ignored;
  (b) fate of the `public/` + `http/` demo — **drop** it or **rebuild** it on `WebAuthnX`;
  (c) final composer package name (currently placeholder `jantvrdik/webauthn`).

## 6. Out-of-scope follow-up (the porcelain)

After the plumbing is done: `RelyingParty::verifyRegistration()` / `verifyAuthentication()`
implementing WebAuthn §7.1 / §7.2, then attestation-statement format verifiers. These reuse
the Phase B COSE/crypto plumbing directly.

## 7. Downloaded reference specs (`spec/`)

| File | Spec |
|---|---|
| `webauthn-3.html` | W3C WebAuthn **Level 3**, CR Snapshot 26 May 2026 (primary) |
| `ctap-2.1.html` | FIDO CTAP 2.1 (CTAP2 canonical CBOR, attestation formats) |
| `rfc8949-cbor.txt` | CBOR |
| `rfc9052-cose-structures.txt` | COSE structures |
| `rfc9053-cose-algorithms.txt` | COSE algorithms |
| `rfc8230-cose-rsa.txt` | RSA keys/algorithms for COSE |
| `rfc8017-pkcs1.txt` | PKCS#1 (RSA key DER) |
| `rfc5480-ecc-spki.txt` | Elliptic-curve SubjectPublicKeyInfo |
| `rfc5280-x509.txt` | X.509 (attestation cert chains — later) |
| `rfc4648.txt` | base64 / base64url |

## 8. Open maintenance note

- `phpunit/phpunit` has a dev-only high-severity advisory **CVE-2026-24765** (unsafe
  deserialization in PHPT coverage handling), fixed in 10.5.62. Only 10.5.26 is currently
  resolvable in this environment; revisit when package metadata updates, or move to
  PHPUnit 12. Low practical risk (affects running untrusted PHPT files only).
