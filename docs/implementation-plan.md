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

### Phase A — Fix correctness bugs in existing plumbing — ✅ done 2026-07-01
Goal: everything that exists compiles, is type-clean at PHPStan max, and behaves per spec.

Outcome: PHPStan level max is clean; test suite green (2136 tests, no risky); line
coverage 48% → 74%. `Base64` decoding now validates strictly; the response classes are
concrete and the `authenticatorData` copy-paste bug is fixed; `CborMap` has the optional
accessors; COSE keys parse into a real `CoseEc2Key`/`CoseRsaKey` hierarchy and are wired
into `AttestedCredentialData` (now exercised end-to-end by `AuthenticatorDataTest`).
Decision: `BytesReader` now assumes 64-bit PHP (manual byte arithmetic replaced the
`mixed`-typed `unpack()` path; the incomplete 32-bit guards were removed).

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

### Phase B — COSE keys, DER wiring, and signature verification (the crux) — ✅ done 2026-07-01
Goal: given a COSE key and signed bytes, verify a signature with `ext-openssl`.

Outcome: PHPStan level max stays clean; suite green (2179 tests); line coverage 74% → 87%,
with the whole `Der`/`Cose`/`Crypto` layer at 100%. COSE keys now validate `alg`/`crv`/
coordinate lengths on parse and expose `toDerSubjectPublicKeyInfo()`; the previously
orphaned `DerEncoder` is now used to build SubjectPublicKeyInfo, and its
`encodeObjectIdentifier()` was reworked to encode a dotted-decimal OID string.
`Crypto\SignatureVerifier` verifies **ES256/384/512, RS256, and EdDSA (Ed25519)** via
`openssl_verify`, proven against OpenSSL-generated key material (our SPKI DER is asserted
byte-for-byte identical to OpenSSL's, including the Ed25519 `OKP` SPKI) and by a full
end-to-end ES256 assertion-signature check. `ext-openssl` added to composer `require`.
Decisions: (a) OID constants live on the COSE key classes that use them rather than a
generic `Der` OID bag; (b) EdDSA is done through OpenSSL rather than `ext-sodium` — this
required **raising the minimum PHP to 8.4** (OpenSSL Ed25519 support landed there), which
avoids a second crypto dependency (`ext-sodium` has no ECDSA/RSA anyway, so it could never
replace OpenSSL); the verifier maps `EdDSA → openssl_verify(..., 0)` (pure scheme, no
prehash); (c) `Crypto\Hash::sha256()` (task 9) is implemented and exercised by the assertion
test but has no `src/` caller until the ceremony layer (porcelain) needs it.

**Post-review hardening (2026-07-01).** Four fresh-eyes review agents (spec / security /
correctness / tests) audited Phase B. Fixes applied:
- **[was HIGH] RSA degenerate-key forgery.** `CoseRsaKey` accepted `e=1` (→ verification is
  the identity function, forgeable without the private key) and tiny moduli. Now requires the
  public exponent to be an odd integer > 1 and the modulus ≥ 2048 bits (RFC 8230 §6.1).
- **[MEDIUM] Malformed-signature contract.** `SignatureVerifier::verify` now returns `false`
  for a malformed/garbage signature (OpenSSL `-1`) instead of throwing, so attacker-supplied
  input yields a clean verification failure, not an exception. It still throws only for an
  unsupported algorithm or a key that fails to load.
- **[LOW] Stale OpenSSL error queue** is drained before use so load-failure messages are
  accurate. **[docs]** `CborDecoder`'s docblock no longer overclaims canonical-CBOR enforcement.
- **[tests]** Added an RFC 8032 §7.1 Ed25519 known-answer vector (fixed pubkey/sig, verify
  ±) — the first deterministic, non-self-generated crypto vector — plus a fixed Ed25519 SPKI
  vector and the missing negative operands (EC `y` length, RSA `e` = 1/even/empty, small modulus).

**Deferred (noted, not blocking the plumbing):** EC point-on-curve validity relies on OpenSSL
(it rejects off-curve points on load — acceptable); ECDSA low-S malleability is not enforced
(matters only for replay/sign-count → ceremony); a type-confused COSE field surfaces as
`CborMapException` rather than `CoseKeyException` (decide whether to normalize); more KAT
vectors for EC/RSA and a negative case in the assertion test would raise assurance further;
full CTAP2-canonical CBOR (key ordering, minimal encodings) is intentionally not enforced.

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

### Phase C — Complete the WebAuthn parsing layer — ✅ done 2026-07-01
Goal: turn raw browser JSON into fully-typed, validated value objects.

Outcome: PHPStan level max stays clean; suite green (2198 tests); every new Phase C class
is at 100% line coverage (overall `src/` line coverage now 95.8%). Added the top-level
`PublicKeyCredential` parser and an `AuthenticatorResponse` base class shared by the two
concrete responses; added `AuthenticatorData` flag accessors; added the missing
`PublicKeyCredentialRequestOptions` plus `JsonSerializable`/`toJson()` for both options
models and their nested DTOs; deleted the dead `BytesWriter`. Decisions: (a) `PublicKeyCredential`
is a generic (`@template T of AuthenticatorResponse`) with two explicit factories —
`fromRegistrationResponseJson()` / `fromAuthenticationResponseJson()` — because the relying
party always knows which ceremony it started, so `->response` is statically typed without an
`instanceof`; (b) binary option members (`challenge`, `user.id`, descriptor `id`) are now
`Bytes` rather than raw `string`, matching the rest of the library and making the base64url
serialization boundary explicit; (c) following the existing convention (`AttestationObject`
doesn't validate `fmt`), the parser does **not** semantically validate the `type` string —
that's deferred to the ceremony layer; (d) the AT/ED flag-vs-section invariant is already
enforced structurally (sections are parsed iff the flag is set, and `BytesReader::read()`
rejects trailing bytes), so item 11 reduced to adding the accessors.

10. **Top-level `PublicKeyCredential`** parser (missing today): `{id, rawId, type,
    response, authenticatorAttachment?, clientExtensionResults?}` → attestation or
    assertion response. _(spec: WebAuthn §5.1)_ — ✅ done
11. **`AuthenticatorData`** — add flag accessors (`isUserPresent`, `isUserVerified`,
    `isBackupEligible`, `isBackupState`) and enforce the flag/section invariants
    (AT/ED bits vs presence of attested-credential-data/extensions). _(spec: §6.1)_ — ✅ done
    (also added `hasAttestedCredentialData`/`hasExtensionData`; the invariant is structural).
12. **`AttestedCredentialData`** — return a parsed `CoseKey` (not a raw `CborMap`). — ✅ done in Phase A/B.
13. **Options model** — add the missing `PublicKeyCredentialRequestOptions` (login side)
    and **JSON serialization** for both creation and request options (base64url for
    binary members), so the library can produce what the browser consumes without a
    third-party lib. _(spec: §5.4, §5.5, §5.1.3/§5.1.4)_ — ✅ done
14. **`BytesWriter`** — either finish it (add `toBytes()`/output) if needed by DER/CBOR
    encoding, or delete it as dead code. Decide based on whether we add a CBOR encoder. —
    ✅ deleted (dead code; no CBOR encoder is needed — options serialize as JSON, DER/SPKI
    builds plain strings, and signature verification does not re-encode CBOR).

**Post-review hardening (2026-07-01).** Four fresh-eyes review agents (spec / correctness /
security / tests) audited Phase C. No HIGH code defects; the generic typing was verified
*real* (statically narrows `->response` at PHPStan max). Fixes applied:
- **[MEDIUM security] Non-canonical base64url accepted.** `Base64::urlDecode` relied on
  `base64_decode(strict:true)`, which ignores non-zero unused trailing bits, so distinct
  strings (`"QQ"`/`"QR"`) decoded to the same bytes — a credential-id-confusion risk and a
  WebAuthn canonical-base64url violation. Now rejects input that does not round-trip to its
  own encoding.
- **[MEDIUM security] `</script>` breakout.** `toJson()` used `JSON_UNESCAPED_SLASHES`, which
  disables json_encode's default slash-escaping (`</script>` → `<\/script>`) that neutralises
  a script-context breakout via user-controlled `name`/`displayName`. Flag removed; locked by a test.
- **[MEDIUM spec] Dropped `transports`.** `AuthenticatorAttestationResponse` now parses the
  `transports` member (via new `JsonObject::getOptionalStringList`) — the one response datum
  not recoverable from the attestation object (RPs persist it to seed later `allowCredentials`).
- **[MEDIUM spec] Over-required `rp.id`.** `PublicKeyCredentialRpEntity::$id` is now optional
  (spec marks it non-`required`); when null it is omitted so the browser defaults it to the
  effective domain.
- **[tests]** Added the missing negatives/edges: assertion response without `userHandle`;
  missing/wrong-typed required members; `getObject` on an explicit-null value; the
  `AuthenticatorData` BE/BS true-paths and the no-AT / extensions-present parse branches; the
  new `getOptionalStringList` error branches. Every Phase C class + every file touched here is
  now at 100% line coverage (overall `src/` 97.1%, 2215 tests).

**Deliberately deferred (documented, non-blocking):** `type` value is not validated (consistent
with `AttestationObject` leaving `fmt` unchecked — a documenting test pins the behaviour);
outbound option invariants (`user.id` 1–64 bytes, non-empty `pubKeyCredParams`, min challenge
length) are RP-controlled and left to a later options-validation pass; a decoded-size DoS cap
(bounded by PHP limits already). Fixture/coverage: the remaining pre-existing untested
`JsonObject::fromString`/`getOptionalBoolean`, `CollectedClientData`, and two `BytesReader`
guard lines await Phase D spec vectors; option JSON does not yet model
`attestation`/`attestationFormats`/`extensions` inputs (add when the ceremony layer needs them).

### Phase D — Coverage, fixtures, and tooling completion — ✅ done 2026-07-01
Goal: near-100% coverage enforced in CI, backed by real spec vectors.

Outcome: PHPStan level max stays clean; suite green (2227 tests); `src/` line coverage is now
**99.80% (488/489)** — the single uncovered line is the unreachable defensive branch in
`BytesReader::unpackFloat` (its `unpack()` cannot fail because `readRaw()` always returns exactly
the requested byte count; the branch is kept for the type-checker). `composer audit --no-dev` is
clean (the library has zero third-party runtime deps; the dev-only PHPUnit advisory is still
tracked in §8). Decisions: (a) end-to-end vectors use **live** crypto driven through the public
API rather than frozen snapshots, because ECDSA output is non-deterministic — the fixed,
independent oracle remains the RFC 8032 Ed25519 KAT (item 15); (b) coverage-guard enforces
*method-level* coverage (two `EnforceCoverageForMethodsRule`s: "no method entirely untested" +
"≥5-line methods must be fully covered"), which is coverage-guard's idiomatic model and cleanly
tolerates the one defensive branch, while PHPUnit still reports the ~100% line figure; (c)
`composer audit` is scoped with `--no-dev` so CI audits what consumers actually install.

15. **Spec test vectors** — ✅ done. Added `CeremonyEndToEndTest`: for **every** supported
    algorithm (ES256/384/512, RS256, EdDSA) it assembles a spec-shaped `none`-attestation
    registration + assertion with real key material, feeds both through the public parsers
    (`PublicKeyCredential`, attestation object, authenticator data, attested credential data →
    `CoseKey`), reconstructs the §7.2 signed message, and verifies it (plus a tamper-negative).
    Introduced a `CborTestEncoder` test helper (production only decodes CBOR) and hoisted the
    signing helpers into `CryptoTestCase`. The real EC2 `none` blob in `AuthenticatorDataTest`
    and the RFC 8032 Ed25519 KAT remain as independent fixtures.
16. **Coverage-guard config** — ✅ done. `coverage-guard.php` with the two method rules above;
    passes on the current suite and actively bites (a stricter variant flagged `unpackFloat`).
17. **CI** — ✅ done. `.github/workflows/ci.yml`: the `tests` job runs PHPUnit with PCOV
    coverage → `clover.xml` → `coverage-guard check`, plus `composer validate --strict` and
    `composer audit --no-dev`; the `phpstan` job runs level max. Added a `composer coverage`
    script (`@putenv XDEBUG_MODE=coverage`); `clover.xml` is git-ignored.
18. **README** — ✅ done. Documents scope (plumbing vs the not-yet-built ceremony façade),
    requirements, supported algorithms, and the current public API (options → `toJson()`,
    `PublicKeyCredential` parsing, `SignatureVerifier` + the §7.2 message reconstruction), with
    an explicit warning that the RP-side checks are still the caller's responsibility.

**Coverage-closing tests added:** `CollectedClientDataTest` (all accessors), `Json\JsonObjectTest`
(`fromString` error paths + `getOptionalBoolean`), and a `BytesReader::bytes()` negative-length
case — closing every pre-existing reachable gap noted in Phase C.

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
