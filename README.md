# WebAuthnX

A from-scratch, spec-compliant [WebAuthn](https://w3c.github.io/webauthn/) **passkey** library
for PHP with **no third-party runtime dependencies** — only PHP itself and the bundled
`ext-openssl`.

The intended entry point is the high-level **`WebAuthnX\Passkey\PasskeyFlow`**: construct it with
your relying party identity and two small storage interfaces, wire its four methods to four HTTP
endpoints, and you have passkey registration and login — usernameless, two-step by email, and
conditional-mediation (autofill), all at once. Everything beneath it (the `RelyingParty` ceremony
engine, response parsing, COSE/CBOR primitives) is public but considered
[low-level API](#low-level-api).

## Requirements

- PHP **8.4+** (Ed25519/Ed448 support in `ext-openssl` requires OpenSSL 3.0 / PHP 8.4)
- `ext-openssl`

## Installation

```sh
composer require jantvrdik/webauthn
```

## Usage

Binary values (challenges, credential IDs, user handles) are plain PHP strings holding **raw
bytes** everywhere in the API — the library base64url-encodes/decodes them at the JSON boundary
for you.

### Set up the flow

```php
use WebAuthnX\Passkey\PasskeyFlow;

$flow = new PasskeyFlow(
    rpId: 'example.com',                  // the domain your passkeys are scoped to
    rpName: 'Example Corp',               // shown by authenticator UIs
    origins: ['https://example.com'],     // exact origins your login pages are served from
    store: $passkeyStore,                 // your PasskeyStore implementation (durable)
    pendingCeremonyStore: $pendingStore,  // your PendingCeremonyStore implementation (session-scoped)
);
```

You implement two interfaces (see [Storage](#storage) below), then expose four endpoints:

### Registration

Registration enrols a passkey for an account **you** have already resolved and authorized —
a signed-in user adding a passkey, or a just-created signup. Deciding *who* may enrol (verifying
the email, requiring an authenticated session) is deliberately left in front of the flow, and the
authorization must still hold when the ceremony *completes*, not just when the options were issued.

```php
use WebAuthnX\Ceremony\VerificationException;

// POST /register/options
$options = $flow->registrationOptions($userHandle, $email);
echo $options->toJson();   // hand to navigator.credentials.create() on the client

// POST /register/verify — body is the PublicKeyCredential.toJSON() output posted by your page
try {
    $registered = $flow->register($rawRequestBody);
    // The passkey is verified and persisted. $registered->userHandle identifies the account —
    // e.g. sign the user in after a passkey-first signup.
} catch (VerificationException $e) {
    // $e->reason is a stable machine-readable code, $e->getMessage() explains it
}
```

The user handle is an opaque, immutable, PII-free account id of at most 64 bytes (the
spec-recommended choice is 64 random bytes stored on the account) — never the email itself. The
options automatically list the account's existing credentials in `excludeCredentials` so the same
authenticator cannot enrol twice, and request a discoverable credential with user verification —
the defaults that make the credential a passkey.

### Authentication

One pair of endpoints covers all three ways passkey login is offered — usually together, on the
same page:

- a dedicated **"sign in with a passkey" button** and **conditional-mediation autofill**: call
  `authenticationOptions(null)` — no username is known, a discoverable credential identifies the
  user via its user handle;
- a **two-step login form** (email first): pass the entered username. If the account is known, the
  ceremony is pinned to it — an assertion by any other user's credential is rejected. An unknown
  username silently falls back to the usernameless options, so the response does not by itself
  confirm whether an account exists.

```php
// POST /login/options
$options = $flow->authenticationOptions($emailOrNull);
echo $options->toJson();   // hand to navigator.credentials.get() on the client

// POST /login/verify
try {
    $result = $flow->authenticate($rawRequestBody);
    // Log the user in as $result->userHandle; the credential state is already persisted.
    if ($result->possibleClone) {
        // The signature counter did not increase — a clone signal, not proof. Apply your risk policy.
    }
} catch (VerificationException $e) {
    // malformed input, an expired/replayed challenge, a failed check — all end up here
}
```

Both `register()` and `authenticate()` are **fail-closed**: on *any* failed check — or a malformed
response — they throw a `VerificationException`; you either get a trustworthy result or an
exception, never a "maybe". Because several ceremonies can run concurrently in one browser session
(autofill starts at page load, a button click starts another), pending ceremonies are keyed by
challenge and looked up from the response — you never juggle "the" pending ceremony yourself.

### Storage

The flow owns no state; you implement two small interfaces:

- **`WebAuthnX\Passkey\PasskeyStore`** — the durable side: your user and credential tables.
  Four methods: `findUserHandleByUsername()`, `findCredentialsByUserHandle()`,
  `findCredentialByCredentialId()`, plus the two writes `saveCredential()` and
  `updateCredential()`. Typically a thin repository over the same database that holds your users.
- **`WebAuthnX\Passkey\PendingCeremonyStore`** — the transient side: ceremonies started but not
  yet finished, keyed by challenge. Implement it on something browser-session-scoped (the PHP
  session, a short-TTL cache), never on durable storage. Its consume-on-read semantics make each
  challenge single-use — the anti-replay control the library relies on.

### Policy knobs

The defaults are right for passkeys: user verification `required`, discoverable credentials
`required`, ES256/RS256/EdDSA, the spec-recommended 300 s timeout, cross-origin iframes rejected.
To change any of them, subclass `PasskeyFlow` and override the corresponding protected method
(`getUserVerificationRequirement()`, `getAllowedAlgorithms()`, `getResidentKeyRequirement()`,
`getTimeout()`, `isCrossOriginAllowed()`, `getAllowedTopOrigins()`, `generateChallenge()`).

## Example

A runnable, single-file relying party lives in [`example/`](example/) — multiple accounts, each
with several passkeys, all four endpoints driven through `PasskeyFlow` with a SQLite-backed
`PasskeyStore` and a `$_SESSION`-backed `PendingCeremonyStore`:

```sh
php -S localhost:8000 example/server.php   # then open http://localhost:8000
```

See [`example/README.md`](example/README.md).

## Attestation is intentionally not supported

This library targets passkeys as a general-purpose authentication mechanism, and for that use case
`attestation: "none"` — the WebAuthn default — is the right choice. Attestation — cryptographically proving
*which authenticator model* produced a credential — is an enterprise feature for relying parties
that must restrict enrolment to approved hardware. It adds no security to authenticating the
general public, and supporting it properly drags in certificate-chain validation, per-vendor
formats, trust-anchor management, and FIDO Metadata Service integration.

Concretely, the library accepts the `none` format and verifies `packed` **self** attestation
(which clients pass through even under `attestation: "none"`). Certificate-based attestation
statements (`packed` with `x5c`, `tpm`, `android-key`, `fido-u2f`, `apple`, …) are **rejected**,
fail-closed — never silently ignored.

Attestation support may be added eventually, but not anytime soon, and definitely not for v1.0 —
possibly never. If your deployment must verify authenticator provenance, this library is not the
right fit today.

## Low-level API

Everything below `PasskeyFlow` is public and usable on its own when the flow's shape doesn't fit —
but it puts challenge storage, single-use enforcement, and result persistence in your hands.

**`WebAuthnX\RelyingParty`** runs the full WebAuthn §7.1 (registration) and §7.2 (authentication)
verification procedures against per-ceremony expectations, reading credentials through a
`CredentialStore` you implement:

```php
use WebAuthnX\Ceremony\RegistrationExpectations;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Credential\PublicKeyCredential;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\RelyingParty;

$credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString($rawJson));

$result = (new RelyingParty())->verifyRegistration(
    $credential,
    new RegistrationExpectations(
        challenge: $challengeYouIssued,   // raw bytes you generated and stored for this ceremony
        rpId: 'example.com',
        origins: ['https://example.com'],
        allowedAlgorithms: [CoseAlgorithmIdentifier::ES256, CoseAlgorithmIdentifier::RS256],
        requireUserVerification: true,
    ),
    $store,   // your WebAuthnX\Ceremony\CredentialStore
);

$store->save($result->toCredentialRecord($userHandle));   // your own persistence
```

`verifyAuthentication()` is the mirror image with `AuthenticationExpectations` and returns an
`AuthenticationResult`. At this level *you* generate the challenge, store it, and invalidate it
after one ceremony — single-use challenges are the anti-replay control.

Below that sit the building blocks: the options models with `toJson()`
(`PublicKeyCredentialCreationOptions` / `PublicKeyCredentialRequestOptions`), full response
parsing (`PublicKeyCredential`, `AttestationObject`, `AuthenticatorData`, `CollectedClientData`),
COSE key parsing and signature verification (`CoseKey::verify()`), and the primitives (CBOR
decoding, DER encoding, canonical base64url, a strict JSON accessor).

### Supported signature algorithms

Signatures are verified through `ext-openssl` with the COSE algorithm identifiers below:

| COSE alg | Constant | Algorithm |
|---:|---|---|
| `-7`   | `CoseAlgorithmIdentifier::ES256` | ECDSA w/ SHA-256 (P-256) |
| `-35`  | `CoseAlgorithmIdentifier::ES384` | ECDSA w/ SHA-384 (P-384) |
| `-36`  | `CoseAlgorithmIdentifier::ES512` | ECDSA w/ SHA-512 (P-521) |
| `-257` | `CoseAlgorithmIdentifier::RS256` | RSASSA-PKCS1-v1_5 w/ SHA-256 |
| `-8`   | `CoseAlgorithmIdentifier::EdDSA` | EdDSA (Ed25519 or Ed448) |
| `-19`  | `CoseAlgorithmIdentifier::Ed25519` | EdDSA w/ Ed25519, fully specified (RFC 9864) |
| `-53`  | `CoseAlgorithmIdentifier::Ed448` | EdDSA w/ Ed448, fully specified (RFC 9864) |

## Development

```sh
composer check          # all the checks below
composer check:cs       # Code Sniffer
composer fix:cs         # Code Sniffer auto-fix
composer check:tests    # PHPUnit
composer check:types    # PHPStan (level max)
composer check:coverage # PHPUnit with coverage + coverage-guard (needs Xdebug or PCOV)
```

CI runs the test suite with coverage enforcement (`shipmonk/coverage-guard`), PHPStan at level
`max`, and `composer audit` on every push and pull request.

## License

MIT
