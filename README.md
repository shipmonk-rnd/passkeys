# WebAuthnX

A from-scratch, spec-compliant [WebAuthn](https://w3c.github.io/webauthn/) (passkeys) library
for PHP with **no third-party runtime dependencies** — only PHP itself and the bundled
`ext-openssl`.

> **Status: usable for passwordless/passkey login with `attestation: "none"`.**
> This library serializes the options a browser consumes, parses and validates every
> WebAuthn/COSE/CBOR structure a browser and authenticator produce, and provides a
> `RelyingParty` façade that runs the full WebAuthn §7.1 (registration) and §7.2
> (authentication) verification procedures. It accepts the `none` format and verifies `packed`
> *self* attestation (which clients pass through even under `attestation: "none"`). What it does
> **not** do yet is verify certificate-based attestation statements (`packed` with `x5c`, `tpm`,
> `android-key`, `fido-u2f`, `apple`) — those are rejected — so it cannot yet prove *which*
> authenticator model produced a credential. See [Scope](#scope) and
> [`docs/ceremony-implementation-plan.md`](docs/ceremony-implementation-plan.md).

## Requirements

- PHP **8.4+** (Ed25519/Ed448 support in `ext-openssl` requires OpenSSL 3.0 / PHP 8.4)
- `ext-openssl`

## Installation

```sh
composer require jantvrdik/webauthn
```

## Supported signature algorithms

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

## Usage

Everything lives under the `WebAuthnX\` namespace. Binary values (challenges, credential IDs,
user handles) are plain PHP strings holding **raw bytes** — the library base64url-encodes/decodes
them at the JSON boundary for you, so you never pass base64url-encoded values to the API.

### 1. Create registration options

```php
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Enum\PublicKeyCredentialType;
use WebAuthnX\Options\PublicKeyCredentialCreationOptions;
use WebAuthnX\Options\PublicKeyCredentialParameters;
use WebAuthnX\Options\PublicKeyCredentialRpEntity;
use WebAuthnX\Options\PublicKeyCredentialUserEntity;

$options = new PublicKeyCredentialCreationOptions(
    rp: new PublicKeyCredentialRpEntity(name: 'Example RP', id: 'example.com'),
    user: new PublicKeyCredentialUserEntity($userId, 'alice', 'Alice Smith'),
    challenge: random_bytes(32),
    pubKeyCredParams: [
        new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
        new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::RS256),
    ],
);

// Ready to hand to navigator.credentials.create() on the client:
$json = $options->toJson();
```

`PublicKeyCredentialRequestOptions` is the equivalent for the authentication (login) ceremony
and serializes the same way via `toJson()`.

Both options default `timeout` to the spec-recommended 300 000 ms ([§15.1](https://w3c.github.io/webauthn/#sctn-timeout-recommended-range));
pass an explicit value (the recommended range is 300 000–600 000 ms) or `null` to omit it. Client
extension inputs (e.g. `prf`, `credProps`) can be passed through verbatim in their JSON form via
the `extensions` member.

### 2. Verify a registration

Parse the browser's response, then hand it to the `RelyingParty` façade with your per-ceremony
expectations. The library owns no state — it reads credentials through a `CredentialStore` you
implement, and returns the record for you to persist.

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
        challenge: $challengeYouIssued,          // the raw bytes you generated for this ceremony
        rpId: 'example.com',
        origins: ['https://example.com'],
        allowedAlgorithms: [CoseAlgorithmIdentifier::ES256, CoseAlgorithmIdentifier::RS256],
        requireUserVerification: true,
    ),
    $store,                                       // your WebAuthnX\Ceremony\CredentialStore
);

// Persist the record against the user you just registered (user.id becomes the user handle):
$store->save($result->toCredentialRecord($userHandle));   // your own persistence
```

### 3. Verify an authentication

```php
use WebAuthnX\Ceremony\AuthenticationExpectations;
use WebAuthnX\Credential\PublicKeyCredential;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\RelyingParty;

$credential = PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString($rawJson));

$result = (new RelyingParty())->verifyAuthentication(
    $credential,
    new AuthenticationExpectations(
        challenge: $challengeYouIssued,
        rpId: 'example.com',
        origins: ['https://example.com'],
        allowedCredentialIds: $idsFromAllowCredentials,  // or null for a usernameless flow
        requireUserVerification: true,
        expectedUserHandle: $userHandle,                 // set if you identified the user first
    ),
    $store,
);

// Log the user in as $result->userHandle, then persist the new state:
$store->updateSignCount($result->credentialId, $result->newSignCount);   // your own persistence

if ($result->possibleClone) {
    // The signature counter did not increase — a clone signal, not proof. Apply your risk policy.
}
```

Both methods are **fail-closed**: on *any* failed check — or a malformed response — they throw a
`WebAuthnX\Ceremony\VerificationException` carrying a stable, machine-readable `->reason`; you
either get a trustworthy result or an exception, never a "maybe". You still generate and store the
challenge yourself and invalidate it after one ceremony — single-use challenges are the anti-replay
control the library relies on.

The lower-level building blocks used above remain public for advanced use: `PublicKeyCredential`
(generic over its response type), `parseAttestationObject()` / `parseAuthenticatorData()`, and the
`SignatureVerifier` primitive.

## Example

A runnable, single-file relying party lives in [`example/`](example/) — create a passkey and log in
with it end to end:

```sh
php -S localhost:8000 example/server.php   # then open http://localhost:8000
```

It shows both ceremonies driven through `RelyingParty`, plus a file-backed `CredentialStore`. See
[`example/README.md`](example/README.md).

## Scope

**Implemented:**

- A `RelyingParty` façade performing the full WebAuthn §7.1 (registration) and §7.2
  (authentication) verification procedures for the `attestation: "none"` case, including
  `packed` self-attestation verification (§8.2 without `x5c`)
- Caller-owned state abstractions (`CredentialStore`, per-ceremony `*Expectations`) and rich,
  typed results (`RegistrationResult` / `AuthenticationResult`) with a fail-closed error model
- Full response parsing: `PublicKeyCredential`, attestation/assertion responses, `AttestationObject`,
  `AuthenticatorData` (with flag accessors) + attested credential data, `CollectedClientData`
- Options models with JSON serialization for both ceremonies
- COSE key parsing (`EC2`, `RSA`, `OKP`) with validation, COSE → SPKI conversion, and a
  `SignatureVerifier` (ES256/384/512, RS256, EdDSA) over `ext-openssl`
- Primitives: binary reader, CBOR decoding, DER (SubjectPublicKeyInfo) encoding, canonical
  base64url, JSON access

**Not implemented yet, planned as the next layer:**

- Certificate-based attestation-statement verification (`packed` with `x5c`, `tpm`, `android-key`,
  `fido-u2f`, `apple`, …) and trust-anchor evaluation
- FIDO Metadata Service integration

## Development

```sh
composer test        # PHPUnit
composer phpstan     # PHPStan (level max)
composer coverage    # PHPUnit with coverage + coverage-guard (needs Xdebug or PCOV)
```

CI runs the test suite with coverage enforcement (`shipmonk/coverage-guard`), PHPStan at level
`max`, and `composer audit` on every push and pull request.

## License

MIT
