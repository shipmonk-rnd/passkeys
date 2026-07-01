# WebAuthnX

A from-scratch, spec-compliant [WebAuthn](https://w3c.github.io/webauthn/) (passkeys) library
for PHP with **no third-party runtime dependencies** — only PHP itself and the bundled
`ext-openssl`.

> **Status: the low-level plumbing is complete; the ceremony façade is not built yet.**
> This library parses and validates every WebAuthn/COSE/CBOR structure a browser and
> authenticator produce, serializes the options a browser consumes, and verifies assertion
> signatures. It does **not yet** provide a one-call `verifyRegistration()` /
> `verifyAuthentication()` façade — the relying-party checks in WebAuthn §7.1/§7.2 (challenge,
> origin, RP ID hash, flags, sign-count) and attestation-statement verification are the planned
> next layer. See [Scope](#scope) and [`docs/implementation-plan.md`](docs/implementation-plan.md).

## Requirements

- PHP **8.4+** (Ed25519 support in `ext-openssl` requires OpenSSL 3.0 / PHP 8.4)
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
| `-8`   | `CoseAlgorithmIdentifier::EdDSA` | EdDSA (Ed25519) |

## Usage

Everything lives under the `WebAuthnX\` namespace. Binary values (challenges, credential IDs,
user handles) are modelled as `WebAuthnX\Binary\Bytes` and are base64url-encoded/decoded at the
JSON boundary for you.

### 1. Create registration options

```php
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Enum\PublicKeyCredentialType;
use WebAuthnX\Options\PublicKeyCredentialCreationOptions;
use WebAuthnX\Options\PublicKeyCredentialParameters;
use WebAuthnX\Options\PublicKeyCredentialRpEntity;
use WebAuthnX\Options\PublicKeyCredentialUserEntity;

$options = new PublicKeyCredentialCreationOptions(
    rp: new PublicKeyCredentialRpEntity(name: 'Example RP', id: 'example.com'),
    user: new PublicKeyCredentialUserEntity(Bytes::fromBinaryString($userId), 'alice', 'Alice Smith'),
    challenge: Bytes::fromBinaryString(random_bytes(32)),
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

### 2. Parse the browser's response

```php
use WebAuthnX\Credential\PublicKeyCredential;
use WebAuthnX\Json\JsonObject;

// Registration (navigator.credentials.create):
$credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString($rawJson));

$response = $credential->response;                       // AuthenticatorAttestationResponse
$authData = $response->parseAttestationObject()->parseAuthenticatorData();
$publicKey = $authData->attestedCredentialData?->credentialPublicKey; // a CoseKey — store it
$transports = $response->transports;                     // persist to seed allowCredentials later
```

Because the relying party always knows which ceremony it started, `PublicKeyCredential` is
generic over its response type: `fromRegistrationResponseJson()` returns a credential whose
`->response` is an `AuthenticatorAttestationResponse`, and `fromAuthenticationResponseJson()`
one whose `->response` is an `AuthenticatorAssertionResponse` — no `instanceof` needed.

### 3. Verify an assertion signature

For login, reconstruct the signed message (`authenticatorData ‖ SHA-256(clientDataJSON)`,
WebAuthn §7.2 step 19) and verify it against the `CoseKey` you stored at registration:

```php
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Credential\PublicKeyCredential;
use WebAuthnX\Crypto\Hash;
use WebAuthnX\Crypto\SignatureVerifier;
use WebAuthnX\Json\JsonObject;

$credential = PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString($rawJson));
$response = $credential->response;                       // AuthenticatorAssertionResponse

$message = Bytes::fromBinaryString(
    $response->authenticatorData->toBinaryString()
    . Hash::sha256($response->clientDataJSON)->toBinaryString(),
);

$isValid = (new SignatureVerifier())->verify($storedPublicKey, $message, $response->signature);
```

`SignatureVerifier::verify()` returns `false` for any signature that does not match (including
malformed attacker input) and throws only for an unsupported algorithm or an unloadable key.

> **You still owe the relying-party checks.** This library gives you the parsed, typed data and
> the signature primitive. Verifying the challenge, `origin`, RP ID hash, the UP/UV flags and the
> signature counter — and, for registration, the attestation statement — is your responsibility
> until the ceremony façade lands. Do not treat a `true` from `verify()` as a complete login.

## Scope

**Implemented (the plumbing):**

- Binary reader, CBOR decoding, DER (SubjectPublicKeyInfo) encoding, canonical base64url, JSON access
- COSE key parsing (`EC2`, `RSA`, `OKP`) with validation, and COSE → SPKI conversion
- `SignatureVerifier` (ES256/384/512, RS256, EdDSA) over `ext-openssl`
- Full response parsing: `PublicKeyCredential`, attestation/assertion responses, `AttestationObject`,
  `AuthenticatorData` (with flag accessors) + attested credential data, `CollectedClientData`
- Options models with JSON serialization for both ceremonies

**Not implemented yet (the porcelain), planned as the next layer:**

- A `verifyRegistration()` / `verifyAuthentication()` relying-party façade (WebAuthn §7.1 / §7.2)
- Attestation-statement format verification (`packed`, `tpm`, `android-key`, `fido-u2f`, `apple`, …)
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
