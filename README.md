# Passkeys for PHP

A from-scratch, spec-compliant [WebAuthn](https://w3c.github.io/webauthn/) **passkey** library for PHP.

- 🔑 **Easy-to-use:** wire four methods to four HTTP endpoints
- 🔧 **Full control:** the low-level WebAuthn API is public too
- 🕸️ **Zero dependencies:** only PHP and `ext-openssl`
- 🧪 **100 % code coverage:** enforced in CI
- 🔬 **PHPStan max level:** strict rules, zero ignores

The intended entry point is the high-level **`ShipMonk\Passkeys\PasskeyFlow`**: construct it with
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
composer require shipmonk/passkeys
```

## Usage

Binary values (challenges, credential IDs, user handles) are plain PHP strings holding **raw
bytes** everywhere in the API — the library base64url-encodes/decodes them at the JSON boundary
for you.

### Set up the flow

```php
use ShipMonk\Passkeys\PasskeyFlow;

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
use ShipMonk\Passkeys\Ceremony\VerificationException;

// POST /register/options
$options = $flow->registrationOptions($userHandle, $email);
echo $options->toJson();   // hand to navigator.credentials.create() on the client

// POST /register/verify — body is the PublicKeyCredential.toJSON() output posted by your page
try {
    // Passing the signed-in user's handle rejects a ceremony minted for any other account
    // before anything is persisted; omit it only when the account cannot be known yet
    // (e.g. a passkey-first signup).
    $registered = $flow->register($rawRequestBody, expectedUserHandle: $signedInUserHandle);
    // The passkey is verified and persisted. $registered->userHandle identifies the account —
    // e.g. sign the user in after a passkey-first signup.
} catch (VerificationException $e) {
    // $e->reason is a stable machine-readable code, $e->getMessage() explains it
}
```

The user handle is an opaque, immutable, PII-free account id of at most 64 bytes — never the email
itself. Mint one with `$flow->generateUserHandle()` (64 random bytes, the spec-recommended choice)
when you create the account, store it there, and reuse that same handle for every passkey the
account enrols — it is the account's WebAuthn identity, so a fresh one per ceremony would fork the
account. The options automatically list the account's existing credentials in `excludeCredentials`
so the same authenticator cannot enrol twice, and request a discoverable credential with user
verification — the defaults that make the credential a passkey.

#### Conditional mediation (automatic passkey upgrade)

Browsers can upgrade a password account to a passkey **silently**, right after a successful
password login. Request the options with `conditionalMediation: true` and hand them to
`navigator.credentials.create()` with `mediation: 'conditional'`:

```php
// POST /register/options — immediately after a password-based sign-in
$options = $flow->registrationOptions($userHandle, $email, conditionalMediation: true);
```

The browser decides on its own whether to create the passkey (typically only when the password was
just autofilled from its credential manager) and does so without any user interaction — the
response then carries neither the User Present nor the User Verified flag, and `register()`
relaxes both checks for that ceremony (and that ceremony only). The same verify endpoint finishes
it; `$registered->conditionalMediation` tells you the passkey was created this way, e.g. to notify
the user.

### Authentication

One pair of endpoints covers all three ways passkey login is offered — usually together, on the
same page:

- a dedicated **"sign in with a passkey" button** and **conditional-mediation autofill**: call
  `authenticationOptions(null)` — no username is known, a discoverable credential identifies the
  user via its user handle;
- a **two-step login form** (email first): pass the entered username. If the account is known, the
  ceremony is pinned to it — an assertion by any other user's credential is rejected. An unknown
  username always leaves the ceremony unpinned; by default it also gets the usernameless empty
  `allowCredentials`, so a non-existent account and one without passkeys look alike. A *known*
  account with passkeys still stands out through its non-empty `allowCredentials`; override
  `getEnumerationHardeningSecret()` to close that leak too, so every username returns the same
  response shape (see [Policy knobs](#policy-knobs)).

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

- **`ShipMonk\Passkeys\PasskeyStore`** — the durable side: your user and credential tables.
  Six methods: the reads `findUserHandleByUsername()`, `findCredentialsByUserHandle()`,
  `findCredentialByCredentialId()` and `findUserEntityByUserHandle()` (the last only used by the
  [Signal API](#keeping-credential-providers-in-sync-signal-api)), plus the two writes
  `saveCredential()` and `updateCredential()`. Typically a thin repository over the same database
  that holds your users.
- **`ShipMonk\Passkeys\PendingCeremonyStore`** — the transient side: ceremonies started but not
  yet finished, keyed by challenge. Implement it on something browser-session-scoped (the PHP
  session, a short-TTL cache), never on durable storage. Its consume-on-read semantics make each
  challenge single-use — the anti-replay control the library relies on.

### Policy knobs

The defaults are right for passkeys: user verification `required`, discoverable credentials
`required`, ES256/RS256/EdDSA, the spec-recommended 300 s timeout, cross-origin iframes rejected.
To change any of them, subclass `PasskeyFlow` and override the corresponding protected method
(`getUserVerificationRequirement()`, `getAllowedAlgorithms()`, `getResidentKeyRequirement()`,
`getTimeout()`, `isCrossOriginAllowed()`, `getAllowedTopOrigins()`, `generateChallenge()`).

#### Username-enumeration hardening

In the two-step flow, an account with passkeys returns a non-empty `allowCredentials` while a
non-existent one (or an account without passkeys) returns none — so a probing attacker can tell,
from the shape of `/login/options`, which usernames have passkeys (WebAuthn
[§14.6.2](https://www.w3.org/TR/webauthn-3/#sctn-username-enumeration)). Override
`getEnumerationHardeningSecret()` to return a fixed, high-entropy secret (≥16 bytes, the same on
every request, kept out of source control) and those responses instead carry a **stable, plausible
fabricated descriptor** derived from the username — indistinguishable from a real one, so the
distinction disappears:

```php
final class MyFlow extends PasskeyFlow
{
    protected function getEnumerationHardeningSecret(): ?string
    {
        return $this->appSecrets->passkeyEnumerationKey();  // fixed 32 random bytes from config
    }
}
```

The decoy only shapes the options response; verification is untouched, so a ceremony for a
non-existent account still fails closed. It equalizes the response, not every side channel — the
per-account response *timing* and the credential *count* can still differ slightly; override
`fabricateAllowCredentials()` if you need to narrow those too.

### Keeping credential providers in sync (Signal API)

Passkey providers (iCloud Keychain, Google Password Manager, …) keep their own copy of a user's
passkeys and the metadata shown for them. When your server's state drifts from theirs — a passkey
deleted server-side, an account renamed — the [WebAuthn Signal API](https://w3c.github.io/webauthn/#sctn-signal-methods)
lets you push corrections so the provider prunes stale passkeys and refreshes labels. The
`signal*()` calls run in the browser; the flow builds the two payloads that need data only your
server has:

```php
// After a successful sign-in, and whenever the user adds/removes a passkey or is renamed:
$accepted = $flow->allAcceptedCredentialsSignal($result->userHandle);  // complete accepted-id list
$details  = $flow->currentUserDetailsSignal($result->userHandle);       // current name/displayName
echo json_encode(['accepted' => $accepted, 'details' => $details]);
```

```js
// …then on the client, hand each payload to its method:
await PublicKeyCredential.signalAllAcceptedCredentials(accepted);
await PublicKeyCredential.signalCurrentUserDetails(details);
```

`allAcceptedCredentialsSignal()` returns the account's **complete** set of accepted credential ids
(an empty list when the account has none — which prunes them all, e.g. on account deletion). It
must stay authoritative: a provider hides any of its passkeys you leave out, so never build the
list from a filtered subset.

The third signal, `signalUnknownCredential()`, needs no server-built payload — the browser already
holds the credential id it just tried and your RP ID. When `authenticate()` rejects a login with
`VerificationException::UNKNOWN_CREDENTIAL`, tell the page, and let it prune that one credential:

```js
if (loginFailedAsUnknownCredential) {
    await PublicKeyCredential.signalUnknownCredential({ rpId, credentialId: credential.id });
}
```

## Example

A runnable, single-file relying party lives in [`example/`](example/) — multiple accounts, each
with several passkeys, all four endpoints driven through `PasskeyFlow` with a SQLite-backed
`PasskeyStore` and a `$_SESSION`-backed `PendingCeremonyStore`:

```sh
php -S localhost:8000 example/server.php   # then open http://localhost:8000
```

See [`example/README.md`](example/README.md).

## Testing your integration

You don't need a browser (or a real authenticator) to integration-test your endpoints:
`ShipMonk\Passkeys\Testing\FakeAuthenticator` is an in-memory software authenticator that turns
the options JSON your endpoint produced into the response JSON a browser would post back — a
`none`-format attestation over a freshly generated key pair for registration, a real signature
over `authenticatorData || SHA-256(clientDataJSON)` for authentication:

```php
use ShipMonk\Passkeys\Testing\FakeAuthenticator;

$authenticator = new FakeAuthenticator(origin: 'https://example.com');

// Registration: drive your endpoints end-to-end.
$optionsJson = $client->post('/register/options');
$client->post('/register/verify', $authenticator->createPasskey($optionsJson));

// Authentication: the fake holds the passkey it just created and signs with it.
$optionsJson = $client->post('/login/options');
$client->post('/login/verify', $authenticator->authenticate($optionsJson));
```

Like a real authenticator it keeps per-credential state across ceremonies (key pair, user handle,
signature counter — inspect it via `getPasskeys()`), refuses creation when `excludeCredentials`
lists a passkey it already holds, and honours `allowCredentials` when picking the passkey to
assert with. Constructor knobs cover the authenticator-side variations worth testing against:
the key algorithm, user presence/verification (e.g. emulate a PIN-less security key and assert
your policy rejects it), and backup state.

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

**`ShipMonk\Passkeys\Ceremony\RelyingParty`** runs the full WebAuthn §7.1 (registration) and §7.2 (authentication)
verification procedures against per-ceremony expectations, reading credentials through a
`CredentialStore` you implement:

```php
use ShipMonk\Passkeys\Ceremony\RegistrationExpectations;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Credential\PublicKeyCredential;
use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\Ceremony\RelyingParty;

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
    $store,   // your ShipMonk\Passkeys\Ceremony\CredentialStore
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
| `-8`   | `CoseAlgorithmIdentifier::EdDSA` | EdDSA (restricted to Ed25519 per WebAuthn [§5.8.5](https://w3c.github.io/webauthn/#sctn-alg-identifier)) |
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
