# ShipMonk\Passkeys — Symfony demo

The same password-first relying party as [`../plain-php/`](../plain-php/), rebuilt idiomatically on
**Symfony** with `MicroKernelTrait` (the whole app is configured inline in one `Kernel`), a
**Doctrine ORM** `PasskeyStore`, a session-backed `PendingCeremonyStore`, and a Twig page. It shows
how the framework-agnostic `ShipMonk\Passkeys` library plugs into a real Symfony application:
dependency injection, the session, and Doctrine.

## Run it

The Symfony, Doctrine, and Twig packages are `require-dev` of the library, so this example runs off
the repository's root `vendor/` — no separate `composer install` here. From the **repository root**:

```sh
composer install                                          # once, installs the dev dependencies
php -S localhost:8000 -t example/symfony/public example/symfony/public/index.php
```

Then open <http://localhost:8000>:

1. **Sign in with a password.** Two accounts are seeded (passwords hard-coded and shown on the page
   for convenience — this is a demo): `alice@example.com` / `alice` and `bob@example.com` / `bob`.
2. While signed in, **Add a passkey** (your OS/browser prompts for Touch ID / Windows Hello / a
   security key). It shows up in the per-account list, where you can also **Remove** it.
3. Sign out, then **Sign in with a passkey** — usernameless: the passkey itself identifies the
   account. Or just focus the email field and pick the passkey from **autofill** (conditional
   mediation), which the page arms in the background.

The database is created and the demo accounts seeded automatically on first run (see
`Kernel::boot()`). To reset the demo, delete `var/passkeys.sqlite` (or the whole `var/`, which also
holds Symfony's cache); it is recreated on the next request.

> RP id / origin are hard-coded to `localhost` / `http://localhost:8000` in `src/Kernel.php`
> (WebAuthn treats `localhost` as a secure context, so no HTTPS is needed locally). Change the
> `$rpId` and `$origins` arguments passed to `PasskeyFlow` there together if you serve it elsewhere.
> The `-t example/symfony/public` docroot lets PHP's built-in server route every request through
> `public/index.php`. Needs a recent browser for the `PublicKeyCredential.parseCreationOptionsFromJSON()`
> / `.toJSON()` helpers the page uses.

## What to look at

- **`src/Kernel.php`** — the wiring, and the file to read first. `MicroKernelTrait` configures the
  container inline: it registers `PasskeyFlow` as a service with this RP's identity, aliases the
  library's `PasskeyStore` / `PendingCeremonyStore` interfaces to the implementations below,
  enables the session, and points Doctrine at a SQLite database. `getProjectDir()` is pinned to this
  directory because the example runs off the *root* `vendor/`, and `boot()` creates the schema and
  seeds the demo accounts on first run.
- **`src/Controller/`** — the endpoints, one thin controller per concern.
  `PasswordLoginController` verifies the seeded password and starts a session (`/login/password`);
  `PasskeyManageController` lists the account's passkeys, adds one to the *signed-in* account (pinned
  to it with `expectedUserHandle`), and removes one (returning a `signalAllAcceptedCredentials`
  payload so the browser prunes it); `PasskeyLoginController` runs usernameless passkey sign-in (`/login/passkey`);
  `HomeController` serves the page and the `/me` + `/logout` session endpoints. Failed passkey checks
  surface the `VerificationException`'s `->reason`.
- **`src/Passkey/DoctrinePasskeyStore.php`** — the library's `PasskeyStore` over an
  `EntityManagerInterface`: `find` / `persist` / `remove` against the `User` and `PasskeyCredential`
  entities, converting to and from the library's `CredentialRecord` / `RegisteredPasskey` DTOs. It
  also carries the account lookups the controllers need (`findUserByEmail`, `deleteCredential`, …).
- **`src/Entity/`** — the interesting part of an ORM-backed store: the **binary** WebAuthn fields.
  The user handle, credential id, and COSE public key are all stored with Doctrine's built-in
  `binary` type (a `BLOB` on SQLite, returned as a plain string); `PasskeyCredential` converts the
  public key to and from the library's `CoseKey` explicitly via `CoseKey::toBytes()` /
  `CoseKey::fromBytes()`. (Doctrine's `blob` type, by contrast, hands back a stream resource —
  awkward for a primary key and for passing raw bytes to the library, hence `binary`.)
- **`src/Passkey/SessionPendingCeremonyStore.php`** — the `PendingCeremonyStore` on the Symfony
  session (via `RequestStack`): unfinished ceremonies keyed by challenge, consumed on use so each
  challenge is single-use, and capped per session.

## Not production code

Accounts and passkeys persist in `var/passkeys.sqlite`; the sign-in state and pending ceremonies
stay in the session. A real service would run the same Doctrine calls against its own database.

The important thing this demo gets **right** is the trust model: a passkey is only ever added by, or
removed from, an authenticated session, and every add-passkey ceremony is pinned to the signed-in
account with `expectedUserHandle`. What it deliberately skips — fine for a local demo, not for
production — is:

- **Symfony Security.** "Who is signed in" is a plain user id on the session (`Account\UserSession`),
  *not* the Symfony Security firewall. The example is about wiring the passkeys library, not building
  an authentication stack; a real app would use a `UserInterface`, a firewall, and a passkey
  authenticator.
- Real password handling (the demo passwords are hard-coded and printed on the page), rate limiting,
  CSRF protection, and hiding account existence (the login error is generic, but response timing and
  the seeded accounts still reveal who exists).
