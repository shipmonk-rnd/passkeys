# ShipMonk\Passkeys demo

A small but realistic relying party built on `ShipMonk\Passkeys`: multiple accounts (each identified by an
email), each able to register several passkeys — so you can see the full registration + login flow,
plus a per-account passkey list.

## Run it

From the project root (after `composer install`):

```sh
php -S localhost:8000 example/server.php
```

Then open <http://localhost:8000>:

1. Enter an email and **Register a passkey** (your OS/browser prompts for Touch ID / Windows Hello /
   a security key).
2. **Sign in with a passkey** — usernameless: the passkey itself identifies the account.
3. While signed in, **Add another passkey** (e.g. from a second device) — they all show up under
   your account. Try a different email to create a second, separate account.

> RP id / origin are hard-coded to `localhost` / `http://localhost:8000` in `server.php` (WebAuthn
> treats `localhost` as a secure context, so no HTTPS is needed locally). Change `RP_ID` and
> `ORIGIN` together if you serve it elsewhere. Needs a recent browser for the
> `PublicKeyCredential.parseCreationOptionsFromJSON()` / `.toJSON()` helpers the page uses.

## What to look at

- **`server.php`** — the routes. `/register/options` finds-or-creates the user by email;
  `/register/verify`, `/login/options` (usernameless) and `/login/verify` run the ceremonies
  through a `PasskeyFlow` constructed with the two stores below; `/me` and `/logout` back a simple
  sign-in session. Failed checks surface the `VerificationException`'s `->reason`.
- **`PasskeyStore.php`** — the library's `PasskeyStore` interface implemented over a SQLite
  database (`pdo_sqlite`, file `example/passkeys.sqlite`): `users` (integer id PK,
  passkey_user_handle unique BLOB, email) and `credentials` (credential_id PK, user_id FK,
  public_key, sign_count, flags, transports, …). One user → many credentials via the foreign key.
  The WebAuthn user handle is the spec-recommended 64 opaque random bytes in its own unique
  column — the integer primary key stays server-internal. The public key is a single `public_key`
  column via `CoseKey::toBytes()`, rehydrated with `CoseKey::fromBytes()` — persistence is just
  INSERT/SELECT/UPDATE over plain columns.
- **`SessionPendingCeremonyStore.php`** — the library's `PendingCeremonyStore` on top of
  `$_SESSION`: unfinished ceremonies keyed by challenge, consumed (deleted) on use so each
  challenge is single-use, and capped per session.

## Not production code

Accounts and passkeys persist in `example/passkeys.sqlite` (needs `pdo_sqlite`; delete the file to
reset the demo), while the sign-in state and pending ceremonies stay in `$_SESSION`. A real service
would run the same INSERT/SELECT/UPDATE against its own database.

Also note the **trust simplification**: the *first* passkey for an email is enrolled without proving
ownership of that address. A real service would verify the email (or require an already-signed-in
session) before the first enrolment. Adding *further* passkeys here already requires being signed in,
which is the correct pattern.
