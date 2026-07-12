# ShipMonk\Passkeys demo

A small but realistic relying party built on `ShipMonk\Passkeys`, in the shape most services
actually have: a **password is the primary credential**, and **passkeys are an added convenience**
an already-signed-in user enrols and manages. There is no self-service signup — two fixed accounts
are seeded with passwords — so you can see the whole real-world flow: password login → add a passkey
→ sign in with the passkey (button or autofill) → remove it again.

## Run it

From the project root (after `composer install`):

```sh
php -S localhost:8000 example/server.php
```

Then open <http://localhost:8000>:

1. **Sign in with a password.** Two accounts are seeded (passwords are hard-coded and shown on the page for convenience — this is a demo): `alice@example.com` / `alice` and `bob@example.com` / `bob`.
2. While signed in, **Add a passkey** (your OS/browser prompts for Touch ID / Windows Hello / a
   security key). It shows up in the per-account list, where you can also **Remove** it.
3. Sign out, then **Sign in with a passkey** — usernameless: the passkey itself identifies the
   account. Or just focus the email field and pick the passkey from **autofill** (conditional
   mediation), which the page arms in the background.

> RP id / origin are hard-coded to `localhost` / `http://localhost:8000` in `server.php` (WebAuthn
> treats `localhost` as a secure context, so no HTTPS is needed locally). Change the `rpId` and
> `origins` arguments passed to `PasskeyFlow` in `server.php` together if you serve it elsewhere.
> Needs a recent browser for the
> `PublicKeyCredential.parseCreationOptionsFromJSON()` / `.toJSON()` helpers the page uses.

## What to look at

- **`server.php`** — the routes. `/login/password` verifies the seeded password and starts a
  session; `/register/options` + `/register/verify` add a passkey to the *signed-in* account
  (pinned to it with `expectedUserHandle`); `/passkeys/remove` deletes one and returns a
  `signalAllAcceptedCredentials` payload so the browser prunes it from the credential provider;
  `/login/options` (usernameless) + `/login/verify` run passkey sign-in; `/me` and `/logout` back
  the session. Passkey ceremonies go through a `PasskeyFlow`; the password login, seeded accounts,
  and session are the relying party's own concern. Failed passkey checks surface the
  `VerificationException`'s `->reason`.
- **`PasskeyStore.php`** — the library's `PasskeyStore` interface implemented over a SQLite
  database (`pdo_sqlite`, file `example/passkeys.sqlite`): `users` (integer id PK,
  passkey_user_handle unique BLOB, email, `password_hash`) and `credentials` (credential_id PK,
  user_id FK, public_key, sign_count, flags, transports, …). One user → many credentials via the
  foreign key. The constructor seeds the two demo accounts idempotently (`INSERT OR IGNORE`), with
  a bcrypt password hash and a freshly minted 64-byte WebAuthn user handle. The public key is a
  single `public_key` column via `CoseKey::toBytes()`, rehydrated with `CoseKey::fromBytes()` —
  persistence is just INSERT/SELECT/UPDATE/DELETE over plain columns.
- **`SessionPendingCeremonyStore.php`** — the library's `PendingCeremonyStore` on top of
  `$_SESSION`: unfinished ceremonies keyed by challenge, consumed (deleted) on use so each
  challenge is single-use, and capped per session.

## Not production code

Accounts and passkeys persist in `example/passkeys.sqlite` (needs `pdo_sqlite`; delete the file to
reset the demo), while the sign-in state and pending ceremonies stay in `$_SESSION`. A real service
would run the same INSERT/SELECT/UPDATE against its own database.

The important thing this demo gets **right** is the trust model: a passkey is only ever added by, or
removed from, an authenticated session, and every add-passkey ceremony is pinned to the signed-in
account. What it deliberately skips — fine for a local demo, not for production — is real password
handling (the demo passwords are hard-coded and printed on the page), rate limiting, CSRF
protection, and hiding account existence (the login error is generic, but response timing and the
seeded accounts still reveal who exists).
