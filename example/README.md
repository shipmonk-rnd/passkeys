# WebAuthnX passkey demo

A small but realistic relying party built on `WebAuthnX`: multiple accounts (each identified by an
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

- **`server.php`** — the routes. `/register/options` finds-or-creates the user by email and sends
  `excludeCredentials` (so one authenticator can't enrol twice); `/register/verify`,
  `/login/options` (usernameless) and `/login/verify` run the ceremonies through `RelyingParty`;
  `/me` and `/logout` back a simple sign-in session. Failed checks surface the
  `VerificationException`'s `->reason`.
- **`PasskeyStore.php`** — a `CredentialStore` shaped like real SQL tables: `users` (user_handle PK,
  email) and `credentials` (credential_id PK, user_handle FK, public_key, sign_count, flags,
  transports, …). One user → many credentials via the foreign key. The public key is a single
  `public_key` column via `CoseKey::toBytes()`, rehydrated with `CoseKey::fromBytes()` — persistence
  is just INSERT/SELECT/UPDATE over plain columns.

## Not production code

State is in-memory, kept in `$_SESSION` only because PHP's built-in server runs each request in a
fresh process (so plain memory can't span requests) — there's no file or database of our own; a real
service runs INSERT/SELECT/UPDATE against those same columns. User verification is relaxed for
authenticator compatibility.

Also note the **trust simplification**: the *first* passkey for an email is enrolled without proving
ownership of that address. A real service would verify the email (or require an already-signed-in
session) before the first enrolment. Adding *further* passkeys here already requires being signed in,
which is the correct pattern.
