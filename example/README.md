# WebAuthnX passkey demo

A tiny, self-contained relying party that runs the full registration + login flow against the
`WebAuthnX\RelyingParty` façade — so you can create a real passkey and log in with it.

## Run it

From the project root (make sure `composer install` has been run):

```sh
php -S localhost:8000 example/server.php
```

Then open <http://localhost:8000>, click **Register a passkey** (your OS/browser will prompt for
Touch ID / Windows Hello / a security key), then click **Log in**.

> The RP id and origin are hard-coded to `localhost` / `http://localhost:8000` in
> `server.php`. WebAuthn treats `localhost` as a secure context, so no HTTPS is needed for local
> testing. If you serve it on another host or port, change `RP_ID` and `ORIGIN` together.
>
> Needs a recent browser (Chrome 119+, Safari 17.4+, or a current Firefox) for the
> `PublicKeyCredential.parseCreationOptionsFromJSON()` / `.toJSON()` helpers the page uses.

## What to look at

- **`server.php`** — five routes: it serves the page, issues creation/request options via the
  `Options\*` models (`->toJson()`), and verifies the browser's responses with
  `RelyingParty::verifyRegistration()` / `verifyAuthentication()`. Failures surface as a
  `VerificationException` whose `->reason` is returned to the page.
- **`PasskeyStore.php`** — a `CredentialStore` shaped like the database tables a real app would use
  (`users`, `credentials`), one row = one associative array of scalar columns. The credential's
  public key is stored in a single `public_key` column via `CoseKey::toBytes()` and rehydrated with
  `CoseKey::fromBytes()` — so persistence is just INSERT/SELECT over plain columns.

## Not production code

One demo user, and user verification is relaxed for authenticator compatibility. The store is
in-memory, kept in `$_SESSION` only because PHP's built-in server runs each request in a fresh
process (so plain memory can't span the register and login requests) — there's no file or database
of our own. A real service would run INSERT/SELECT/UPDATE against those same columns, with a proper
user/account model and per-session challenge storage. Login here is *usernameless* (discoverable
passkey): the assertion's `userHandle` identifies the account, so there's no username field.
