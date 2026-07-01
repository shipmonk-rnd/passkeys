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
- **`PasskeyStore.php`** — a file-backed `CredentialStore`. It shows the one non-obvious part of
  persisting a credential: a `CredentialRecord` carries a live `CoseKey`, and the library has no
  way to serialise that key by itself, so the store keeps the raw `attestationObject` from
  registration and re-parses it into a `CoseKey` on each login.

## Not production code

One demo user, state in a JSON file under `example/.data/` (git-ignored), and user verification is
relaxed for authenticator compatibility. A real service would use a database (one row per
credential), per-session challenge storage, and its own user/account model. Login here is
*usernameless* (discoverable passkey): the assertion's `userHandle` identifies the account, so
there's no username field.
