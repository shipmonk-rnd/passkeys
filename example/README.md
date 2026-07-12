# ShipMonk\Passkeys examples

Two runnable relying parties, both the **same password-first flow** — a password is the primary
credential and passkeys are an *added* convenience an already-signed-in user enrols and manages:

> password login → add a passkey → sign in with the passkey (button or autofill) → remove it.

They exist to be compared: the same `PasskeyFlow`, `PasskeyStore`, and `PendingCeremonyStore`
concepts wired two ways. Both serve `http://localhost:8000` (WebAuthn treats `localhost` as a
secure context, so no HTTPS is needed locally), so run one at a time.

## [`plain-php/`](plain-php/)

A single-file, dependency-free relying party on PHP's built-in server — the shortest path to seeing
the library work. SQLite-backed `PasskeyStore`, `$_SESSION`-backed `PendingCeremonyStore`.

```sh
php -S localhost:8000 example/plain-php/server.php
```

## [`symfony/`](symfony/)

The same relying party built idiomatically on Symfony (`MicroKernelTrait`): `PasskeyFlow` as a
container service, a **Doctrine ORM** `PasskeyStore` (with custom DBAL types for the binary
WebAuthn fields), a session-backed `PendingCeremonyStore`, and a Twig page. The Symfony/Doctrine/Twig
packages are `require-dev` of the library, so a single root `composer install` is all the setup it
needs.

```sh
composer install                                                       # from the repo root
php example/symfony/bin/console app:setup                              # schema + seed accounts
php -S localhost:8000 -t example/symfony/public example/symfony/public/index.php
```

Neither is production code — see each directory's `README.md` for what they deliberately skip
(real password handling, rate limiting, CSRF protection, …) and what they get right (the trust
model: a passkey is only ever added or removed from an authenticated session).
