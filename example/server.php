<?php declare(strict_types = 1);

/**
 * A small but realistic relying party built on ShipMonk\Passkeys, in the shape most services
 * actually have: a password is the primary credential, and passkeys are an *added* convenience an
 * already-signed-in user enrols and manages. There is no self-service signup — two fixed accounts
 * (alice@example.com / bob@example.com) are seeded with passwords by {@see PasskeyStore} — so the
 * "prove you own this email before the first enrolment" problem never arises here: every passkey
 * is added from an authenticated session, which is the pattern a real service should follow.
 *
 * Run it with PHP's built-in server from the project root:
 *
 *     php -S localhost:8000 example/server.php
 *
 * then open http://localhost:8000 and sign in with one of the seeded accounts (the demo passwords
 * are printed on the page). The RP id / origin below assume exactly that host and port; change
 * them together if you serve it elsewhere.
 *
 * Passkey sign-in goes through the high-level {@see PasskeyFlow} — usernameless via the button, or
 * conditional-mediation autofill — over the SQLite-backed {@see PasskeyStore} and the
 * session-backed {@see SessionPendingCeremonyStore}. Password login, the seeded accounts, and the
 * sign-in session are the relying party's own concern and live here.
 *
 * Deliberately NOT production code: the demo passwords are printed on the page, account existence
 * is observable, and there is no rate limiting or CSRF protection. What it does get right is the
 * trust model — a passkey is only ever added or removed from an authenticated session, and every
 * add-passkey ceremony is pinned to the signed-in account with `$expectedUserHandle` so a ceremony
 * started in one session can never complete in another and attach a cross-account credential.
 */

namespace ShipMonk\PasskeysDemo;

use ShipMonk\Passkeys\Ceremony\VerificationException;
use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\PasskeyFlow;
use Throwable;
use function file_get_contents;
use function header;
use function http_response_code;
use function is_string;
use function json_encode;
use function parse_url;
use function password_verify;
use function session_regenerate_id;
use function session_start;
use const JSON_THROW_ON_ERROR;
use const PHP_URL_PATH;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/PasskeyStore.php';
require __DIR__ . '/SessionPendingCeremonyStore.php';

session_start();
$store = new PasskeyStore(__DIR__ . '/passkeys.sqlite');

$flow = new PasskeyFlow(
    rpId: 'localhost',
    rpName: 'ShipMonk\Passkeys Demo',
    origins: ['http://localhost:8000'],
    store: $store,
    pendingCeremonyStore: new SessionPendingCeremonyStore(),
);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

/**
 * @param array<string, mixed>|string $body
 */
function respond(int $status, array|string $body): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo is_string($body) ? $body : json_encode($body, JSON_THROW_ON_ERROR);
}

function body(): JsonObject
{
    return JsonObject::fromString((string) file_get_contents('php://input'));
}

// --- Session state: who is signed in ------------------------------------------------------------
// (Pending ceremony state lives in SessionPendingCeremonyStore, also on top of $_SESSION.)

// Both password and passkey sign-in land here. The session id is rotated on every sign-in so a
// fixed, pre-authentication id can't be reused to ride the new session (session fixation).
function signIn(int $userId): void
{
    session_regenerate_id(true);
    $_SESSION['auth_user_id'] = $userId;
}

function currentUserId(): ?int
{
    return $_SESSION['auth_user_id'] ?? null;
}

/**
 * The signed-in account, or null after sending a 401 — the guard the passkey-management routes
 * share, since a passkey is only ever added or removed from an authenticated session.
 *
 * @return array{id: int, passkey_user_handle: string, email: string, password_hash: string}|null
 */
function requireUser(PasskeyStore $store): ?array
{
    $userId = currentUserId();
    $user = $userId === null ? null : $store->findUserById($userId);

    if ($user === null) {
        respond(401, ['ok' => false, 'message' => 'You must be signed in.']);
        return null;
    }

    return $user;
}

match ($path) {
    '/' => (static function (): void {
        header('Content-Type: text/html; charset=utf-8');
        echo file_get_contents(__DIR__ . '/index.html');
    })(),

    // Who is signed in, and the passkeys they can manage.
    '/me' => (static function () use ($store): void {
        $userId = currentUserId();
        $user = $userId === null ? null : $store->findUserById($userId);

        if ($user === null) {
            respond(200, ['authenticated' => false]);
            return;
        }

        $credentials = [];

        foreach ($store->credentialsForUser($user['id']) as $row) {
            $credentials[] = [
                'id' => $row['credential_id'],
                'attachment' => $row['authenticator_attachment'],
                'createdAt' => $row['created_at'],
            ];
        }

        respond(200, ['authenticated' => true, 'email' => $user['email'], 'credentials' => $credentials]);
    })(),

    '/logout' => (static function (): void {
        unset($_SESSION['auth_user_id']);
        respond(200, ['ok' => true]);
    })(),

    // ---- Password sign-in (the primary credential) ------------------------------------------

    // What a fresh visitor signs in with. Passkeys are added afterwards, from the session this
    // establishes. The demo accounts and their passwords are seeded by PasskeyStore.
    '/login/password' => (static function () use ($store): void {
        try {
            $body = body();
            $email = $body->getString('email');
            $password = $body->getString('password');

        } catch (Throwable $e) {
            respond(400, ['ok' => false, 'message' => 'Email and password are required.']);
            return;
        }

        $user = $store->findUserByEmail($email);

        // One generic message for both "no such account" and "wrong password", so the response does
        // not disclose which failed. (Timing still differs — password_verify only runs for a known
        // account; a real service verifies against a dummy hash to equalize it. Out of scope here.)
        if ($user === null || !password_verify($password, $user['password_hash'])) {
            respond(401, ['ok' => false, 'message' => 'Invalid email or password.']);
            return;
        }

        signIn($user['id']);
        respond(200, ['ok' => true, 'email' => $user['email']]);
    })(),

    // ---- Passkey management: add / remove, signed-in only -----------------------------------

    // Enrol an additional passkey for the already-signed-in account (navigator.credentials.create).
    // There is no signed-out registration path: the only way to a passkey is from a session that has
    // already proved who it is.
    '/register/options' => (static function () use ($store, $flow): void {
        $user = requireUser($store);

        if ($user === null) {
            return;
        }

        // The flow issues the challenge, excludes already-enrolled authenticators, and asks for a
        // discoverable (resident) credential with user verification — the passkey defaults.
        $options = $flow->registrationOptions($user['passkey_user_handle'], $user['email']);
        respond(200, $options->toJson());
    })(),

    '/register/verify' => (static function () use ($store, $flow): void {
        $user = requireUser($store);

        if ($user === null) {
            return;
        }

        try {
            // $expectedUserHandle pins the ceremony to the signed-in account: a pending registration
            // minted in another session (for another user) is rejected before anything is verified
            // or persisted, so a passkey can never be attached across accounts.
            $flow->register(
                (string) file_get_contents('php://input'),
                expectedUserHandle: $user['passkey_user_handle'],
            );
            respond(200, ['ok' => true]);

        } catch (VerificationException $e) {
            respond(400, ['ok' => false, 'reason' => $e->reason, 'message' => $e->getMessage()]);
        }
    })(),

    // Remove one of the account's passkeys.
    '/passkeys/remove' => (static function () use ($store, $flow): void {
        $user = requireUser($store);

        if ($user === null) {
            return;
        }

        try {
            $credentialId = body()->getString('id');

        } catch (Throwable $e) {
            respond(400, ['ok' => false, 'message' => 'A credential id is required.']);
            return;
        }

        // Scoped to the user, so an account can only ever delete its own passkey.
        $store->deleteCredential($user['id'], $credentialId);

        // The account's accepted-credential set just changed: hand the browser the *complete*
        // remaining set (WebAuthn §5.1.10) so its credential provider prunes the passkey it still
        // lists. Read straight from the store after the delete, so it stays authoritative.
        $signal = $flow->allAcceptedCredentialsSignal($user['passkey_user_handle']);
        respond(200, ['ok' => true, 'signal' => $signal]);
    })(),

    // ---- Passkey sign-in (navigator.credentials.get) ----------------------------------------

    // Usernameless: no allowCredentials, so a discoverable passkey identifies the account by its
    // user handle. The same options feed both the explicit "sign in with a passkey" button and the
    // conditional-mediation (autofill) request the page starts in the background.
    '/login/options' => (static function () use ($flow): void {
        $options = $flow->authenticationOptions();
        respond(200, $options->toJson());
    })(),

    '/login/verify' => (static function () use ($store, $flow): void {
        try {
            $result = $flow->authenticate((string) file_get_contents('php://input'));
            $user = $store->findUserByHandle($result->userHandle);

            if ($user !== null) {
                signIn($user['id']);
            }

            respond(200, ['ok' => true, 'email' => $user['email'] ?? 'unknown']);

        } catch (VerificationException $e) {
            respond(400, ['ok' => false, 'reason' => $e->reason, 'message' => $e->getMessage()]);
        }
    })(),

    default => respond(404, ['message' => 'Not found']),
};
