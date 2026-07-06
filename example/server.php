<?php declare(strict_types = 1);

/**
 * A small but realistic relying party built on ShipMonk\WebAuthn: multiple users (each identified by an
 * email), each able to register several passkeys.
 *
 * Run it with PHP's built-in server from the project root:
 *
 *     php -S localhost:8000 example/server.php
 *
 * then open http://localhost:8000. The RP id / origin below assume exactly that host and port;
 * change them together if you serve it elsewhere.
 *
 * All four WebAuthn endpoints go through the high-level {@see PasskeyFlow}, constructed with the
 * SQLite-backed {@see PasskeyStore} and the session-backed {@see SessionPendingCeremonyStore}:
 * login is usernameless, two-step by email, or conditional-mediation autofill; registration
 * enrols the resolved account. What remains here is only what a relying party genuinely owns —
 * resolving/creating accounts and the session.
 *
 * Accounts and credentials persist in a SQLite file next to this script (see PasskeyStore); only
 * the sign-in state and pending ceremonies live in $_SESSION.
 *
 * Deliberately NOT production code — importantly, the very first registration for an email is
 * allowed without proving ownership, so anyone can squat any email (first come, first served). A
 * real service gates every enrolment path — signup, adding a passkey, account recovery — on a live
 * proof: an authenticated session or a fresh email-control token, still valid when the ceremony
 * *completes*, not just when its options were issued. Adding *further* passkeys here does require
 * being signed in, which is the correct pattern. (The "email already has an account" reply also
 * reveals account existence — fine for a demo, something to obscure in production.)
 */

namespace ShipMonk\WebAuthnDemo;

use ShipMonk\WebAuthn\Ceremony\VerificationException;
use ShipMonk\WebAuthn\Json\JsonObject;
use ShipMonk\WebAuthn\Passkey\PasskeyFlow;
use Throwable;
use function file_get_contents;
use function filter_var;
use function header;
use function http_response_code;
use function is_string;
use function json_encode;
use function parse_url;
use function session_start;
use const FILTER_VALIDATE_EMAIL;
use const JSON_THROW_ON_ERROR;
use const PHP_URL_PATH;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/PasskeyStore.php';
require __DIR__ . '/SessionPendingCeremonyStore.php';

session_start();
$store = new PasskeyStore(__DIR__ . '/passkeys.sqlite');

$flow = new PasskeyFlow(
    rpId: 'localhost',
    rpName: 'ShipMonk\WebAuthn Demo',
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

// A ceremony yields the opaque WebAuthn user handle; the relying party resolves it to its own
// account (PasskeyStore::findUserByHandle) and the session keys off the integer user id.
function signIn(int $userId): void
{
    $_SESSION['auth_user_id'] = $userId;
}

function currentUserId(): ?int
{
    return $_SESSION['auth_user_id'] ?? null;
}

match ($path) {
    '/' => (static function (): void {
        header('Content-Type: text/html; charset=utf-8');
        echo file_get_contents(__DIR__ . '/index.html');
    })(),

    // Who is signed in, and their registered passkeys.
    '/me' => (static function () use ($store): void {
        $userId = currentUserId();
        $user = $userId === null ? null : $store->findUserById($userId);

        if ($userId === null || $user === null) {
            respond(200, ['authenticated' => false]);
            return;
        }

        $credentials = [];

        foreach ($store->credentialsForUser($userId) as $row) {
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

    // ---- Registration (navigator.credentials.create) ---------------------------------------

    '/register/options' => (static function () use ($store, $flow): void {
        try {
            $currentId = currentUserId();

            if ($currentId !== null) {
                // Signed in: enrol an additional passkey for the current account.
                $user = $store->findUserById($currentId);

                if ($user === null) {
                    respond(400, ['ok' => false, 'message' => 'Signed-in user no longer exists']);
                    return;
                }

            } else {
                // Not signed in: register a brand-new account by email. An existing account must
                // never be enrollable while signed out — that would let anyone who knows the email
                // attach their own passkey to it and take it over.
                $email = body()->getString('email');

                if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
                    respond(400, ['ok' => false, 'message' => 'A valid email is required to register.']);
                    return;
                }

                $existing = $store->findUserByEmail($email);

                if ($existing !== null) {
                    respond(400, ['ok' => false, 'message' => 'This email already has an account — sign in with its passkey to add another one.']);
                    return;
                }

                // The email is free: create the account and enrol its first passkey in one go. A
                // cancelled prompt leaves a credential-less row that blocks the email for good
                // (delete the row to retry). That is deliberate, not resumed: a pending ceremony
                // stays completable for as long as the session keeps it, so whoever requested
                // options for this email first could still attach their passkey to the account
                // after the real user enrolled. A real service side-steps the whole problem by
                // gating first enrolment on email verification.
                $user = $store->insertUser($email);
            }

            // The flow issues the challenge, excludes already-enrolled authenticators, and asks
            // for a discoverable (resident) credential with user verification — the passkey defaults.
            $options = $flow->registrationOptions($user['passkey_user_handle'], $user['email']);

            respond(200, $options->toJson());

        } catch (Throwable $e) {
            respond(400, ['ok' => false, 'message' => $e->getMessage()]);
        }
    })(),

    '/register/verify' => (static function () use ($store, $flow): void {
        try {
            // The flow verifies the ceremony and persists the credential (PasskeyStore::saveCredential).
            $registered = $flow->register((string) file_get_contents('php://input'));
            $user = $store->findUserByHandle($registered->userHandle);

            if ($user !== null) {
                signIn($user['id']);
            }

            respond(200, ['ok' => true, 'email' => $user['email'] ?? 'unknown']);

        } catch (VerificationException $e) {
            respond(400, ['ok' => false, 'reason' => $e->reason, 'message' => $e->getMessage()]);
        }
    })(),

    // ---- Authentication (navigator.credentials.get) ----------------------------------------

    // Without an email the options are usernameless (no allowCredentials — a discoverable passkey
    // identifies the user); with one, the ceremony is pinned to that account and its credentials
    // are listed. The same endpoint also feeds the conditional-mediation (autofill) request.
    '/login/options' => (static function () use ($flow): void {
        try {
            $body = JsonObject::fromString((string) file_get_contents('php://input'));
            $email = $body->getOptionalString('email');
            $options = $flow->authenticationOptions($email);
            respond(200, $options->toJson());

        } catch (Throwable $e) {
            respond(400, ['ok' => false, 'message' => $e->getMessage()]);
        }
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
