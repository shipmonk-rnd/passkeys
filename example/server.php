<?php declare(strict_types = 1);

/**
 * A small but realistic relying party built on WebAuthnX: multiple users (each identified by an
 * email), each able to register several passkeys.
 *
 * Run it with PHP's built-in server from the project root:
 *
 *     php -S localhost:8000 example/server.php
 *
 * then open http://localhost:8000. The RP id / origin below assume exactly that host and port;
 * change them together if you serve it elsewhere.
 *
 * All four WebAuthn endpoints go through the high-level {@see DemoPasskeyFlow} (a
 * {@see \WebAuthnX\Passkey\PasskeyFlow}): login is usernameless, two-step by email, or
 * conditional-mediation autofill; registration enrols the resolved account. What remains here is
 * only what a relying party genuinely owns — resolving/creating accounts and the session.
 *
 * Deliberately NOT production code: state lives in $_SESSION (see PasskeyStore) and — importantly —
 * the very first registration for an email is allowed without proving ownership. A real service
 * would verify the email (or require an already-authenticated session) before enrolling the first
 * passkey; adding *further* passkeys here does require being signed in, which is the correct
 * pattern.
 */

namespace WebAuthnXDemo;

use Throwable;
use WebAuthnX\Ceremony\VerificationException;
use WebAuthnX\Json\JsonObject;

use function base64_decode;
use function base64_encode;
use function file_get_contents;
use function filter_var;
use function header;
use function http_response_code;
use function json_encode;
use function parse_url;
use function random_bytes;
use function session_start;
use function trim;

use const FILTER_VALIDATE_EMAIL;
use const JSON_THROW_ON_ERROR;
use const PHP_URL_PATH;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/PasskeyStore.php';
require __DIR__ . '/DemoPasskeyFlow.php';

const RP_ID = 'localhost';
const RP_NAME = 'WebAuthnX Demo';
const ORIGIN = 'http://localhost:8000';

session_start();
$store = new PasskeyStore();
$flow = new DemoPasskeyFlow($store, RP_ID, RP_NAME, [ORIGIN]);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

/** @param array<string, mixed>|string $body */
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
// (Pending ceremony state lives in DemoPasskeyFlow, also on top of $_SESSION.)

function signIn(string $handle): void
{
	$_SESSION['auth_user_handle'] = base64_encode($handle);
}

function currentUserHandle(): ?string
{
	$handle = $_SESSION['auth_user_handle'] ?? null;

	return $handle === null ? null : base64_decode($handle);
}

match ($path) {
	'/' => (static function (): void {
		header('Content-Type: text/html; charset=utf-8');
		echo file_get_contents(__DIR__ . '/index.html');
	})(),

	// Who is signed in, and their registered passkeys.
	'/me' => (static function () use ($store): void {
		$handle = currentUserHandle();
		$user = $handle === null ? null : $store->findUserByHandle($handle);

		if ($handle === null || $user === null) {
			respond(200, ['authenticated' => false]);

			return;
		}

		$credentials = [];

		foreach ($store->credentialsForUser($handle) as $row) {
			$credentials[] = [
				'id' => $row['credential_id'],
				'attachment' => $row['authenticator_attachment'],
				'createdAt' => $row['created_at'],
				'signCount' => $row['sign_count'],
			];
		}

		respond(200, ['authenticated' => true, 'email' => $user['email'], 'credentials' => $credentials]);
	})(),

	'/logout' => (static function (): void {
		unset($_SESSION['auth_user_handle']);
		respond(200, ['ok' => true]);
	})(),

	// ---- Registration (navigator.credentials.create) ---------------------------------------

	'/register/options' => (static function () use ($store, $flow): void {
		try {
			$current = currentUserHandle();

			if ($current !== null) {
				// Signed in: enrol an additional passkey for the current account.
				$user = $store->findUserByHandle($current);

				if ($user === null) {
					respond(400, ['ok' => false, 'message' => 'Signed-in user no longer exists']);

					return;
				}

				$handle = $current;
				$email = $user['email'];
			} else {
				// Not signed in: register a new (or returning) account by email.
				$email = trim(body()->getOptionalString('email') ?? '');

				if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
					respond(400, ['ok' => false, 'message' => 'A valid email is required to register.']);

					return;
				}

				$existing = $store->findUserByEmail($email);
				$handle = $existing !== null
					? base64_decode($existing['user_handle'])
					: random_bytes(16);

				if ($existing === null) {
					$store->insertUser($handle, $email);
				}
			}

			// The flow issues the challenge, excludes already-enrolled authenticators, and asks
			// for a discoverable (resident) credential with user verification — the passkey defaults.
			$options = $flow->registrationOptions($handle, $email);

			respond(200, $options->toJson());

		} catch (Throwable $e) {
			respond(400, ['ok' => false, 'message' => $e->getMessage()]);
		}
	})(),

	'/register/verify' => (static function () use ($store, $flow): void {
		try {
			// The flow verifies the ceremony and persists the credential (DemoPasskeyFlow::saveCredential).
			$registered = $flow->register((string) file_get_contents('php://input'));
			signIn($registered->userHandle);

			$user = $store->findUserByHandle($registered->userHandle);
			respond(200, ['ok' => true, 'email' => $user['email'] ?? 'unknown']);

		} catch (VerificationException $e) {
			respond(400, ['ok' => false, 'reason' => $e->reason, 'message' => $e->getMessage()]);
		} catch (Throwable $e) {
			respond(400, ['ok' => false, 'message' => $e->getMessage()]);
		}
	})(),

	// ---- Authentication (navigator.credentials.get) ----------------------------------------

	// Without an email the options are usernameless (no allowCredentials — a discoverable passkey
	// identifies the user); with one, the ceremony is pinned to that account and its credentials
	// are listed. The same endpoint also feeds the conditional-mediation (autofill) request.
	'/login/options' => (static function () use ($flow): void {
		try {
			$email = trim(body()->getOptionalString('email') ?? '');
			$options = $flow->authenticationOptions($email === '' ? null : $email);

			respond(200, $options->toJson());

		} catch (Throwable $e) {
			respond(400, ['ok' => false, 'message' => $e->getMessage()]);
		}
	})(),

	'/login/verify' => (static function () use ($store, $flow): void {
		try {
			$result = $flow->authenticate((string) file_get_contents('php://input'));
			signIn($result->userHandle);

			$user = $store->findUserByHandle($result->userHandle);
			respond(200, [
				'ok' => true,
				'email' => $user['email'] ?? 'unknown',
				'signCount' => $result->newSignCount,
				'possibleClone' => $result->possibleClone,
			]);

		} catch (VerificationException $e) {
			respond(400, ['ok' => false, 'reason' => $e->reason, 'message' => $e->getMessage()]);
		} catch (Throwable $e) {
			respond(400, ['ok' => false, 'message' => $e->getMessage()]);
		}
	})(),

	default => respond(404, ['message' => 'Not found']),
};
