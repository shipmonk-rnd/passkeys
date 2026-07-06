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
 * Deliberately NOT production code: state lives in $_SESSION (see PasskeyStore), user verification
 * is relaxed for authenticator compatibility, and — importantly — the very first registration for
 * an email is allowed without proving ownership. A real service would verify the email (or require
 * an already-authenticated session) before enrolling the first passkey; adding *further* passkeys
 * here does require being signed in, which is the correct pattern.
 */

namespace WebAuthnXDemo;

use Throwable;
use WebAuthnX\Ceremony\AuthenticationExpectations;
use WebAuthnX\Ceremony\RegistrationExpectations;
use WebAuthnX\Ceremony\VerificationException;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Credential\PublicKeyCredential;
use WebAuthnX\Enum\PublicKeyCredentialType;
use WebAuthnX\Enum\ResidentKeyRequirement;
use WebAuthnX\Enum\UserVerificationRequirement;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\Options\AuthenticatorSelectionCriteria;
use WebAuthnX\Options\PublicKeyCredentialCreationOptions;
use WebAuthnX\Options\PublicKeyCredentialDescriptor;
use WebAuthnX\Options\PublicKeyCredentialParameters;
use WebAuthnX\Options\PublicKeyCredentialRequestOptions;
use WebAuthnX\Options\PublicKeyCredentialRpEntity;
use WebAuthnX\Options\PublicKeyCredentialUserEntity;
use WebAuthnX\RelyingParty;

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

const RP_ID = 'localhost';
const RP_NAME = 'WebAuthnX Demo';
const ORIGIN = 'http://localhost:8000';

/** The algorithms we accept, best first. */
const ALLOWED_ALGORITHMS = [
	CoseAlgorithmIdentifier::ES256,
	CoseAlgorithmIdentifier::RS256,
	CoseAlgorithmIdentifier::EdDSA,
];

session_start();
$store = new PasskeyStore();
$rp = new RelyingParty();

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

// --- Session state: the pending ceremony challenge + who is signed in --------------------------
// Transient per-browser state (not database tables); a real app keeps these in the session/cache.

function rememberChallenge(string $challenge): void
{
	$_SESSION['pending_challenge'] = base64_encode($challenge);
}

/** Returns and clears the pending challenge, keeping each challenge single-use. */
function consumeChallenge(): ?string
{
	$challenge = $_SESSION['pending_challenge'] ?? null;
	unset($_SESSION['pending_challenge']);

	return $challenge === null ? null : base64_decode($challenge);
}

/** The user a pending registration ceremony is enrolling a passkey for. */
function rememberPendingUser(string $handle): void
{
	$_SESSION['pending_user_handle'] = base64_encode($handle);
}

function consumePendingUser(): ?string
{
	$handle = $_SESSION['pending_user_handle'] ?? null;
	unset($_SESSION['pending_user_handle']);

	return $handle === null ? null : base64_decode($handle);
}

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

	'/register/options' => (static function () use ($store): void {
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

			// Don't let the same authenticator enrol twice for this user.
			$excludeCredentials = [];

			foreach ($store->credentialsForUser($handle) as $row) {
				$excludeCredentials[] = new PublicKeyCredentialDescriptor(
					PublicKeyCredentialType::PUBLIC_KEY,
					base64_decode($row['credential_id']),
					$row['transports'],
				);
			}

			$challenge = random_bytes(32);
			rememberChallenge($challenge);
			rememberPendingUser($handle);

			$options = new PublicKeyCredentialCreationOptions(
				rp: new PublicKeyCredentialRpEntity(name: RP_NAME, id: RP_ID),
				user: new PublicKeyCredentialUserEntity($handle, $email, $email),
				challenge: $challenge,
				pubKeyCredParams: [
					new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
					new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::RS256),
					new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::EdDSA),
				],
				excludeCredentials: $excludeCredentials === [] ? null : $excludeCredentials,
				authenticatorSelection: new AuthenticatorSelectionCriteria(
					residentKey: ResidentKeyRequirement::PREFERRED,
					userVerification: UserVerificationRequirement::PREFERRED,
				),
			);

			respond(200, $options->toJson());

		} catch (Throwable $e) {
			respond(400, ['ok' => false, 'message' => $e->getMessage()]);
		}
	})(),

	'/register/verify' => (static function () use ($store, $rp): void {
		try {
			$credential = PublicKeyCredential::fromRegistrationResponseJson(body());
			$challenge = consumeChallenge();
			$handle = consumePendingUser();

			if ($challenge === null || $handle === null) {
				respond(400, ['ok' => false, 'message' => 'No registration in progress — request options first']);

				return;
			}

			$result = $rp->verifyRegistration(
				$credential,
				new RegistrationExpectations(
					challenge: $challenge,
					rpId: RP_ID,
					origins: [ORIGIN],
					allowedAlgorithms: ALLOWED_ALGORITHMS,
					requireUserVerification: false,
				),
				$store,
			);

			$store->insertCredential($result->toCredentialRecord($handle), $credential->authenticatorAttachment);
			signIn($handle);

			$user = $store->findUserByHandle($handle);
			respond(200, ['ok' => true, 'email' => $user['email'] ?? 'unknown']);

		} catch (VerificationException $e) {
			respond(400, ['ok' => false, 'reason' => $e->reason, 'message' => $e->getMessage()]);
		} catch (Throwable $e) {
			respond(400, ['ok' => false, 'message' => $e->getMessage()]);
		}
	})(),

	// ---- Authentication (navigator.credentials.get) ----------------------------------------

	'/login/options' => (static function (): void {
		$challenge = random_bytes(32);
		rememberChallenge($challenge);

		// No allowCredentials: a discoverable passkey identifies the user by its returned userHandle.
		$options = new PublicKeyCredentialRequestOptions(
			challenge: $challenge,
			rpId: RP_ID,
			userVerification: UserVerificationRequirement::PREFERRED,
		);

		respond(200, $options->toJson());
	})(),

	'/login/verify' => (static function () use ($store, $rp): void {
		try {
			$credential = PublicKeyCredential::fromAuthenticationResponseJson(body());
			$challenge = consumeChallenge();

			if ($challenge === null) {
				respond(400, ['ok' => false, 'message' => 'No login in progress — request options first']);

				return;
			}

			$result = $rp->verifyAuthentication(
				$credential,
				new AuthenticationExpectations(
					challenge: $challenge,
					rpId: RP_ID,
					origins: [ORIGIN],
					allowedCredentialIds: null, // usernameless: any of our credentials may answer
					requireUserVerification: false,
					expectedUserHandle: null,   // identify the user from the assertion's userHandle
				),
				$store,
			);

			$store->updateSignCount($result->credentialId, $result->newSignCount);
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
