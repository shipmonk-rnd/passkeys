<?php declare(strict_types = 1);

/**
 * A minimal, single-file relying party demonstrating the full WebAuthnX passkey flow end to end.
 *
 * Run it with PHP's built-in server from the project root:
 *
 *     php -S localhost:8000 example/server.php
 *
 * then open http://localhost:8000 and register + log in with a passkey. The RP id / origin below
 * assume exactly that host and port; change them together if you serve it elsewhere.
 *
 * This is intentionally tiny and NOT production code: it has one demo user, keeps state in a JSON
 * file (example/.data/), and relaxes user-verification. It exists to show how the library's pieces
 * fit together, not how to run a real service.
 */

namespace WebAuthnXDemo;

use Throwable;
use WebAuthnX\Binary\Bytes;
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
use WebAuthnX\Options\PublicKeyCredentialParameters;
use WebAuthnX\Options\PublicKeyCredentialRequestOptions;
use WebAuthnX\Options\PublicKeyCredentialRpEntity;
use WebAuthnX\Options\PublicKeyCredentialUserEntity;
use WebAuthnX\RelyingParty;

use function file_get_contents;
use function header;
use function http_response_code;
use function json_encode;
use function parse_url;
use function random_bytes;

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

$store = new PasskeyStore(__DIR__ . '/.data');
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

match ($path) {
	'/' => (static function (): void {
		header('Content-Type: text/html; charset=utf-8');
		echo file_get_contents(__DIR__ . '/index.html');
	})(),

	// ---- Registration (navigator.credentials.create) ---------------------------------------

	'/register/options' => (static function () use ($store): void {
		$user = $store->user();

		if ($user === null) {
			$handle = Bytes::fromBinaryString(random_bytes(16));
			$store->setUser($handle, 'demo@example.com');
		} else {
			$handle = Bytes::fromBinaryString(PasskeyStore::b64UrlDecode($user['handle']));
		}

		$challenge = Bytes::fromBinaryString(random_bytes(32));
		$store->rememberChallenge($challenge);

		$options = new PublicKeyCredentialCreationOptions(
			rp: new PublicKeyCredentialRpEntity(name: RP_NAME, id: RP_ID),
			user: new PublicKeyCredentialUserEntity($handle, 'demo@example.com', 'Demo User'),
			challenge: $challenge,
			pubKeyCredParams: [
				new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
				new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::RS256),
				new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::EdDSA),
			],
			authenticatorSelection: new AuthenticatorSelectionCriteria(
				residentKey: ResidentKeyRequirement::PREFERRED,
				userVerification: UserVerificationRequirement::PREFERRED,
			),
		);

		respond(200, $options->toJson());
	})(),

	'/register/verify' => (static function () use ($store, $rp): void {
		try {
			$credential = PublicKeyCredential::fromRegistrationResponseJson(body());
			$challenge = $store->consumeChallenge();

			if ($challenge === null) {
				respond(400, ['ok' => false, 'message' => 'No pending challenge — request options first']);

				return;
			}

			$result = $rp->verifyRegistration(
				$credential,
				new RegistrationExpectations(
					challenge: $challenge,
					rpId: RP_ID,
					origins: [ORIGIN],
					allowedAlgorithms: ALLOWED_ALGORITHMS,
					// A real RP handling sensitive data should require UV; relaxed here for compatibility.
					requireUserVerification: false,
				),
				$store,
			);

			$user = $store->user() ?? throw new VerificationException(
				VerificationException::UNKNOWN_CREDENTIAL,
				'User vanished mid-ceremony',
			);
			$store->save($result->toCredentialRecord(Bytes::fromBinaryString(PasskeyStore::b64UrlDecode($user['handle']))), $credential->response->attestationObject);

			respond(200, ['ok' => true, 'message' => 'Passkey registered. You can now log in.']);

		} catch (VerificationException $e) {
			respond(400, ['ok' => false, 'reason' => $e->reason, 'message' => $e->getMessage()]);
		} catch (Throwable $e) {
			respond(400, ['ok' => false, 'message' => $e->getMessage()]);
		}
	})(),

	// ---- Authentication (navigator.credentials.get) ----------------------------------------

	'/login/options' => (static function () use ($store): void {
		$challenge = Bytes::fromBinaryString(random_bytes(32));
		$store->rememberChallenge($challenge);

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
			$challenge = $store->consumeChallenge();

			if ($challenge === null) {
				respond(400, ['ok' => false, 'message' => 'No pending challenge — request options first']);

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

			respond(200, [
				'ok' => true,
				'user' => $store->userNameForHandle($result->userHandle) ?? 'unknown',
				'signCount' => $result->newSignCount,
				'userVerified' => $result->userVerified,
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
