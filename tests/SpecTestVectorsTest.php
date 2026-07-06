<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Ceremony\AuthenticationExpectations;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Ceremony\RegistrationExpectations;
use WebAuthnX\Ceremony\RegistrationResult;
use WebAuthnX\Ceremony\VerificationException;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Credential\AuthenticatorAttestationResponse;
use WebAuthnX\Credential\PublicKeyCredential;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\RelyingParty;
use WebAuthnXTests\Ceremony\InMemoryCredentialStore;

use function bin2hex;
use function chr;
use function file_get_contents;
use function ord;
use function strlen;
use function substr;

/**
 * Known-answer tests over the official WebAuthn Level 3 §16 test vectors: frozen registration +
 * authentication ceremony pairs published by the spec, walked through {@see RelyingParty} exactly
 * as a relying party would (RP ID `example.org`, origin `https://example.org`).
 *
 * These complement {@see CeremonyEndToEndTest}: that test proves the plumbing composes using
 * live-generated keys, while these vectors are an implementation-independent oracle — fixed
 * bytes we had no hand in producing — and cover deterministic client-data edge cases
 * (`crossOrigin`, `topOrigin`, a maximum-length 1023-byte credential ID) that cannot be
 * frozen with self-generated ECDSA material.
 *
 * Vectors using `none` attestation or `packed` **self** attestation (§16.3) run the full §7.1
 * registration ceremony. Vectors whose `packed` statement carries an `x5c` certificate chain
 * still run the full §7.2 authentication ceremony, but for registration only the parse layer is
 * exercised (plus the check that {@see RelyingParty} refuses the chain rather than skipping the
 * statement) — X.509 trust-path verification is a planned later layer. The spec's TPM / Android
 * Key / Apple / U2F attestation vectors (§16.13–16.16) and the `prf` extension vectors (§16.17)
 * are likewise out of scope here.
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-test-vectors
 */
class SpecTestVectorsTest extends WebAuthnTestCase
{
	private const string RP_ID = 'example.org';
	private const string ORIGIN = 'https://example.org';
	private const string TOP_ORIGIN = 'https://example.com';

	/** The vectors carry no user handle; the relying party assigns one at registration. */
	private const string USER_HANDLE = 'spec-vector-user';

	#[DataProvider('provideVectors')]
	public function testRegistrationThenAuthentication(
		string $fixture,
		int $alg,
		string $fmt = 'none',
		bool $crossOrigin = false,
	): void {
		$vector = self::loadVector($fixture);
		$registration = $vector->getObject('registration');
		$authentication = $vector->getObject('authentication');

		$credentialId = self::hexField($registration, 'credentialId');
		$userHandle = self::USER_HANDLE;
		$store = new InMemoryCredentialStore();
		$relyingParty = new RelyingParty();

		// --- Registration ceremony (§7.1) against the vector's frozen outputs. ---
		$credential = PublicKeyCredential::fromRegistrationResponseJson(self::jsonObject([
			'id' => Base64::urlEncode($credentialId),
			'rawId' => Base64::urlEncode($credentialId),
			'type' => 'public-key',
			'response' => [
				'clientDataJSON' => Base64::urlEncode(self::hexField($registration, 'clientDataJSON')),
				'attestationObject' => Base64::urlEncode(self::hexField($registration, 'attestationObject')),
			],
		]));

		$registrationExpectations = new RegistrationExpectations(
			challenge: self::hexField($registration, 'challenge'),
			rpId: self::RP_ID,
			origins: [self::ORIGIN],
			allowedAlgorithms: [$alg],
			allowCrossOrigin: $crossOrigin,
			allowedTopOrigins: [self::TOP_ORIGIN],
		);

		if ($fmt !== 'packed-x5c') {
			$result = $relyingParty->verifyRegistration($credential, $registrationExpectations, $store);

			self::assertSame(bin2hex($credentialId), bin2hex($result->credentialId));
			self::assertSame(
				bin2hex(self::hexField($registration, 'aaguid')),
				bin2hex($result->aaguid),
			);
			self::assertSame(0, $result->signCount);
			self::assertSame($alg, $result->publicKey->alg);
			self::assertSame(
				$fmt === 'packed-self' ? RegistrationResult::ATTESTATION_SELF : RegistrationResult::ATTESTATION_NONE,
				$result->attestationType,
			);

			$store->add($result->toCredentialRecord($userHandle));

		} else {
			self::registerPackedCredential($relyingParty, $credential, $registrationExpectations, $store, $registration, $alg, $userHandle);
		}

		// --- Authentication ceremony (§7.2) against the vector's frozen assertion. ---
		$signature = self::hexField($authentication, 'signature');
		$assertion = self::assertionCredential($credentialId, $authentication, $signature, $userHandle);

		$authenticationExpectations = new AuthenticationExpectations(
			challenge: self::hexField($authentication, 'challenge'),
			rpId: self::RP_ID,
			origins: [self::ORIGIN],
			allowedCredentialIds: [$credentialId],
			allowCrossOrigin: $crossOrigin,
			allowedTopOrigins: [self::TOP_ORIGIN],
		);

		$result = $relyingParty->verifyAuthentication($assertion, $authenticationExpectations, $store);

		self::assertSame(bin2hex($credentialId), bin2hex($result->credentialId));
		self::assertSame(self::USER_HANDLE, $result->userHandle);
		self::assertSame(0, $result->newSignCount);
		self::assertFalse($result->possibleClone);

		// A single flipped signature byte must fail §7.2 step 21 against the registered key.
		$tamperedBytes = $signature;
		$last = strlen($tamperedBytes) - 1;
		$tamperedBytes = substr($tamperedBytes, 0, $last) . chr(ord($tamperedBytes[$last]) ^ 0x01);
		$tampered = self::assertionCredential(
			$credentialId,
			$authentication,
			$tamperedBytes,
			$userHandle,
		);

		self::assertException(
			VerificationException::class,
			'Assertion signature is invalid',
			static fn () => $relyingParty->verifyAuthentication($tampered, $authenticationExpectations, $store),
		);
	}

	/**
	 * One entry per applicable §16 vector: fixture name, the COSE algorithm the RP offered,
	 * the attestation format the vector uses, and whether its client data is cross-origin.
	 *
	 * @return iterable<string, array{string, int, 2?: string, 3?: bool}>
	 */
	public static function provideVectors(): iterable
	{
		yield '§16.2 none / ES256' => ['none-es256', CoseAlgorithmIdentifier::ES256];
		yield '§16.3 packed self-attestation / ES256' => ['packed-self-es256', CoseAlgorithmIdentifier::ES256, 'packed-self'];
		yield '§16.4 none / ES256, crossOrigin' => ['none-es256-crossorigin', CoseAlgorithmIdentifier::ES256, 'none', true];
		yield '§16.5 none / ES256, topOrigin' => ['none-es256-toporigin', CoseAlgorithmIdentifier::ES256, 'none', true];
		yield '§16.6 none / ES256, 1023-byte credential ID' => ['none-es256-long-credential-id', CoseAlgorithmIdentifier::ES256];
		yield '§16.7 packed / ES256' => ['packed-es256', CoseAlgorithmIdentifier::ES256, 'packed-x5c'];
		yield '§16.8 packed / ES384' => ['packed-es384', CoseAlgorithmIdentifier::ES384, 'packed-x5c'];
		yield '§16.9 packed / ES512' => ['packed-es512', CoseAlgorithmIdentifier::ES512, 'packed-x5c'];
		yield '§16.10 packed / RS256' => ['packed-rs256', CoseAlgorithmIdentifier::RS256, 'packed-x5c'];
		yield '§16.11 packed / EdDSA (Ed25519)' => ['packed-ed25519', CoseAlgorithmIdentifier::EdDSA, 'packed-x5c'];
		yield '§16.12 packed / Ed448' => ['packed-ed448', CoseAlgorithmIdentifier::Ed448, 'packed-x5c'];
	}

	/**
	 * Registers a vector whose `packed` statement carries an `x5c` chain {@see RelyingParty}
	 * cannot verify yet: first proves the façade refuses the chain (fail-closed, §7.1 step 21),
	 * then recovers the attested credential through the parse layer — the same data a
	 * packed-capable relying party would persist — and stores it for the authentication half
	 * of the vector.
	 *
	 * @param  PublicKeyCredential<AuthenticatorAttestationResponse> $credential
	 */
	private static function registerPackedCredential(
		RelyingParty $relyingParty,
		PublicKeyCredential $credential,
		RegistrationExpectations $expectations,
		InMemoryCredentialStore $store,
		JsonObject $registration,
		int $alg,
		string $userHandle,
	): void {
		self::assertException(
			VerificationException::class,
			"Attestation format 'packed' with an x5c certificate chain is not supported",
			static fn () => $relyingParty->verifyRegistration($credential, $expectations, $store),
		);

		$attestationObject = $credential->response->parseAttestationObject();
		self::assertSame('packed', $attestationObject->fmt);

		$authData = $attestationObject->parseAuthenticatorData();
		$attestedCredentialData = $authData->attestedCredentialData;
		self::assertNotNull($attestedCredentialData);

		self::assertSame(
			bin2hex(self::hexField($registration, 'credentialId')),
			bin2hex($attestedCredentialData->credentialId),
		);
		self::assertSame(
			bin2hex(self::hexField($registration, 'aaguid')),
			bin2hex($attestedCredentialData->aaGuid),
		);
		self::assertSame($alg, $attestedCredentialData->credentialPublicKey->alg);

		$store->add(new CredentialRecord(
			credentialId: $attestedCredentialData->credentialId,
			publicKey: $attestedCredentialData->credentialPublicKey,
			signCount: $authData->signCount,
			userHandle: $userHandle,
			uvInitialized: $authData->isUserVerified(),
			backupEligible: $authData->isBackupEligible(),
			backupState: $authData->isBackupState(),
		));
	}

	/**
	 * @return PublicKeyCredential<\WebAuthnX\Credential\AuthenticatorAssertionResponse>
	 */
	private static function assertionCredential(
		string $credentialId,
		JsonObject $authentication,
		string $signature,
		string $userHandle,
	): PublicKeyCredential {
		return PublicKeyCredential::fromAuthenticationResponseJson(self::jsonObject([
			'id' => Base64::urlEncode($credentialId),
			'rawId' => Base64::urlEncode($credentialId),
			'type' => 'public-key',
			'response' => [
				'clientDataJSON' => Base64::urlEncode(self::hexField($authentication, 'clientDataJSON')),
				'authenticatorData' => Base64::urlEncode(self::hexField($authentication, 'authenticatorData')),
				'signature' => Base64::urlEncode($signature),
				'userHandle' => Base64::urlEncode($userHandle),
			],
		]));
	}

	private static function loadVector(string $name): JsonObject
	{
		$content = file_get_contents(__DIR__ . '/SpecVectors/' . $name . '.json');

		if ($content === false) {
			throw new RuntimeException("Missing spec vector fixture {$name}");
		}

		return JsonObject::fromString($content);
	}

	private static function hexField(JsonObject $object, string $field): string
	{
		return self::bytesFromHex($object->getString($field));
	}
}
