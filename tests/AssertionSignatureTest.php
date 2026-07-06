<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use WebAuthnX\Credential\AuthenticatorAssertionResponse;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;

use function hash;
use function is_string;
use function json_encode;
use function openssl_sign;
use function pack;

use const OPENSSL_ALGO_SHA256;

/**
 * Exercises the full authentication-assertion signature check end-to-end
 * (WebAuthn Level 3 §7.2 step 19): the signed message is
 * {@code authenticatorData || SHA-256(clientDataJSON)}.
 */
class AssertionSignatureTest extends CryptoTestCase
{
	public function testVerifiesAssertionSignature(): void
	{
		[$coseKey, $privateKey] = self::generateCoseKeyPair(CoseAlgorithmIdentifier::ES256);

		$rpIdHash = hash('sha256', 'example.com', binary: true);
		$authenticatorData = $rpIdHash . "\x05" . pack('N', 1); // flags = UP | UV, signCount = 1

		$clientDataJson = json_encode([
			'type' => 'webauthn.get',
			'challenge' => Base64::urlEncode('random-challenge'),
			'origin' => 'https://example.com',
		]);
		if (!is_string($clientDataJson)) {
			self::fail('Failed to encode client data JSON');
		}

		$signedData = $authenticatorData . hash('sha256', $clientDataJson, binary: true);
		if (!openssl_sign($signedData, $signature, $privateKey, OPENSSL_ALGO_SHA256) || !is_string($signature)) {
			self::fail('Failed to sign');
		}

		$response = AuthenticatorAssertionResponse::fromJsonObject(self::jsonObject([
			'clientDataJSON' => Base64::urlEncode($clientDataJson),
			'authenticatorData' => Base64::urlEncode($authenticatorData),
			'signature' => Base64::urlEncode($signature),
		]));

		// Reconstruct the signed message the way a relying party would.
		$message = $response->authenticatorData
			. hash('sha256', $response->clientDataJSON, binary: true);

		self::assertTrue($coseKey->verify($message, $response->signature));
	}
}
