<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use PHPUnit\Framework\Attributes\DataProvider;
use WebAuthnX\Credential\AuthenticatorAttestationResponse;
use WebAuthnX\Credential\AuthenticatorData;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseOkpKey;
use WebAuthnX\Crypto\Hash;
use WebAuthnX\Crypto\SignatureVerifier;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\Credential\PublicKeyCredential;

use function chr;
use function hash;
use function json_encode;
use function ord;
use function pack;
use function str_repeat;
use function strlen;

use const JSON_THROW_ON_ERROR;

/**
 * Acceptance test that walks a full WebAuthn ceremony for every supported algorithm using
 * real cryptographic material: an authenticator's outputs are assembled into spec-shaped,
 * browser-style JSON, fed through the public parsers, and the resulting COSE key + assertion
 * are checked with {@see SignatureVerifier} exactly as a relying party would (§7.2 step 19).
 *
 * Unlike the unit tests it exercises no piece in isolation — it proves the whole plumbing
 * composes: base64url boundaries, the CBOR/COSE decode inside attested credential data, the
 * generic {@see PublicKeyCredential} wrapper, and the signed-message reconstruction. Signatures
 * are produced live rather than frozen because ECDSA output is non-deterministic; the fixed,
 * independent oracles are the RFC 8032 Ed25519 known-answer vector in the crypto tests and
 * the official WebAuthn §16 test vectors in {@see SpecTestVectorsTest}.
 */
class CeremonyEndToEndTest extends CryptoTestCase
{
	private const string RP_ID = 'example.com';
	private const string CREDENTIAL_ID = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a";

	#[DataProvider('provideAlgorithms')]
	public function testRegistrationThenAuthentication(int $alg, int $okpCrv = CoseOkpKey::CRV_ED25519): void
	{
		[$privateKey, $coseEntries] = self::generateKeyAndCoseEntries($alg, $okpCrv);
		$rpIdHash = hash('sha256', self::RP_ID, binary: true);

		// --- Registration ceremony: parse the attestation and recover the credential public key. ---
		$registration = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
			'id' => Base64::urlEncode(self::CREDENTIAL_ID),
			'rawId' => Base64::urlEncode(self::CREDENTIAL_ID),
			'type' => 'public-key',
			'response' => [
				'clientDataJSON' => Base64::urlEncode(self::clientDataJson('webauthn.create')),
				'attestationObject' => Base64::urlEncode(self::attestationObject($rpIdHash, $coseEntries)),
				'transports' => ['internal'],
			],
		], JSON_THROW_ON_ERROR)));

		$attestationResponse = $registration->response;
		self::assertInstanceOf(AuthenticatorAttestationResponse::class, $attestationResponse);
		self::assertSame(['internal'], $attestationResponse->transports);

		$registeredKey = $attestationResponse
			->parseAttestationObject()
			->parseAuthenticatorData()
			->attestedCredentialData
			?->credentialPublicKey;

		self::assertNotNull($registeredKey);
		self::assertSame($alg, $registeredKey->alg);

		// --- Authentication ceremony: sign over authenticatorData || SHA-256(clientDataJSON). ---
		$assertionAuthData = $rpIdHash
			. chr(AuthenticatorData::FLAG_USER_PRESENT | AuthenticatorData::FLAG_USER_VERIFIED)
			. pack('N', 1);
		$assertionClientData = self::clientDataJson('webauthn.get');
		$signature = self::sign($privateKey, $assertionAuthData . hash('sha256', $assertionClientData, binary: true), $alg);

		$authentication = PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString(json_encode([
			'id' => Base64::urlEncode(self::CREDENTIAL_ID),
			'rawId' => Base64::urlEncode(self::CREDENTIAL_ID),
			'type' => 'public-key',
			'response' => [
				'clientDataJSON' => Base64::urlEncode($assertionClientData),
				'authenticatorData' => Base64::urlEncode($assertionAuthData),
				'signature' => Base64::urlEncode($signature),
				'userHandle' => Base64::urlEncode('user-handle'),
			],
		], JSON_THROW_ON_ERROR)));

		$assertionResponse = $authentication->response;
		$message = $assertionResponse->authenticatorData
			. Hash::sha256($assertionResponse->clientDataJSON);

		$verifier = new SignatureVerifier();
		self::assertTrue($verifier->verify($registeredKey, $message, $assertionResponse->signature));

		// A single flipped signature byte must not verify against the registered key.
		$tampered = $assertionResponse->signature;
		$tampered[0] = chr(ord($tampered[0]) ^ 0x01);
		self::assertFalse($verifier->verify($registeredKey, $message, $tampered));
	}

	/**
	 * @return iterable<string, array{int, 1?: int}>
	 */
	public static function provideAlgorithms(): iterable
	{
		yield 'ES256' => [CoseAlgorithmIdentifier::ES256];
		yield 'ES384' => [CoseAlgorithmIdentifier::ES384];
		yield 'ES512' => [CoseAlgorithmIdentifier::ES512];
		yield 'RS256' => [CoseAlgorithmIdentifier::RS256];
		yield 'EdDSA / Ed25519' => [CoseAlgorithmIdentifier::EdDSA, CoseOkpKey::CRV_ED25519];
		yield 'EdDSA / Ed448' => [CoseAlgorithmIdentifier::EdDSA, CoseOkpKey::CRV_ED448];
		yield 'Ed25519' => [CoseAlgorithmIdentifier::Ed25519];
		yield 'Ed448' => [CoseAlgorithmIdentifier::Ed448];
	}

	/**
	 * Builds a `none`-format attestation object whose authenticator data carries attested
	 * credential data (AT flag) for the given COSE public key.
	 *
	 * @param  array<int, int|string> $coseEntries
	 */
	private static function attestationObject(string $rpIdHash, array $coseEntries): string
	{
		$attestedCredentialData = str_repeat("\x00", 16) // AAGUID
			. pack('n', strlen(self::CREDENTIAL_ID))
			. self::CREDENTIAL_ID
			. CborTestEncoder::intMap($coseEntries);

		$flags = AuthenticatorData::FLAG_USER_PRESENT
			| AuthenticatorData::FLAG_USER_VERIFIED
			| AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA;

		$authData = $rpIdHash . chr($flags) . pack('N', 0) . $attestedCredentialData;

		return CborTestEncoder::map([
			[CborTestEncoder::textString('fmt'), CborTestEncoder::textString('none')],
			[CborTestEncoder::textString('attStmt'), CborTestEncoder::map([])],
			[CborTestEncoder::textString('authData'), CborTestEncoder::byteString($authData)],
		]);
	}

	private static function clientDataJson(string $type): string
	{
		return json_encode([
			'type' => $type,
			'challenge' => Base64::urlEncode('a-fixed-challenge'),
			'origin' => 'https://' . self::RP_ID,
		], JSON_THROW_ON_ERROR);
	}
}
