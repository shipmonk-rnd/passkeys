<?php declare(strict_types = 1);

namespace WebAuthnXTests\Crypto;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Cose\CoseOkpKey;
use WebAuthnX\Crypto\SignatureVerificationException;
use WebAuthnX\Crypto\SignatureVerifier;
use WebAuthnXTests\CryptoTestCase;

use function chr;
use function is_string;
use function openssl_error_string;
use function openssl_sign;
use function ord;
use function substr;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;

class SignatureVerifierTest extends CryptoTestCase
{
	private const MESSAGE = 'authenticatorData||clientDataHash ' . '0123456789abcdef';

	#[DataProvider('provideAlgorithms')]
	public function testVerifiesValidSignature(int $alg): void
	{
		[$coseKey, $privateKey] = self::generateCoseKeyPair($alg);
		$signature = self::sign($privateKey, self::MESSAGE, $alg);

		self::assertTrue(
			(new SignatureVerifier())->verify($coseKey, self::bytes(self::MESSAGE), $signature),
		);
	}

	#[DataProvider('provideAlgorithms')]
	public function testRejectsSignatureOverDifferentData(int $alg): void
	{
		[$coseKey, $privateKey] = self::generateCoseKeyPair($alg);
		$signature = self::sign($privateKey, self::MESSAGE, $alg);

		self::assertFalse(
			(new SignatureVerifier())->verify($coseKey, self::bytes(self::MESSAGE . '!'), $signature),
		);
	}

	#[DataProvider('provideAlgorithms')]
	public function testRejectsSignatureFromDifferentKey(int $alg): void
	{
		[, $privateKey] = self::generateCoseKeyPair($alg);
		[$otherCoseKey] = self::generateCoseKeyPair($alg);
		$signature = self::sign($privateKey, self::MESSAGE, $alg);

		self::assertFalse(
			(new SignatureVerifier())->verify($otherCoseKey, self::bytes(self::MESSAGE), $signature),
		);
	}

	/**
	 * @return iterable<string, array{int}>
	 */
	public static function provideAlgorithms(): iterable
	{
		yield 'ES256' => [CoseAlgorithmIdentifier::ES256];
		yield 'ES384' => [CoseAlgorithmIdentifier::ES384];
		yield 'ES512' => [CoseAlgorithmIdentifier::ES512];
		yield 'RS256' => [CoseAlgorithmIdentifier::RS256];
		yield 'EdDSA' => [CoseAlgorithmIdentifier::EdDSA];
	}

	public function testThrowsOnUnsupportedAlgorithm(): void
	{
		$key = new class (9999) extends CoseKey {
			public function __construct(int $alg)
			{
				parent::__construct($alg);
			}

			public function toDerSubjectPublicKeyInfo(): Bytes
			{
				return Bytes::fromBinaryString('');
			}
		};

		self::assertException(
			SignatureVerificationException::class,
			'Unsupported algorithm 9999',
			static fn () => (new SignatureVerifier())->verify($key, self::bytes('x'), self::bytes('y')),
		);
	}

	public function testThrowsWhenPublicKeyCannotBeLoaded(): void
	{
		$key = new class (CoseAlgorithmIdentifier::ES256) extends CoseKey {
			public function __construct(int $alg)
			{
				parent::__construct($alg);
			}

			public function toDerSubjectPublicKeyInfo(): Bytes
			{
				return Bytes::fromBinaryString("\x00\x01\x02");
			}
		};

		self::assertException(
			SignatureVerificationException::class,
			'Failed to load public key%A',
			static fn () => (new SignatureVerifier())->verify($key, self::bytes('x'), self::bytes('y')),
		);
	}

	/**
	 * A malformed signature is a verification failure (false), never an exception —
	 * regardless of whether OpenSSL reports it as 0 (RSA/EdDSA) or -1 (ECDSA DER parse).
	 */
	#[DataProvider('provideAlgorithms')]
	public function testRejectsMalformedSignature(int $alg): void
	{
		[$coseKey, $privateKey] = self::generateCoseKeyPair($alg);
		$signature = self::sign($privateKey, self::MESSAGE, $alg);
		$malformed = Bytes::fromBinaryString(substr($signature->toBinaryString(), 0, 5));

		self::assertFalse(
			(new SignatureVerifier())->verify($coseKey, self::bytes(self::MESSAGE), $malformed),
		);
	}

	/**
	 * Known-answer vector from RFC 8032 §7.1 (Ed25519, Test 1): a fixed public key,
	 * empty message, and fixed 64-byte signature not produced by our own code path.
	 */
	public function testVerifiesEd25519KnownAnswerVector(): void
	{
		$publicKey = self::bytesFromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
		$signature = self::bytesFromHex(
			'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
			. '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
		);

		$coseKey = CoseKey::fromCborMap(self::cborMap([
			1 => CoseOkpKey::KTY,
			3 => CoseAlgorithmIdentifier::EdDSA,
			-1 => CoseOkpKey::CRV_ED25519,
			-2 => $publicKey->toBinaryString(),
		]));

		$verifier = new SignatureVerifier();
		self::assertTrue($verifier->verify($coseKey, self::bytes(''), $signature));

		$tampered = $signature->toBinaryString();
		$tampered[0] = chr(ord($tampered[0]) ^ 0x01);
		self::assertFalse($verifier->verify($coseKey, self::bytes(''), Bytes::fromBinaryString($tampered)));
	}

	private static function sign(OpenSSLAsymmetricKey $privateKey, string $message, int $alg): Bytes
	{
		if (!openssl_sign($message, $signature, $privateKey, self::opensslDigest($alg)) || !is_string($signature)) {
			self::fail('Failed to sign: ' . openssl_error_string());
		}

		return Bytes::fromBinaryString($signature);
	}

	private static function opensslDigest(int $alg): int
	{
		return match ($alg) {
			CoseAlgorithmIdentifier::ES256, CoseAlgorithmIdentifier::RS256 => OPENSSL_ALGO_SHA256,
			CoseAlgorithmIdentifier::ES384 => OPENSSL_ALGO_SHA384,
			CoseAlgorithmIdentifier::ES512 => OPENSSL_ALGO_SHA512,
			CoseAlgorithmIdentifier::EdDSA => 0, // EdDSA is a pure signature scheme (no prehash)
			default => self::fail("Unsupported test algorithm {$alg}"),
		};
	}

	private static function bytes(string $data): Bytes
	{
		return Bytes::fromBinaryString($data);
	}
}
