<?php declare(strict_types = 1);

namespace WebAuthnXTests\Crypto;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Crypto\SignatureVerificationException;
use WebAuthnX\Crypto\SignatureVerifier;
use WebAuthnXTests\CryptoTestCase;

use function is_string;
use function openssl_error_string;
use function openssl_sign;
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
	}

	public function testThrowsOnUnsupportedAlgorithm(): void
	{
		$key = new class (-8) extends CoseKey {
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
			'Unsupported algorithm -8',
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

	public function testThrowsOnMalformedSignature(): void
	{
		[$coseKey, $privateKey] = self::generateCoseKeyPair(CoseAlgorithmIdentifier::ES256);
		$signature = self::sign($privateKey, self::MESSAGE, CoseAlgorithmIdentifier::ES256);
		$malformed = Bytes::fromBinaryString(substr($signature->toBinaryString(), 0, 5));

		self::assertException(
			SignatureVerificationException::class,
			'Signature verification failed%A',
			fn () => (new SignatureVerifier())->verify($coseKey, self::bytes(self::MESSAGE), $malformed),
		);
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
			default => self::fail("Unsupported test algorithm {$alg}"),
		};
	}

	private static function bytes(string $data): Bytes
	{
		return Bytes::fromBinaryString($data);
	}
}
