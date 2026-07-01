<?php declare(strict_types = 1);

namespace WebAuthnXTests\Cose;

use PHPUnit\Framework\Attributes\DataProvider;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseEc2Key;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Cose\CoseKeyException;
use WebAuthnX\Cose\CoseRsaKey;
use WebAuthnXTests\CryptoTestCase;

use function bin2hex;
use function str_pad;

class CoseKeyTest extends CryptoTestCase
{
	/**
	 * The DER SubjectPublicKeyInfo we build from a COSE EC2 key must be byte-for-byte
	 * identical to what OpenSSL emits for the same key.
	 */
	#[DataProvider('provideEc2Algorithms')]
	public function testEc2SubjectPublicKeyInfoMatchesOpenssl(int $alg): void
	{
		[$coseKey, $privateKey] = self::generateCoseKeyPair($alg);

		self::assertInstanceOf(CoseEc2Key::class, $coseKey);
		self::assertSame(
			bin2hex(self::pemToDer(self::stringField(self::keyDetails($privateKey), 'key'))),
			bin2hex($coseKey->toDerSubjectPublicKeyInfo()->toBinaryString()),
		);
	}

	/**
	 * @return iterable<string, array{int}>
	 */
	public static function provideEc2Algorithms(): iterable
	{
		yield 'P-256 / ES256' => [CoseAlgorithmIdentifier::ES256];
		yield 'P-384 / ES384' => [CoseAlgorithmIdentifier::ES384];
		yield 'P-521 / ES512' => [CoseAlgorithmIdentifier::ES512];
	}

	public function testRsaSubjectPublicKeyInfoMatchesOpenssl(): void
	{
		[$coseKey, $privateKey] = self::generateCoseKeyPair(CoseAlgorithmIdentifier::RS256);

		self::assertInstanceOf(CoseRsaKey::class, $coseKey);
		self::assertSame(
			bin2hex(self::pemToDer(self::stringField(self::keyDetails($privateKey), 'key'))),
			bin2hex($coseKey->toDerSubjectPublicKeyInfo()->toBinaryString()),
		);
	}

	/**
	 * @param  array<int, int|string> $entries
	 */
	#[DataProvider('provideInvalidKeys')]
	public function testFromCborMapRejectsInvalidKeys(string $expectedMessage, array $entries): void
	{
		self::assertException(
			CoseKeyException::class,
			$expectedMessage,
			static fn () => CoseKey::fromCborMap(self::cborMap($entries)),
		);
	}

	/**
	 * @return iterable<string, array{string, array<int, int|string>}>
	 */
	public static function provideInvalidKeys(): iterable
	{
		$x = str_pad('', 32, "\x01");
		$y = str_pad('', 32, "\x02");

		yield 'unsupported key type' => [
			'Unsupported COSE key type 99',
			[1 => 99, 3 => CoseAlgorithmIdentifier::ES256],
		];

		yield 'unsupported EC2 algorithm' => [
			'Unsupported EC2 algorithm -999',
			[1 => CoseEc2Key::KTY, 3 => -999, -1 => CoseEc2Key::CRV_P256, -2 => $x, -3 => $y],
		];

		yield 'EC2 curve mismatch' => [
			'EC2 algorithm -7 requires curve 1, got 2',
			[1 => CoseEc2Key::KTY, 3 => CoseAlgorithmIdentifier::ES256, -1 => CoseEc2Key::CRV_P384, -2 => $x, -3 => $y],
		];

		yield 'EC2 wrong coordinate length' => [
			'EC2 curve 1 requires 32-byte coordinates',
			[1 => CoseEc2Key::KTY, 3 => CoseAlgorithmIdentifier::ES256, -1 => CoseEc2Key::CRV_P256, -2 => 'short', -3 => $y],
		];

		yield 'unsupported RSA algorithm' => [
			'Unsupported RSA algorithm -7',
			[1 => CoseRsaKey::KTY, 3 => CoseAlgorithmIdentifier::ES256, -1 => str_pad('', 256, "\x01"), -2 => "\x01\x00\x01"],
		];

		yield 'empty RSA modulus' => [
			'RSA modulus and exponent must not be empty',
			[1 => CoseRsaKey::KTY, 3 => CoseAlgorithmIdentifier::RS256, -1 => '', -2 => "\x01\x00\x01"],
		];
	}
}
