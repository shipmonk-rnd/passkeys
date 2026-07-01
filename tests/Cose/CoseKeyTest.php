<?php declare(strict_types = 1);

namespace WebAuthnXTests\Cose;

use PHPUnit\Framework\Attributes\DataProvider;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseEc2Key;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Cose\CoseKeyException;
use WebAuthnX\Cose\CoseOkpKey;
use WebAuthnX\Cose\CoseRsaKey;
use WebAuthnXTests\CryptoTestCase;

use function bin2hex;
use function str_pad;

class CoseKeyTest extends CryptoTestCase
{
	/**
	 * The DER SubjectPublicKeyInfo we build from a COSE key must be byte-for-byte
	 * identical to what OpenSSL emits for the same key.
	 *
	 * @param  class-string<CoseKey> $expectedClass
	 */
	#[DataProvider('provideAlgorithms')]
	public function testSubjectPublicKeyInfoMatchesOpenssl(int $alg, string $expectedClass): void
	{
		[$coseKey, $privateKey] = self::generateCoseKeyPair($alg);

		self::assertInstanceOf($expectedClass, $coseKey);
		self::assertSame(
			bin2hex(self::pemToDer(self::stringField(self::keyDetails($privateKey), 'key'))),
			bin2hex($coseKey->toDerSubjectPublicKeyInfo()->toBinaryString()),
		);
	}

	/**
	 * @return iterable<string, array{int, class-string<CoseKey>}>
	 */
	public static function provideAlgorithms(): iterable
	{
		yield 'P-256 / ES256' => [CoseAlgorithmIdentifier::ES256, CoseEc2Key::class];
		yield 'P-384 / ES384' => [CoseAlgorithmIdentifier::ES384, CoseEc2Key::class];
		yield 'P-521 / ES512' => [CoseAlgorithmIdentifier::ES512, CoseEc2Key::class];
		yield 'RSA / RS256' => [CoseAlgorithmIdentifier::RS256, CoseRsaKey::class];
		yield 'Ed25519 / EdDSA' => [CoseAlgorithmIdentifier::EdDSA, CoseOkpKey::class];
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

		yield 'unsupported OKP algorithm' => [
			'Unsupported OKP algorithm -7',
			[1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::ES256, -1 => CoseOkpKey::CRV_ED25519, -2 => $x],
		];

		yield 'OKP curve mismatch' => [
			'OKP algorithm -8 requires curve 6, got 99',
			[1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::EdDSA, -1 => 99, -2 => $x],
		];

		yield 'OKP wrong key length' => [
			'OKP curve 6 requires 32-byte public key',
			[1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::EdDSA, -1 => CoseOkpKey::CRV_ED25519, -2 => 'short'],
		];
	}
}
