<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Cose;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Cose\CoseEc2Key;
use ShipMonk\Passkeys\Cose\CoseKey;
use ShipMonk\Passkeys\Cose\CoseKeyException;
use ShipMonk\Passkeys\Cose\CoseOkpKey;
use ShipMonk\Passkeys\Cose\CoseRsaKey;
use ShipMonk\PasskeysTests\CryptoTestCase;
use function bin2hex;
use function str_pad;

#[CoversClass(CoseKey::class)]
#[CoversClass(CoseEc2Key::class)]
#[CoversClass(CoseOkpKey::class)]
#[CoversClass(CoseRsaKey::class)]
final class CoseKeyTest extends CryptoTestCase
{

    /**
     * The DER SubjectPublicKeyInfo we build from a COSE key must be byte-for-byte
     * identical to what OpenSSL emits for the same key.
     *
     * @param CoseAlgorithmIdentifier::* $alg
     * @param class-string<CoseKey>      $expectedClass
     */
    #[DataProvider('provideAlgorithms')]
    public function testSubjectPublicKeyInfoMatchesOpenssl(
        int $alg,
        string $expectedClass,
    ): void
    {
        [$coseKey, $privateKey] = self::generateCoseKeyPair($alg);

        self::assertInstanceOf($expectedClass, $coseKey);
        self::assertSame(
            bin2hex(self::pemToDer(self::stringField(self::keyDetails($privateKey), 'key'))),
            bin2hex($coseKey->toDerSubjectPublicKeyInfo()),
        );
    }

    /**
     * @return iterable<string, array{CoseAlgorithmIdentifier::*, class-string<CoseKey>}>
     */
    public static function provideAlgorithms(): iterable
    {
        yield 'P-256 / ES256' => [CoseAlgorithmIdentifier::ES256, CoseEc2Key::class];
        yield 'P-384 / ES384' => [CoseAlgorithmIdentifier::ES384, CoseEc2Key::class];
        yield 'P-521 / ES512' => [CoseAlgorithmIdentifier::ES512, CoseEc2Key::class];
        yield 'RSA / RS256' => [CoseAlgorithmIdentifier::RS256, CoseRsaKey::class];
        yield 'Ed25519 / EdDSA' => [CoseAlgorithmIdentifier::EdDSA, CoseOkpKey::class];
        yield 'Ed448' => [CoseAlgorithmIdentifier::Ed448, CoseOkpKey::class];
    }

    /**
     * Fixed vector (independent of the OpenSSL oracle): the RFC 8032 §7.1 Test 1
     * public key must encode to the exact RFC 8410 §4 Ed25519 SubjectPublicKeyInfo.
     */
    public function testEd25519SubjectPublicKeyInfoKnownAnswer(): void
    {
        $publicKey = self::bytesFromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');

        $coseKey = CoseKey::fromCborMap(self::cborMap([
            1 => CoseOkpKey::KTY,
            3 => CoseAlgorithmIdentifier::EdDSA,
            -1 => CoseOkpKey::CRV_ED25519,
            -2 => $publicKey,
        ]));

        self::assertSame(
            '302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
            bin2hex($coseKey->toDerSubjectPublicKeyInfo()),
        );
    }

    /**
     * {@see CoseKey::toBytes()} then {@see CoseKey::fromBytes()} must reconstruct an equivalent key
     * (same type, same key material) and re-encode to the same bytes — this is the round-trip a
     * relying party relies on to persist and later load a credential's public key.
     *
     * @param CoseAlgorithmIdentifier::* $alg
     * @param class-string<CoseKey>      $expectedClass
     */
    #[DataProvider('provideAlgorithms')]
    public function testToBytesRoundTrips(
        int $alg,
        string $expectedClass,
    ): void
    {
        [$coseKey] = self::generateCoseKeyPair($alg);

        $restored = CoseKey::fromBytes($coseKey->toBytes());

        self::assertInstanceOf($expectedClass, $restored);
        self::assertSame(
            bin2hex($coseKey->toDerSubjectPublicKeyInfo()),
            bin2hex($restored->toDerSubjectPublicKeyInfo()),
        );
        self::assertSame(
            bin2hex($coseKey->toBytes()),
            bin2hex($restored->toBytes()),
        );
    }

    public function testFromBytesRejectsMalformedCbor(): void
    {
        self::assertException(
            CoseKeyException::class,
            'Malformed COSE key',
            static fn () => CoseKey::fromBytes(self::bytesFromHex('ff')),
        );
    }

    public function testFromBytesRejectsTrailingBytes(): void
    {
        [$coseKey] = self::generateCoseKeyPair(CoseAlgorithmIdentifier::ES256);
        $withTrailingByte = $coseKey->toBytes() . "\x00";

        self::assertException(
            CoseKeyException::class,
            'Malformed COSE key',
            static fn () => CoseKey::fromBytes($withTrailingByte),
        );
    }

    /**
     * @param array<int, int|string> $entries
     */
    #[DataProvider('provideInvalidKeys')]
    public function testFromCborMapRejectsInvalidKeys(
        string $expectedMessage,
        array $entries,
    ): void
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

        yield 'EC2 wrong x length' => [
            'EC2 curve 1 requires 32-byte coordinates',
            [1 => CoseEc2Key::KTY, 3 => CoseAlgorithmIdentifier::ES256, -1 => CoseEc2Key::CRV_P256, -2 => 'short', -3 => $y],
        ];

        yield 'EC2 wrong y length' => [
            'EC2 curve 1 requires 32-byte coordinates',
            [1 => CoseEc2Key::KTY, 3 => CoseAlgorithmIdentifier::ES256, -1 => CoseEc2Key::CRV_P256, -2 => $x, -3 => 'short'],
        ];

        $rsaModulus = str_pad('', 256, "\x01");

        yield 'unsupported RSA algorithm' => [
            'Unsupported RSA algorithm -7',
            [1 => CoseRsaKey::KTY, 3 => CoseAlgorithmIdentifier::ES256, -1 => $rsaModulus, -2 => "\x01\x00\x01"],
        ];

        yield 'RSA modulus too small' => [
            'RSA modulus must be at least 2048 bits',
            [1 => CoseRsaKey::KTY, 3 => CoseAlgorithmIdentifier::RS256, -1 => str_pad('', 128, "\x01"), -2 => "\x01\x00\x01"],
        ];

        yield 'RSA exponent of one (forgeable)' => [
            'RSA public exponent must be an odd integer greater than 1',
            [1 => CoseRsaKey::KTY, 3 => CoseAlgorithmIdentifier::RS256, -1 => $rsaModulus, -2 => "\x01"],
        ];

        yield 'RSA even exponent' => [
            'RSA public exponent must be an odd integer greater than 1',
            [1 => CoseRsaKey::KTY, 3 => CoseAlgorithmIdentifier::RS256, -1 => $rsaModulus, -2 => "\x02"],
        ];

        yield 'RSA empty exponent' => [
            'RSA public exponent must be an odd integer greater than 1',
            [1 => CoseRsaKey::KTY, 3 => CoseAlgorithmIdentifier::RS256, -1 => $rsaModulus, -2 => ''],
        ];

        yield 'unsupported OKP algorithm' => [
            'Unsupported OKP algorithm -7',
            [1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::ES256, -1 => CoseOkpKey::CRV_ED25519, -2 => $x],
        ];

        yield 'unsupported OKP curve' => [
            'OKP algorithm -8 does not allow curve 99',
            [1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::EdDSA, -1 => 99, -2 => $x],
        ];

        yield 'OKP fully-specified algorithm / curve mismatch' => [
            'OKP algorithm -53 does not allow curve 6',
            [1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::Ed448, -1 => CoseOkpKey::CRV_ED25519, -2 => $x],
        ];

        yield 'OKP generic EdDSA with Ed448 curve (WebAuthn §5.8.5 requires Ed25519)' => [
            'OKP algorithm -8 does not allow curve 7',
            [1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::EdDSA, -1 => CoseOkpKey::CRV_ED448, -2 => $x],
        ];

        yield 'OKP wrong Ed25519 key length' => [
            'OKP curve 6 requires 32-byte public key',
            [1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::EdDSA, -1 => CoseOkpKey::CRV_ED25519, -2 => 'short'],
        ];

        yield 'OKP wrong Ed448 key length' => [
            'OKP curve 7 requires 57-byte public key',
            [1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::Ed448, -1 => CoseOkpKey::CRV_ED448, -2 => $x],
        ];
    }

}
