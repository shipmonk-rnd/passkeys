<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Cose;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Cose\CoseEc2Key;
use ShipMonk\Passkeys\Cose\CoseKey;
use ShipMonk\Passkeys\Cose\CoseKeyException;
use ShipMonk\Passkeys\Cose\CoseOkpKey;
use ShipMonk\PasskeysTests\Cbor\CborTestEncoder;
use ShipMonk\PasskeysTests\CryptoTestCase;
use function chr;
use function openssl_error_string;
use function openssl_pkey_get_public;
use function ord;
use function str_repeat;
use function strlen;

#[CoversClass(CoseKey::class)]
#[CoversClass(CoseEc2Key::class)]
#[CoversClass(CoseOkpKey::class)]
final class CoseKeyMaterialTest extends CryptoTestCase
{

    // P-256 generator coordinates from SEC 2 v2 §2.4.2.
    private const P256_BASE_POINT_X = '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296';
    private const P256_BASE_POINT_Y = '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';

    /**
     * Both enrollment's map import and stored-key deserialization must reject these keys.
     *
     * @param array<int, int|string> $entries
     */
    #[DataProvider('provideRejectedKeyMaterial')]
    public function testRejectsKeyMaterial(
        string $message,
        array $entries,
    ): void
    {
        self::assertException(CoseKeyException::class, $message, static fn () => CoseKey::fromCborMap(self::cborMap($entries)));
        self::assertException(CoseKeyException::class, $message, static fn () => CoseKey::fromBytes(CborTestEncoder::intMap($entries)));
    }

    /**
     * @param array<int, int|string> $entries
     */
    #[DataProvider('provideRejectedEcPoints')]
    public function testRejectsOffCurveEcPoints(
        string $message,
        array $entries,
    ): void
    {
        self::assertException(CoseKeyException::class, $message, static fn () => CoseKey::fromCborMap(self::cborMap($entries)));
        self::assertException(CoseKeyException::class, $message, static fn () => CoseKey::fromBytes(CborTestEncoder::intMap($entries)));
        self::assertFalse(openssl_error_string());
    }

    public function testEcImportClearsStaleOpenSslErrors(): void
    {
        self::assertFalse(openssl_pkey_get_public('not a key at all'));

        CoseEc2Key::fromCborMap(self::cborMap([
            1 => CoseEc2Key::KTY,
            3 => CoseAlgorithmIdentifier::ES256,
            -1 => CoseEc2Key::CRV_P256,
            -2 => self::bytesFromHex(self::P256_BASE_POINT_X),
            -3 => self::bytesFromHex(self::P256_BASE_POINT_Y),
        ]));

        self::assertFalse(openssl_error_string());
    }

    public function testEcImportDoesNotReportStaleOpenSslErrors(): void
    {
        $map = self::cborMap([
            1 => CoseEc2Key::KTY,
            3 => CoseAlgorithmIdentifier::ES256,
            -1 => CoseEc2Key::CRV_P256,
            -2 => str_repeat("\x00", 32),
            -3 => str_repeat("\x00", 32),
        ]);

        try {
            CoseEc2Key::fromCborMap($map);
            self::fail('Expected an invalid public point');

        } catch (CoseKeyException $e) {
            $message = $e->getMessage();
        }

        self::assertFalse(openssl_pkey_get_public('not a key at all'));

        try {
            CoseEc2Key::fromCborMap($map);
            self::fail('Expected an invalid public point');

        } catch (CoseKeyException $e) {
            self::assertSame($message, $e->getMessage());
        }

        self::assertFalse(openssl_error_string());
    }

    public function testAcceptsGeneratedEcPoints(): void
    {
        foreach ([CoseAlgorithmIdentifier::ES256, CoseAlgorithmIdentifier::ES384, CoseAlgorithmIdentifier::ES512] as $alg) {
            [$key, $privateKey] = self::generateCoseKeyPair($alg);
            self::assertInstanceOf(CoseEc2Key::class, $key);
            self::assertTrue($key->verify('message', self::sign($privateKey, 'message', $alg)));
        }
    }

    /**
     * @return iterable<string, array{string, array<int, int|string>}>
     */
    public static function provideRejectedEcPoints(): iterable
    {
        foreach ([CoseAlgorithmIdentifier::ES256, CoseAlgorithmIdentifier::ES384, CoseAlgorithmIdentifier::ES512] as $alg) {
            [, $crv, $length] = self::ec2Spec($alg);

            foreach ([0, 1] as $coordinate) {
                yield "EC2 {$crv}, off-curve coordinates {$coordinate}" => [
                    "Failed to load public key for COSE algorithm {$alg}: error:%a",
                    [1 => CoseEc2Key::KTY, 3 => $alg, -1 => $crv, -2 => str_repeat(chr($coordinate), $length), -3 => str_repeat(chr($coordinate), $length)],
                ];
            }
        }

        $y = self::bytesFromHex(self::P256_BASE_POINT_Y);
        $y[31] = $y[31] ^ "\x01";

        yield 'P-256 generator with one changed y bit' => [
            'Failed to load public key for COSE algorithm -7: error:%a',
            [
                1 => CoseEc2Key::KTY,
                3 => CoseAlgorithmIdentifier::ES256,
                -1 => CoseEc2Key::CRV_P256,
                -2 => self::bytesFromHex(self::P256_BASE_POINT_X),
                -3 => $y,
            ],
        ];
    }

    /**
     * Ed25519 vectors: libsodium 1.0.18 ge25519_has_small_order.
     * Each vector is tested with both sign bits, including the invalid negative-zero encodings.
     *
     * @return iterable<string, array{string, array<int, int|string>}>
     */
    public static function provideRejectedKeyMaterial(): iterable
    {
        $smallOrder = [
            str_repeat('00', 32),
            '01' . str_repeat('00', 31),
            '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
            'ec' . str_repeat('ff', 30) . '7f',
        ];

        $noncanonical = [
            'ed' . str_repeat('ff', 30) . '7f', // p, an alias for y = 0
            'ee' . str_repeat('ff', 30) . '7f', // p + 1, an alias for the identity
            str_repeat('ff', 31) . '7f',
        ];

        $crv = CoseOkpKey::CRV_ED25519;

        foreach (['small-order public key' => $smallOrder, 'noncanonical public key encoding' => $noncanonical] as $reason => $vectors) {
            foreach ($vectors as $index => $hex) {
                foreach ([0, 0x80] as $sign) {
                    $key = self::bytesFromHex($hex);
                    $key[strlen($key) - 1] = chr(ord($key[strlen($key) - 1]) | $sign);

                    yield "OKP {$crv}, {$reason}, vector {$index}, sign {$sign}" => [
                        "OKP curve {$crv} has {$reason}",
                        [1 => CoseOkpKey::KTY, 3 => CoseAlgorithmIdentifier::EdDSA, -1 => $crv, -2 => $key],
                    ];
                }
            }
        }
    }

    /**
     * R = the RFC 8032 base point, S = 1: no secret is used. Review probes showed OpenSSL 3.5.9
     * accepting these public signatures under weak keys. This regression checks that import
     * rejects the keys, independently of whether the installed OpenSSL accepts the signatures.
     *
     * @param CoseAlgorithmIdentifier::* $alg
     * @param CoseOkpKey::CRV_*          $crv
     */
    #[DataProvider('providePublicSignatures')]
    public function testRejectsPubliclyConstructibleSignatures(
        int $alg,
        int $crv,
        string $publicKey,
        string $signature,
    ): void
    {
        $bytes = CborTestEncoder::intMap([1 => CoseOkpKey::KTY, 3 => $alg, -1 => $crv, -2 => $publicKey]);

        foreach (['message one', 'message two'] as $message) {
            self::assertException(
                CoseKeyException::class,
                "OKP curve {$crv} has small-order public key",
                static fn () => CoseKey::fromBytes($bytes)->verify($message, $signature),
            );
        }
    }

    /**
     * @return iterable<string, array{CoseAlgorithmIdentifier::*, CoseOkpKey::CRV_*, string, string}>
     */
    public static function providePublicSignatures(): iterable
    {
        yield 'Ed25519 identity' => [
            CoseAlgorithmIdentifier::EdDSA,
            CoseOkpKey::CRV_ED25519,
            "\x01" . str_repeat("\x00", 31),
            self::bytesFromHex('58' . str_repeat('66', 31)) . "\x01" . str_repeat("\x00", 31),
        ];
    }

}
