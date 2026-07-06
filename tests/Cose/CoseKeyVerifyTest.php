<?php declare(strict_types = 1);

namespace WebAuthnXTests\Cose;

use PHPUnit\Framework\Attributes\DataProvider;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Cose\CoseOkpKey;
use WebAuthnX\Cose\SignatureVerificationException;
use WebAuthnXTests\CryptoTestCase;

use function chr;
use function ord;
use function substr;

use const OPENSSL_ALGO_SHA256;

class CoseKeyVerifyTest extends CryptoTestCase
{
    private const string MESSAGE = 'authenticatorData||clientDataHash ' . '0123456789abcdef';

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testVerifiesValidSignature(int $alg, int $okpCrv = CoseOkpKey::CRV_ED25519): void
    {
        [$coseKey, $privateKey] = self::generateCoseKeyPair($alg, $okpCrv);
        $signature = self::sign($privateKey, self::MESSAGE, $alg);

        self::assertTrue($coseKey->verify(self::MESSAGE, $signature));
    }

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testRejectsSignatureOverDifferentData(int $alg, int $okpCrv = CoseOkpKey::CRV_ED25519): void
    {
        [$coseKey, $privateKey] = self::generateCoseKeyPair($alg, $okpCrv);
        $signature = self::sign($privateKey, self::MESSAGE, $alg);

        self::assertFalse($coseKey->verify(self::MESSAGE . '!', $signature));
    }

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testRejectsSignatureFromDifferentKey(int $alg, int $okpCrv = CoseOkpKey::CRV_ED25519): void
    {
        [, $privateKey] = self::generateCoseKeyPair($alg, $okpCrv);
        [$otherCoseKey] = self::generateCoseKeyPair($alg, $okpCrv);
        $signature = self::sign($privateKey, self::MESSAGE, $alg);

        self::assertFalse($otherCoseKey->verify(self::MESSAGE, $signature));
    }

    /**
     * @return iterable<string, array{CoseAlgorithmIdentifier::*, 1?: int}>
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

    public function testThrowsWhenPublicKeyCannotBeLoaded(): void
    {
        $key = new class (CoseAlgorithmIdentifier::ES256) extends CoseKey {
            public function __construct(int $alg)
            {
                parent::__construct($alg);
            }

            public function toDerSubjectPublicKeyInfo(): string
            {
                return "\x00\x01\x02";
            }

            public function toBytes(): string
            {
                return "\x00\x01\x02";
            }

            protected function opensslAlgorithm(): int
            {
                return OPENSSL_ALGO_SHA256;
            }
        };

        self::assertException(
            SignatureVerificationException::class,
            'Failed to load public key%A',
            static fn () => $key->verify('x', 'y'),
        );
    }

    /**
     * A malformed signature is a verification failure (false), never an exception —
     * regardless of whether OpenSSL reports it as 0 (RSA/EdDSA) or -1 (ECDSA DER parse).
     */
    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testRejectsMalformedSignature(int $alg, int $okpCrv = CoseOkpKey::CRV_ED25519): void
    {
        [$coseKey, $privateKey] = self::generateCoseKeyPair($alg, $okpCrv);
        $signature = self::sign($privateKey, self::MESSAGE, $alg);
        $malformed = substr($signature, 0, 5);

        self::assertFalse($coseKey->verify(self::MESSAGE, $malformed));
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
            -2 => $publicKey,
        ]));

        self::assertTrue($coseKey->verify('', $signature));

        $tampered = $signature;
        $tampered[0] = chr(ord($tampered[0]) ^ 0x01);
        self::assertFalse($coseKey->verify('', $tampered));
    }
}
