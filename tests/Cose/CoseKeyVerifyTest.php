<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Cose;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Cose\CoseEc2Key;
use ShipMonk\Passkeys\Cose\CoseKey;
use ShipMonk\Passkeys\Cose\CoseKeyLoadException;
use ShipMonk\Passkeys\Cose\CoseOkpKey;
use ShipMonk\Passkeys\Cose\CoseRsaKey;
use ShipMonk\PasskeysTests\CryptoTestCase;
use function chr;
use function openssl_pkey_get_public;
use function ord;
use function substr;
use const OPENSSL_ALGO_SHA256;

#[CoversClass(CoseKey::class)]
#[CoversClass(CoseEc2Key::class)]
#[CoversClass(CoseOkpKey::class)]
#[CoversClass(CoseRsaKey::class)]
#[CoversClass(CoseKeyLoadException::class)]
final class CoseKeyVerifyTest extends CryptoTestCase
{

    private const string MESSAGE = 'authenticatorData||clientDataHash 0123456789abcdef';

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testVerifiesValidSignature(int $alg): void
    {
        [$coseKey, $privateKey] = self::generateCoseKeyPair($alg);
        $signature = self::sign($privateKey, self::MESSAGE, $alg);

        self::assertTrue($coseKey->verify(self::MESSAGE, $signature));
    }

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testRejectsSignatureOverDifferentData(int $alg): void
    {
        [$coseKey, $privateKey] = self::generateCoseKeyPair($alg);
        $signature = self::sign($privateKey, self::MESSAGE, $alg);

        self::assertFalse($coseKey->verify(self::MESSAGE . '!', $signature));
    }

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testRejectsSignatureFromDifferentKey(int $alg): void
    {
        [, $privateKey] = self::generateCoseKeyPair($alg);
        [$otherCoseKey] = self::generateCoseKeyPair($alg);
        $signature = self::sign($privateKey, self::MESSAGE, $alg);

        self::assertFalse($otherCoseKey->verify(self::MESSAGE, $signature));
    }

    /**
     * @return iterable<string, array{CoseAlgorithmIdentifier::*}>
     */
    public static function provideAlgorithms(): iterable
    {
        yield 'ES256' => [CoseAlgorithmIdentifier::ES256];
        yield 'ES384' => [CoseAlgorithmIdentifier::ES384];
        yield 'ES512' => [CoseAlgorithmIdentifier::ES512];
        yield 'RS256' => [CoseAlgorithmIdentifier::RS256];
        yield 'EdDSA' => [CoseAlgorithmIdentifier::EdDSA];
        yield 'Ed448' => [CoseAlgorithmIdentifier::Ed448];
    }

    public function testThrowsWhenPublicKeyCannotBeLoaded(): void
    {
        $key = self::unloadableKey();

        self::assertException(
            CoseKeyLoadException::class,
            'Failed to load public key%A',
            static fn () => $key->verify('x', 'y'),
        );
    }

    /**
     * Whatever OpenSSL logged while rejecting the key material is what the exception has to report,
     * so the cause of the load failure is not lost.
     */
    public function testReportsTheOpenSslErrorsBehindALoadFailure(): void
    {
        $key = self::unloadableKey(logOpenSslError: true);

        self::assertException(
            CoseKeyLoadException::class,
            'Failed to load public key: error:%a',
            static fn () => $key->verify('x', 'y'),
        );
    }

    /**
     * OpenSSL's error queue is process-wide and survives across calls, so an error left there by
     * unrelated code must not be attributed to this verification: the queue is drained on entry.
     */
    public function testDoesNotReportOpenSslErrorsLeftBehindByEarlierCalls(): void
    {
        $key = self::unloadableKey();

        // Leave a stale entry in the queue, the way any earlier failed OpenSSL call would.
        self::assertFalse(openssl_pkey_get_public('not a key at all'));

        self::assertException(
            CoseKeyLoadException::class,
            'Failed to load public key: ',
            static fn () => $key->verify('x', 'y'),
        );
    }

    /**
     * A key whose material OpenSSL refuses to load, optionally logging a real error to the queue
     * on the way — the two shapes a load failure takes in practice.
     */
    private static function unloadableKey(bool $logOpenSslError = false): CoseKey
    {
        return new readonly class (CoseAlgorithmIdentifier::ES256, $logOpenSslError) extends CoseKey {

            public function __construct(
                int $alg,
                private bool $logOpenSslError,
            )
            {
                parent::__construct($alg);
            }

            protected function toOpenSslPublicKey(): OpenSSLAsymmetricKey|false
            {
                if ($this->logOpenSslError) {
                    openssl_pkey_get_public('not a key at all');
                }

                return false;
            }

            public function toBytes(): string
            {
                return "\x00\x01\x02";
            }

            protected function getOpenSslAlgorithm(): int
            {
                return OPENSSL_ALGO_SHA256;
            }

        };
    }

    /**
     * A malformed signature is a verification failure (false), never an exception —
     * regardless of whether OpenSSL reports it as 0 (RSA/EdDSA) or -1 (ECDSA DER parse).
     */
    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testRejectsMalformedSignature(int $alg): void
    {
        [$coseKey, $privateKey] = self::generateCoseKeyPair($alg);
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
