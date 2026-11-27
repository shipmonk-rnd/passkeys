<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Der;

use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Der\DerEncoder;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function bin2hex;
use function str_repeat;

/**
 * Known-answer vectors. The INTEGER, NULL, BIT STRING and OBJECT IDENTIFIER encodings agree with
 * `openssl asn1parse -genstr`; the SubjectPublicKeyInfo the encoder builds is checked against
 * OpenSSL's own export in {@see \ShipMonk\PasskeysTests\Cose\CoseKeyTest}.
 */
#[CoversClass(DerEncoder::class)]
final class DerEncoderTest extends PasskeysTestCase
{

    #[DataProvider('provideUnsignedInts')]
    public function testEncodeUnsignedInt(
        string $bytesHex,
        string $expectedHex,
    ): void
    {
        self::assertSame($expectedHex, bin2hex(DerEncoder::encodeUnsignedInt(self::bytesFromHex($bytesHex))));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUnsignedInts(): iterable
    {
        yield 'no bytes encode zero' => ['', '020100'];
        yield 'zero' => ['00', '020100'];
        yield 'zero with leading zero bytes' => ['000000', '020100'];
        yield 'one' => ['01', '020101'];
        yield 'largest value without a sign byte' => ['7f', '02017f'];
        yield 'high bit set gets a sign byte' => ['80', '02020080'];
        yield 'leading zero bytes dropped before the sign byte' => ['000080', '02020080'];
        yield 'leading zero bytes dropped' => ['00000100', '02020100'];
        yield 'zero bytes after the first non-zero one stay' => ['010000', '0203010000'];
        yield 'RSA exponent 65537' => ['010001', '0203010001'];
        yield '2048-bit modulus (long-form length)' => [
            str_repeat('ff', 256),
            '0282010100' . str_repeat('ff', 256),
        ];
    }

    public function testEncodeBitString(): void
    {
        self::assertSame('030100', bin2hex(DerEncoder::encodeBitString('')));
        self::assertSame('0303000102', bin2hex(DerEncoder::encodeBitString("\x01\x02")));
    }

    public function testEncodeNull(): void
    {
        self::assertSame('0500', bin2hex(DerEncoder::encodeNull()));
    }

    #[DataProvider('provideObjectIdentifiers')]
    public function testEncodeObjectIdentifier(
        string $oid,
        string $expectedHex,
    ): void
    {
        self::assertSame($expectedHex, bin2hex(DerEncoder::encodeObjectIdentifier($oid)));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideObjectIdentifiers(): iterable
    {
        yield 'id-ecPublicKey' => ['1.2.840.10045.2.1', '06072a8648ce3d0201'];
        yield 'prime256v1 (P-256)' => ['1.2.840.10045.3.1.7', '06082a8648ce3d030107'];
        yield 'secp384r1 (P-384)' => ['1.3.132.0.34', '06052b81040022'];
        yield 'secp521r1 (P-521)' => ['1.3.132.0.35', '06052b81040023'];
        yield 'rsaEncryption' => ['1.2.840.113549.1.1.1', '06092a864886f70d010101'];
        yield 'smallest' => ['0.0', '060100'];
        yield 'largest second arc under root 1' => ['1.39', '06014f'];
        yield 'second arc of 40 under root 2' => ['2.40', '060178'];
        yield 'X.690 example (multi-byte first subidentifier)' => ['2.999.3', '0603883703'];
        yield '18-digit arc' => ['1.2.999999999999999999', '060a2a8df0add6babb8fff7f'];
        yield '18-digit second arc' => ['2.999999999999999999', '06098df0add6babb90804f'];
    }

    #[DataProvider('provideInvalidObjectIdentifiers')]
    public function testEncodeObjectIdentifierRejectsMalformedInput(string $oid): void
    {
        self::assertException(
            LogicException::class,
            "Invalid object identifier '{$oid}'",
            static fn () => DerEncoder::encodeObjectIdentifier($oid),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidObjectIdentifiers(): iterable
    {
        yield 'empty' => [''];
        yield 'single arc' => ['1'];
        yield 'root above 2' => ['3.0'];
        yield 'negative root' => ['-1.2'];
        yield 'second arc of 40 under root 0' => ['0.40'];
        yield 'second arc of 40 under root 1' => ['1.40'];
        yield 'negative arc' => ['1.-2'];
        yield 'leading zero in root' => ['01.2'];
        yield 'leading zero in arc' => ['1.2.03'];
        yield 'empty arc' => ['1..2'];
        yield 'trailing dot' => ['1.2.'];
        yield 'leading dot' => ['.1.2'];
        yield 'non-digit arc' => ['1.2.x'];
        yield 'leading garbage' => ['x1.2'];
        yield 'trailing garbage' => ['1.2x'];
        yield 'trailing newline' => ["1.2\n"];
        yield '19-digit arc' => ['1.2.1000000000000000000'];
        yield '19-digit second arc' => ['2.1000000000000000000'];
    }

    public function testEncodeSequence(): void
    {
        self::assertSame('3000', bin2hex(DerEncoder::encodeSequence()));
        self::assertSame('30020500', bin2hex(DerEncoder::encodeSequence(DerEncoder::encodeNull())));
        self::assertSame(
            '3006020101020102',
            bin2hex(DerEncoder::encodeSequence(DerEncoder::encodeUnsignedInt("\x01"), DerEncoder::encodeUnsignedInt("\x02"))),
        );
        self::assertSame(
            '300430020500',
            bin2hex(DerEncoder::encodeSequence(DerEncoder::encodeSequence(DerEncoder::encodeNull()))),
        );
    }

    /**
     * Every element type shares the same tag-length-value framing; SEQUENCE takes arbitrary contents,
     * so it shows the length octets at each boundary of the short and long forms.
     */
    #[DataProvider('provideLengths')]
    public function testEncodesLengthInTheShortestForm(
        int $length,
        string $expectedHeaderHex,
    ): void
    {
        $contents = str_repeat("\xab", $length);

        self::assertSame($expectedHeaderHex . bin2hex($contents), bin2hex(DerEncoder::encodeSequence($contents)));
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideLengths(): iterable
    {
        yield 'largest short form' => [127, '307f'];
        yield 'smallest long form' => [128, '308180'];
        yield 'largest one-byte long form' => [255, '3081ff'];
        yield 'smallest two-byte long form' => [256, '30820100'];
        yield 'largest two-byte long form' => [65_535, '3082ffff'];
        yield 'smallest three-byte long form' => [65_536, '3083010000'];
    }

    /**
     * The Base64 body is wrapped at exactly 64 characters (RFC 7468 §2): 48 bytes fill one line,
     * one more byte starts a second.
     */
    public function testToPem(): void
    {
        self::assertSame(
            "-----BEGIN PUBLIC KEY-----\n"
            . str_repeat('A', 64) . "\n"
            . "-----END PUBLIC KEY-----\n",
            DerEncoder::toPem('PUBLIC KEY', str_repeat("\x00", 48)),
        );
        self::assertSame(
            "-----BEGIN PRIVATE KEY-----\n"
            . str_repeat('A', 64) . "\n"
            . "AA==\n"
            . "-----END PRIVATE KEY-----\n",
            DerEncoder::toPem('PRIVATE KEY', str_repeat("\x00", 49)),
        );
    }

}
