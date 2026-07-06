<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthnTests\Der;

use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\WebAuthn\Der\DerEncoder;
use ShipMonk\WebAuthnTests\WebAuthnTestCase;
use function bin2hex;
use function chr;
use function intdiv;
use function ord;
use function pack;
use function random_int;
use function strlen;
use function substr;

class DerEncoderTest extends WebAuthnTestCase
{

    #[DataProvider('provideEncodeIntData')]
    public function testEncodeInt(
        string $bytes,
        string $expected,
    ): void
    {
        self::assertSame($expected, DerEncoder::encodeUnsignedInt($bytes));
    }

    /**
     * @return iterable<array{string, string}>
     */
    public static function provideEncodeIntData(): iterable
    {
        yield ["\x00", "\x02\x01\x00"];
        yield ["\x01", "\x02\x01\x01"];
        yield ["\x00\x00", "\x02\x01\x00"];

        for ($i = 0; $i < 1000; $i++) {
            $int = random_int(0, 1_000_000);
            $bytes = pack('N', $int);
            yield [$bytes, self::derUnsignedInteger($bytes)];
        }
    }

    #[DataProvider('provideEncodeObjectIdentifierData')]
    public function testEncodeObjectIdentifier(
        string $oid,
        string $expectedHex,
    ): void
    {
        self::assertSame($expectedHex, bin2hex(DerEncoder::encodeObjectIdentifier($oid)));
    }

    /**
     * @return iterable<array{string, string}>
     */
    public static function provideEncodeObjectIdentifierData(): iterable
    {
        yield 'id-ecPublicKey' => ['1.2.840.10045.2.1', '06072a8648ce3d0201'];
        yield 'prime256v1 (P-256)' => ['1.2.840.10045.3.1.7', '06082a8648ce3d030107'];
        yield 'secp384r1 (P-384)' => ['1.3.132.0.34', '06052b81040022'];
        yield 'secp521r1 (P-521)' => ['1.3.132.0.35', '06052b81040023'];
        yield 'rsaEncryption' => ['1.2.840.113549.1.1.1', '06092a864886f70d010101'];
    }

    #[DataProvider('provideInvalidObjectIdentifierData')]
    public function testEncodeInvalidObjectIdentifier(string $oid): void
    {
        $this->expectException(LogicException::class);
        DerEncoder::encodeObjectIdentifier($oid);
    }

    /**
     * @return iterable<array{string}>
     */
    public static function provideInvalidObjectIdentifierData(): iterable
    {
        yield 'single arc' => ['1'];
        yield 'first arc too large' => ['3.0'];
        yield 'negative second arc' => ['1.-2.3'];
        yield 'negative later arc' => ['1.2.-3'];
    }

    public function testEncodeSequence(): void
    {
        self::assertSame("\x30\x00", DerEncoder::encodeSequence());
        self::assertSame("\x30\x02\x05\x00", DerEncoder::encodeSequence(DerEncoder::encodeNull()));
        self::assertSame(
            "\x30\x06\x02\x01\x01\x02\x01\x02",
            DerEncoder::encodeSequence(DerEncoder::encodeUnsignedInt("\x01"), DerEncoder::encodeUnsignedInt("\x02")),
        );
    }

    /**
     * @param non-negative-int $length
     */
    #[DataProvider('provideEncodeLengthData')]
    public function testEncodeLength(
        int $length,
        string $expected,
    ): void
    {
        self::assertSame($expected, DerEncoder::encodeLength($length));
    }

    /**
     * @return iterable<array{non-negative-int, string}>
     */
    public static function provideEncodeLengthData(): iterable
    {
        yield [0, "\x00"];
        yield [1, "\x01"];
        yield [38, "\x26"];
        yield [127, "\x7f"];
        yield [128, "\x81\x80"];
        yield [201, "\x81\xc9"];
        yield [255, "\x81\xff"];
        yield [256, "\x82\x01\x00"];

        for ($i = 0; $i < 1000; $i++) {
            $int = random_int(0, 1_000_000);
            yield [$int, self::derLength($int)];
        }
    }

    private static function derLength(int $len): string
    {
        if ($len < 128) {
            return chr($len);
        }
        $lenBytes = '';
        while ($len > 0) {
            $lenBytes = chr($len % 256) . $lenBytes;
            $len = intdiv($len, 256);
        }
        return chr(0x80 | strlen($lenBytes)) . $lenBytes;
    }

    private static function derUnsignedInteger(string $bytes): string
    {
        $len = strlen($bytes);

        // Remove leading zero bytes
        $i = 0;
        for (; $i < ($len - 1); $i++) {
            if (ord($bytes[$i]) !== 0) {
                break;
            }
        }
        if ($i !== 0) {
            $bytes = substr($bytes, $i);
        }

        // If most significant bit is set, prefix with another zero to prevent it being seen as negative number
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

}
