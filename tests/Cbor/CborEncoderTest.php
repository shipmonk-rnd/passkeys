<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Cbor;

use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Binary\BytesReader;
use ShipMonk\Passkeys\Cbor\CborEncoder;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function bin2hex;
use function str_repeat;

final class CborEncoderTest extends PasskeysTestCase
{

    /**
     * Exercises every head-byte width: inline (< 24), 1-, 2-, 4- and 8-byte arguments, plus the
     * negative-integer major type.
     */
    #[DataProvider('provideIntegers')]
    public function testEncodeInt(
        int $value,
        string $expectedHex,
    ): void
    {
        self::assertSame($expectedHex, bin2hex(CborEncoder::encodeInt($value)));
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideIntegers(): iterable
    {
        yield 'zero' => [0, '00'];
        yield 'inline max (23)' => [23, '17'];
        yield 'one-byte (24)' => [24, '1818'];
        yield 'one-byte (200)' => [200, '18c8'];
        yield 'two-byte (1000)' => [1000, '1903e8'];
        yield 'two-byte max (65535)' => [65_535, '19ffff'];
        yield 'four-byte (100000)' => [100_000, '1a000186a0'];
        yield 'eight-byte (5e9)' => [5_000_000_000, '1b000000012a05f200'];
        yield 'negative one' => [-1, '20'];
        yield 'negative (ES256 alg -7)' => [-7, '26'];
        yield 'negative two-byte (RS256 alg -257)' => [-257, '390100'];
    }

    public function testEncodeByteString(): void
    {
        self::assertSame('40', bin2hex(CborEncoder::encodeByteString('')));
        self::assertSame('43616263', bin2hex(CborEncoder::encodeByteString('abc')));
        // 32-byte coordinate: head 0x58 0x20, then the bytes.
        self::assertSame('5820' . str_repeat('01', 32), bin2hex(CborEncoder::encodeByteString(str_repeat("\x01", 32))));
    }

    public function testEncodeMapKeepsOrderAndRoundTripsThroughTheDecoder(): void
    {
        $encoded = CborEncoder::encodeMap([
            [CborEncoder::encodeInt(1), CborEncoder::encodeInt(2)],
            [CborEncoder::encodeInt(-1), CborEncoder::encodeByteString('xy')],
        ]);

        self::assertSame('a2010220427879', bin2hex($encoded));

        $map = BytesReader::read(
            self::bytesFromHex(bin2hex($encoded)),
            static fn (BytesReader $reader): CborMap => CborMap::fromBytesReader($reader),
        );

        self::assertSame(2, $map->getInt(1));
        self::assertSame('xy', $map->getString(-1));
    }

    public function testEmptyMap(): void
    {
        self::assertSame('a0', bin2hex(CborEncoder::encodeMap([])));
    }

}
