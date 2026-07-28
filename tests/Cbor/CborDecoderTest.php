<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Cbor;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Binary\BytesReader;
use ShipMonk\Passkeys\Cbor\CborDecoder;
use ShipMonk\Passkeys\Cbor\InvalidCborException;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function array_fill;
use function json_decode;
use function sprintf;
use function str_repeat;
use function str_replace;
use function substr;
use const JSON_THROW_ON_ERROR;

#[CoversClass(CborDecoder::class)]
final class CborDecoderTest extends PasskeysTestCase
{

    #[DataProvider('provideDecodeData')]
    public function testDecode(
        string $data,
        mixed $expected,
    ): void
    {
        $bytes = self::bytesFromHex($data);

        $actual = BytesReader::read($bytes, static function (BytesReader $reader): mixed {
            return CborDecoder::decode($reader);
        });

        self::assertSame($expected, $actual);
    }

    /**
     * @return iterable<array{string, mixed}>
     */
    public static function provideDecodeData(): iterable
    {
        // positive int or zero
        yield ['00', 0];
        yield ['01', 1];
        yield ['0a', 10];
        yield ['17', 23];
        yield ['18 18', 24];
        yield ['18 19', 25];
        yield ['18 64', 100];
        yield ['19 03 e8', 1000];
        yield ['1a 00 0f 42 40', 1_000_000];
        yield ['1b 00 00 00 e8 d4 a5 10 00', 1_000_000_000_000];
        yield ['1b 7f ff ff ff ff ff ff ff', 9_223_372_036_854_775_807];

        // negative int
        yield ['20', -1];
        yield ['29', -10];
        yield ['38 63', -100];
        yield ['39 03 e7', -1000];
        yield ['3a 00 0f 42 3f', -1_000_000];
        yield ['3b 7f ff ff ff ff ff ff ff', -9_223_372_036_854_775_807 - 1];

        // byte strings (longer length prefixes are accepted even when not minimally encoded)
        yield ['40', ''];
        yield ['44 01 02 03 04', "\x01\x02\x03\x04"];
        yield ['58 04 01 02 03 04', "\x01\x02\x03\x04"];
        yield ['59 00 04 01 02 03 04', "\x01\x02\x03\x04"];
        yield ['5a 00 00 00 04 01 02 03 04', "\x01\x02\x03\x04"];
        yield ['5b 00 00 00 00 00 00 00 04 01 02 03 04', "\x01\x02\x03\x04"];

        // utf-8 strings
        yield ['60', ''];
        yield ['61 61', 'a'];
        yield ['64 49 45 54 46', 'IETF'];
        yield ['62 22 5c', '"\\'];
        yield ['62 c3 bc', "\u{00fc}"];
        yield ['63 e6 b0 b4', "\u{6c34}"];
        yield ['64 f0 90 85 91', "\u{10151}"];
        yield ['78 04 49 45 54 46', 'IETF'];
        yield ['79 00 04 49 45 54 46', 'IETF'];
        yield ['7a 00 00 00 04 49 45 54 46', 'IETF'];
        yield ['7b 00 00 00 00 00 00 00 04 49 45 54 46', 'IETF'];

        // arrays
        yield ['80', []];
        yield ['83 01 02 03', [1, 2, 3]];
        yield ['83 01 82 02 03 82 04 05', [1, [2, 3], [4, 5]]];
        yield ['98 19 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 18 18 19', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]];
        yield ['99 00 03 01 02 03', [1, 2, 3]];
        yield ['9a 00 00 00 03 01 02 03', [1, 2, 3]];
        yield ['9b 00 00 00 00 00 00 00 03 01 02 03', [1, 2, 3]];

        // maps
        yield ['a0', []];
        yield ['a2 01 02 03 04', [1 => 2, 3 => 4]];
        yield ['a2 61 61 01 61 62 82 02 03', ['a' => 1, 'b' => [2, 3]]];
        yield ['82 61 61 a1 61 62 61 63', ['a', ['b' => 'c']]];
        yield ['a5 61 61 61 41 61 62 61 42 61 63 61 43 61 64 61 44 61 65 61 45', ['a' => 'A', 'b' => 'B', 'c' => 'C', 'd' => 'D', 'e' => 'E']];
        yield ['b8 02 01 02 03 04', [1 => 2, 3 => 4]];
        yield ['b9 00 02 01 02 03 04', [1 => 2, 3 => 4]];
        yield ['ba 00 00 00 02 01 02 03 04', [1 => 2, 3 => 4]];
        yield ['bb 00 00 00 00 00 00 00 02 01 02 03 04', [1 => 2, 3 => 4]];

        // literals
        yield ['f4', false];
        yield ['f5', true];
        yield ['f6', null];

        // nesting exactly at the maximum accepted depth: 16 single-element arrays wrapping a 0
        yield 'nesting at the maximum depth' => [
            str_repeat('81 ', 16) . '00',
            json_decode(str_repeat('[', 16) . '0' . str_repeat(']', 16), flags: JSON_THROW_ON_ERROR),
        ];
    }

    /**
     * Decodes every accepted CBOR initial byte, each with the minimal well-formed payload its head
     * calls for: the shorthand forms that carry the argument in the initial byte itself (0x00–0x17
     * of each major type) as well as the explicit 1/2/4/8-byte argument forms, plus the three
     * literals. Together with {@see self::testDecodeRejectsEveryOtherInitialByte()} this pins down
     * all 256 initial bytes, so no arm of the decoder's match can be dropped or shifted by one
     * without failing here.
     */
    #[DataProvider('provideEveryAcceptedInitialByte')]
    public function testDecodeEveryAcceptedInitialByte(
        string $data,
        mixed $expected,
    ): void
    {
        $bytes = self::bytesFromHex($data);

        $actual = BytesReader::read($bytes, static function (BytesReader $reader): mixed {
            return CborDecoder::decode($reader);
        });

        self::assertSame($expected, $actual);
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function provideEveryAcceptedInitialByte(): iterable
    {
        // major type 0 (0x00–0x1b): unsigned integer; 0x00–0x17 are the value itself.
        for ($byte = 0x00; $byte <= 0x17; $byte++) {
            yield sprintf('unsigned 0x%02x', $byte) => [sprintf('%02x', $byte), $byte];
        }

        yield 'unsigned 1-byte argument' => ['18 ff', 0xFF];
        yield 'unsigned 2-byte argument' => ['19 ff ff', 0xFFFF];
        yield 'unsigned 4-byte argument' => ['1a ff ff ff ff', 0xFFFFFFFF];
        yield 'unsigned 8-byte argument' => ['1b 00 00 00 01 00 00 00 00', 0x100000000];

        // major type 1 (0x20–0x3b): negative integer, encoded as -1 - argument.
        for ($byte = 0x20; $byte <= 0x37; $byte++) {
            yield sprintf('negative 0x%02x', $byte) => [sprintf('%02x', $byte), -1 - ($byte & 0x1F)];
        }

        yield 'negative 1-byte argument' => ['38 ff', -0x100];
        yield 'negative 2-byte argument' => ['39 ff ff', -0x10000];
        yield 'negative 4-byte argument' => ['3a ff ff ff ff', -0x100000000];
        yield 'negative 8-byte argument' => ['3b 00 00 00 01 00 00 00 00', -0x100000001];

        // major type 2 (0x40–0x5b): byte string of the given length.
        for ($byte = 0x40; $byte <= 0x57; $byte++) {
            $length = $byte & 0x1F;

            yield sprintf('byte string 0x%02x', $byte) => [
                sprintf('%02x', $byte) . str_repeat('41', $length),
                str_repeat('A', $length),
            ];
        }

        yield 'byte string 1-byte length' => ['58 02 41 42', 'AB'];
        yield 'byte string 2-byte length' => ['59 00 02 41 42', 'AB'];
        yield 'byte string 4-byte length' => ['5a 00 00 00 02 41 42', 'AB'];
        yield 'byte string 8-byte length' => ['5b 00 00 00 00 00 00 00 02 41 42', 'AB'];

        // major type 3 (0x60–0x7b): utf-8 string of the given length.
        for ($byte = 0x60; $byte <= 0x77; $byte++) {
            $length = $byte & 0x1F;

            yield sprintf('utf-8 string 0x%02x', $byte) => [
                sprintf('%02x', $byte) . str_repeat('41', $length),
                str_repeat('A', $length),
            ];
        }

        yield 'utf-8 string 1-byte length' => ['78 02 41 42', 'AB'];
        yield 'utf-8 string 2-byte length' => ['79 00 02 41 42', 'AB'];
        yield 'utf-8 string 4-byte length' => ['7a 00 00 00 02 41 42', 'AB'];
        yield 'utf-8 string 8-byte length' => ['7b 00 00 00 00 00 00 00 02 41 42', 'AB'];

        // major type 4 (0x80–0x9b): array of the given number of items (each a zero).
        for ($byte = 0x80; $byte <= 0x97; $byte++) {
            $count = $byte & 0x1F;

            yield sprintf('array 0x%02x', $byte) => [
                sprintf('%02x', $byte) . str_repeat('00', $count),
                array_fill(0, $count, 0),
            ];
        }

        yield 'array 1-byte count' => ['98 02 00 00', [0, 0]];
        yield 'array 2-byte count' => ['99 00 02 00 00', [0, 0]];
        yield 'array 4-byte count' => ['9a 00 00 00 02 00 00', [0, 0]];
        yield 'array 8-byte count' => ['9b 00 00 00 00 00 00 00 02 00 00', [0, 0]];

        // major type 5 (0xa0–0xbb): map of the given number of pairs (distinct integer keys).
        for ($byte = 0xA0; $byte <= 0xB7; $byte++) {
            $count = $byte & 0x1F;
            $pairs = '';

            for ($key = 0; $key < $count; $key++) {
                $pairs .= sprintf('%02x', $key) . '00';
            }

            yield sprintf('map 0x%02x', $byte) => [
                sprintf('%02x', $byte) . $pairs,
                array_fill(0, $count, 0),
            ];
        }

        yield 'map 1-byte count' => ['b8 02 00 00 01 00', [0, 0]];
        yield 'map 2-byte count' => ['b9 00 02 00 00 01 00', [0, 0]];
        yield 'map 4-byte count' => ['ba 00 00 00 02 00 00 01 00', [0, 0]];
        yield 'map 8-byte count' => ['bb 00 00 00 00 00 00 00 02 00 00 01 00', [0, 0]];

        // major type 7: the three literals we support.
        yield 'literal false' => ['f4', false];
        yield 'literal true' => ['f5', true];
        yield 'literal null' => ['f6', null];
    }

    /**
     * The other 78 initial bytes: every unassigned additional-information value (0x1c–0x1e of each
     * major type), every indefinite-length head (…0x1f), every tag, every simple value we do not
     * recognise, and the three float widths. Each must be refused with its own message rather than
     * silently falling into a neighbouring arm.
     */
    #[DataProvider('provideEveryRejectedInitialByte')]
    public function testDecodeRejectsEveryOtherInitialByte(
        string $data,
        string $message,
    ): void
    {
        $this->assertDecodeFails($data, $message);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideEveryRejectedInitialByte(): iterable
    {
        $accepted = [];

        foreach (self::provideEveryAcceptedInitialByte() as [$data]) {
            $accepted[substr(str_replace(' ', '', $data), 0, 2)] = true;
        }

        for ($byte = 0x00; $byte <= 0xFF; $byte++) {
            $initialByte = sprintf('%02x', $byte);

            if (isset($accepted[$initialByte])) {
                continue;
            }

            $message = match (true) {
                ($byte & 0x1F) === 31 => 'Indefinite-length values are not supported',
                ($byte >> 5) === 6 => 'Tagged values are not supported',
                $byte >= 0xF9 && $byte <= 0xFB => 'Floating-point values are not supported',
                ($byte >> 5) === 7 => sprintf('Unrecognized simple value byte 0x%x', $byte),
                default => sprintf('Unrecognized CBOR initial byte 0x%x', $byte),
            };

            yield "rejected 0x{$initialByte}" => [$initialByte, $message];
        }
    }

    /**
     * Nesting is bounded through map values too, not only array items — a map counts each of its
     * keys and values as one level deeper, so 16 nested single-entry maps are the deepest accepted.
     */
    public function testDecodeBoundsNestingThroughMaps(): void
    {
        $atMaximumDepth = str_repeat('a1 00 ', 16) . '00';

        $decoded = BytesReader::read(
            self::bytesFromHex($atMaximumDepth),
            static function (BytesReader $reader): mixed {
                return CborDecoder::decode($reader);
            },
        );

        self::assertSame([0 => [0 => [0 => [0 => [0 => [0 => [0 => [0 => [0 => [0 => [0 => [0 => [0 => [0 => [0 => [0 => 0]]]]]]]]]]]]]]]], $decoded);

        $this->assertDecodeFails(str_repeat('a1 00 ', 17) . '00', 'Maximum CBOR nesting depth of 16 exceeded');
    }

    /**
     * A map *key* counts towards the depth budget too, so an over-nested key is refused by the depth
     * guard before the decoder ever gets to complain about its type.
     */
    public function testDecodeBoundsNestingThroughMapKeys(): void
    {
        $this->assertDecodeFails(
            'a1 ' . str_repeat('81 ', 16) . '00 00',
            'Maximum CBOR nesting depth of 16 exceeded',
        );
    }

    #[DataProvider('provideDecodeInvalid')]
    public function testDecodeInvalid(
        string $data,
        string $message,
    ): void
    {
        $this->assertDecodeFails($data, $message);
    }

    private function assertDecodeFails(
        string $data,
        string $message,
    ): void
    {
        $bytes = self::bytesFromHex($data);

        self::assertException(
            InvalidCborException::class,
            $message,
            static function () use ($bytes): void {
                BytesReader::read($bytes, static function (BytesReader $reader): mixed {
                    return CborDecoder::decode($reader);
                });
            },
        );
    }

    /**
     * @return iterable<array{string, string}>
     */
    public static function provideDecodeInvalid(): iterable
    {
        yield ['', 'Unexpected end of data'];
        yield ['44 01 02 03', 'Unexpected end of data'];

        yield ['1b ff ff ff ff ff ff ff ff', 'Value is too large for 64-bit signed integer'];
        yield ['3b ff ff ff ff ff ff ff ff', 'Value is too large for 64-bit signed integer'];

        yield ['62 c0 ae', 'Invalid UTF-8 string'];

        yield ['a2 f4 02 03 04', 'Invalid CBOR map key type'];
        yield ['a2 01 02 01 04', 'Duplicate CBOR map key 1'];

        yield ['c2 49 01 00 00 00 00 00 00 00 00', 'Tagged values are not supported'];
        yield ['c3 49 01 00 00 00 00 00 00 00 00', 'Tagged values are not supported'];
        yield ['c0 74 32 30 31 33 2d 30 33 2d 32 31 54 32 30 3a 30 34 3a 30 30 5a', 'Tagged values are not supported'];
        yield ['c1 1a 51 4b 67 b0', 'Tagged values are not supported'];
        yield ['c1 fb 41 d4 52 d9 ec 20 00 00', 'Tagged values are not supported'];
        yield ['d7 44 01 02 03 04', 'Tagged values are not supported'];
        yield ['d8 18 45 64 49 45 54 46', 'Tagged values are not supported'];
        yield ['d8 20 76 68 74 74 70 3a 2f 2f 77 77 77 2e 65 78  6 16 d7 06 c6 52 e6 36 f6 d', 'Tagged values are not supported'];

        yield ['f7', 'Unrecognized simple value byte 0xf7'];
        yield ['f0', 'Unrecognized simple value byte 0xf0'];
        yield ['f8 ff', 'Unrecognized simple value byte 0xf8'];

        yield ['f9 3c 00', 'Floating-point values are not supported'];
        yield ['fa 47 c3 50 00', 'Floating-point values are not supported'];
        yield ['fb 3f f1 99 99 99 99 99 9a', 'Floating-point values are not supported'];
        yield ['83 01 02 f9 7e 00', 'Floating-point values are not supported'];
        yield ['a1 61 61 fb 7f f0 00 00 00 00 00 00', 'Floating-point values are not supported'];

        yield ['5f 42 01 02 43 03 04 05 ff', 'Indefinite-length values are not supported'];
        yield ['7f 65 73 74 72 65 61 64 6d 69 6e 67 ff', 'Indefinite-length values are not supported'];
        yield ['9f ff', 'Indefinite-length values are not supported'];
        yield ['9f 01 82 02 03 82 04 05 ff', 'Indefinite-length values are not supported'];
        yield ['9f 01 82 02 03 9f 04 05 ff ff', 'Indefinite-length values are not supported'];
        yield ['83 01 82 02 03 9f 04 05 ff', 'Indefinite-length values are not supported'];
        yield ['83 01 9f 02 03 ff 82 04 05', 'Indefinite-length values are not supported'];
        yield ['9f 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 18 18 19 ff', 'Indefinite-length values are not supported'];
        yield ['bf 61 61 01 61 62 9f 02 03 ff ff', 'Indefinite-length values are not supported'];
        yield ['82 61 61 bf 61 62 61 63 ff', 'Indefinite-length values are not supported'];
        yield ['bf 63 46 75 6e f5 63 41 6d 74 21 ff', 'Indefinite-length values are not supported'];

        // one level past the maximum accepted depth: unbounded recursion would otherwise crash the process
        yield 'nesting past the maximum depth' => [str_repeat('81 ', 17) . '00', 'Maximum CBOR nesting depth of 16 exceeded'];
    }

}
