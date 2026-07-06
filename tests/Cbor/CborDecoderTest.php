<?php declare(strict_types = 1);

namespace WebAuthnXTests\Cbor;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborDecoder;
use WebAuthnX\Cbor\InvalidCborException;
use WebAuthnXTests\WebAuthnTestCase;

use function is_float;
use function is_nan;

#[CoversClass(CborDecoder::class)]
class CborDecoderTest extends WebAuthnTestCase
{
	#[DataProvider('provideDecodeData')]
	public function testDecode(string $data, mixed $expected): void
	{
		$bytes = self::bytesFromHex($data);

		$actual = BytesReader::read($bytes, static function (BytesReader $reader): mixed {
			return CborDecoder::decode($reader);
		});

		if (is_float($expected) && is_nan($expected)) {
			self::assertNan($actual);

		} else {
			self::assertSame($expected, $actual);
		}
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
		yield ['1a 00 0f 42 40', 1000000];
		yield ['1b 00 00 00 e8 d4 a5 10 00', 1000000000000];
		yield ['1b 7f ff ff ff ff ff ff ff', 9223372036854775807];

		// negative int
		yield ['20', -1];
		yield ['29', -10];
		yield ['38 63', -100];
		yield ['39 03 e7', -1000];
		yield ['3b 7f ff ff ff ff ff ff ff', -9223372036854775807 - 1];

		// byte strings
		yield ['40', ''];
		yield ['44 01 02 03 04', "\x01\x02\x03\x04"];

		// utf-8 strings
		yield ['60', ''];
		yield ['61 61', 'a'];
		yield ['64 49 45 54 46', 'IETF'];
		yield ['62 22 5c', "\"\\"];
		yield ['62 c3 bc', "\u{00fc}"];
		yield ['63 e6 b0 b4', "\u{6c34}"];
		yield ['64 f0 90 85 91', "\u{10151}"];

		// arrays
		yield ['80', []];
		yield ['83 01 02 03', [1, 2, 3]];
		yield ['83 01 82 02 03 82 04 05', [1, [2, 3], [4, 5]]];
		yield ['98 19 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 18 18 19', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]];

		// maps
		yield ['a0', []];
		yield ['a2 01 02 03 04', [1 => 2, 3 => 4]];
		yield ['a2 61 61 01 61 62 82 02 03', ['a' => 1, 'b' => [2, 3]]];
		yield ['82 61 61 a1 61 62 61 63', ['a', ['b' => 'c']]];
		yield ['a5 61 61 61 41 61 62 61 42 61 63 61 43 61 64 61 44 61 65 61 45', ['a' => 'A', 'b' => 'B', 'c' => 'C', 'd' => 'D', 'e' => 'E']];

		// floats
		yield ['f9 00 00', +0.0];
		yield ['f9 80 00', -0.0];
		yield ['f9 3c 00', 1.0];
		yield ['fb 3f f1 99 99 99 99 99 9a', 1.1];
		yield ['f9 3e 00', 1.5];
		yield ['f9 7b ff', 65504.0];
		yield ['fa 47 c3 50 00', 100000.0];
		yield ['fa 7f 7f ff ff', 3.4028234663852886e+38];
		yield ['fb 7e 37 e4 3c 88 00 75 9c', 1.0e+300];
		yield ['f9 00 01', 5.960464477539063e-8];
		yield ['f9 04 00', 0.00006103515625];
		yield ['f9 c4 00', -4.0];
		yield ['fb c0 10 66 66 66 66 66 66', -4.1];
		yield ['f9 7c 00', INF];
		yield ['f9 7e 00', NAN];
		yield ['f9 fc 00', -INF];
		yield ['fa 7f 80 00 00', INF];
		yield ['fa 7f c0 00 00', NAN];
		yield ['fa ff 80 00 00', -INF];
		yield ['fb 7f f0 00 00 00 00 00 00', INF];
		yield ['fb 7f f8 00 00 00 00 00 00', NAN];
		yield ['fb ff f0 00 00 00 00 00 00', -INF];

		// literals
		yield ['f4', false];
		yield ['f5', true];
		yield ['f6', null];
	}

	#[DataProvider('provideDecodeInvalid')]
	public function testDecodeInvalid(string $data, string $message): void
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
	}
}
