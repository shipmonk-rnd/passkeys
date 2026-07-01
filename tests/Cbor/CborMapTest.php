<?php declare(strict_types = 1);

namespace WebAuthnXTests\Cbor;

use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnXTests\WebAuthnTestCase;

class CborMapTest extends WebAuthnTestCase
{
	/**
	 * A CBOR map with mixed key and value types:
	 *   1       => 2                       (int)
	 *   3       => "abc"                   (text string)
	 *   4       => h'01020304'             (byte string)
	 *   5       => {1: 2}                   (nested map)
	 *   "neg"   => -1                      (int, text key)
	 */
	private const SAMPLE_MAP_HEX = 'a5 01 02 03 63 61 62 63 04 44 01 02 03 04 05 a1 01 02 63 6e 65 67 20';

	private static function sampleMap(): CborMap
	{
		return BytesReader::read(
			self::bytesFromHex(self::SAMPLE_MAP_HEX),
			static fn (BytesReader $reader): CborMap => CborMap::fromBytesReader($reader),
		);
	}

	public function testTypedGetters(): void
	{
		$map = self::sampleMap();

		self::assertSame(2, $map->getInt(1));
		self::assertSame(-1, $map->getInt('neg'));
		self::assertSame('abc', $map->getString(3));
		self::assertSame("\x01\x02\x03\x04", $map->getBytes(4)->toBinaryString());
		self::assertSame(2, $map->getMap(5)->getInt(1));
	}

	public function testHas(): void
	{
		$map = self::sampleMap();

		self::assertTrue($map->has(1));
		self::assertTrue($map->has('neg'));
		self::assertFalse($map->has(99));
	}

	public function testOptionalGetters(): void
	{
		$map = self::sampleMap();

		self::assertSame(2, $map->getOptionalInt(1));
		self::assertSame('abc', $map->getOptionalString(3));
		self::assertSame("\x01\x02\x03\x04", $map->getOptionalBytes(4)?->toBinaryString());
		self::assertSame(2, $map->getOptionalMap(5)?->getInt(1));

		self::assertNull($map->getOptionalInt(99));
		self::assertNull($map->getOptionalString(99));
		self::assertNull($map->getOptionalBytes(99));
		self::assertNull($map->getOptionalMap(99));
	}

	public function testMissingKeyThrows(): void
	{
		self::assertException(
			CborMapException::class,
			"Key '99' not found",
			static fn () => self::sampleMap()->getInt(99),
		);
	}

	public function testWrongTypeThrows(): void
	{
		$map = self::sampleMap();

		self::assertException(CborMapException::class, "Key '1' is not a string", static fn () => $map->getString(1));
		self::assertException(CborMapException::class, "Key '3' is not an integer", static fn () => $map->getInt(3));
		self::assertException(CborMapException::class, "Key '1' is not a byte string", static fn () => $map->getBytes(1));
		self::assertException(CborMapException::class, "Key '1' is not a map", static fn () => $map->getMap(1));
	}

	public function testNonMapValueThrows(): void
	{
		self::assertException(
			CborMapException::class,
			'CBOR value is not a map',
			static fn () => BytesReader::read(
				self::bytesFromHex('01'),
				static fn (BytesReader $reader): CborMap => CborMap::fromBytesReader($reader),
			),
		);
	}
}
