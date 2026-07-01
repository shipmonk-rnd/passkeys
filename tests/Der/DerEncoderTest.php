<?php declare(strict_types = 1);

namespace WebAuthnXTests\Der;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Der\DerEncoder;

class DerEncoderTest extends TestCase
{
	#[DataProvider('provideEncodeIntData')]
	public function testEncodeInt(string $bytes, string $expected): void
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
			$int = random_int(0, 1000000);
			$bytes = pack('N', $int);
			yield [$bytes, self::_der_unsignedInteger($bytes)];
		}
	}

	#[DataProvider('provideEncodeLengthData')]
	public function testEncodeLength(int $length, string $expected): void
	{
		self::assertSame($expected, DerEncoder::encodeLength($length));
	}

	/**
	 * @return iterable<array{int, string}>
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
			$int = random_int(0, 1000000);
			yield [$int, self::_der_length($int)];
		}
	}

	private static function _der_length($len)
	{
		if ($len < 128) {
			return \chr($len);
		}
		$lenBytes = '';
		while ($len > 0) {
			$lenBytes = \chr($len % 256) . $lenBytes;
			$len = \intdiv($len, 256);
		}
		return \chr(0x80 | \strlen($lenBytes)) . $lenBytes;
	}

	private static function _der_unsignedInteger($bytes)
	{
		$len = \strlen($bytes);

		// Remove leading zero bytes
		for ($i = 0; $i < ($len - 1); $i++) {
			if (\ord($bytes[$i]) !== 0) {
				break;
			}
		}
		if ($i !== 0) {
			$bytes = \substr($bytes, $i);
		}

		// If most significant bit is set, prefix with another zero to prevent it being seen as negative number
		if ((\ord($bytes[0]) & 0x80) !== 0) {
			$bytes = "\x00" . $bytes;
		}

		return "\x02" . self::_der_length(\strlen($bytes)) . $bytes;
	}
}
