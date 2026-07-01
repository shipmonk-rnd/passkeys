<?php declare(strict_types = 1);

namespace WebAuthnX\Der;

use LogicException;

use function chr;
use function ltrim;
use function ord;
use function pack;
use function strlen;

class DerEncoder
{
	public static function encodeUnsignedInt(string $bytes): string
	{
		$bytes = ltrim($bytes, "\x00");

		if (strlen($bytes) === 0 || ord($bytes[0]) >= 0x80) {
			$bytes = "\x00{$bytes}";
		}

		return "\x02" . self::encodeLength(strlen($bytes)) . $bytes;
	}

	public static function encodeBitString(string $bytes): string
	{
		return "\x03" . self::encodeLength(strlen($bytes) + 1) . "\x00{$bytes}";
	}

	public static function encodeNull(): string
	{
		return "\x05\x00";
	}

	public static function encodeObjectIdentifier(string $bytes): string
	{
		return "\x06" . self::encodeLength(strlen($bytes)) . $bytes;
	}

	public static function encodeSequence(string $bytes): string
	{
		return "\x30" . self::encodeLength(strlen($bytes)) . $bytes;
	}

	public static function encodeLength(int $length): string
	{
		if ($length < 0) {
			throw new LogicException('Length cannot be negative');
		}

		if ($length < 0x80) {
			return chr($length);
		}

		$lengthBytes = ltrim(pack('J', $length), "\x00");
		return chr(0x80 | strlen($lengthBytes)) . $lengthBytes;
	}
}
