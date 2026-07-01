<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use function chr;
use function count;
use function is_int;
use function pack;
use function strlen;

/**
 * Minimal CBOR encoder used only to build test fixtures (COSE keys, attestation
 * objects). The production code never encodes CBOR — it only decodes — so this
 * lives in the test suite rather than in {@see \WebAuthnX}.
 */
final class CborTestEncoder
{
	/**
	 * Major type 0/1: a (signed) integer.
	 */
	public static function int(int $value): string
	{
		return $value >= 0
			? self::head(0, $value)
			: self::head(1, -1 - $value);
	}

	/**
	 * Major type 2: a byte string.
	 */
	public static function byteString(string $bytes): string
	{
		return self::head(2, strlen($bytes)) . $bytes;
	}

	/**
	 * Major type 3: a UTF-8 text string.
	 */
	public static function textString(string $text): string
	{
		return self::head(3, strlen($text)) . $text;
	}

	/**
	 * Major type 5: a map of already-encoded (key, value) byte pairs, kept in the given order.
	 *
	 * @param  list<array{string, string}> $pairs
	 */
	public static function map(array $pairs): string
	{
		$body = '';

		foreach ($pairs as [$key, $value]) {
			$body .= $key . $value;
		}

		return self::head(5, count($pairs)) . $body;
	}

	/**
	 * An integer-keyed map, as used by COSE keys: integer values encode as CBOR
	 * integers, string values as CBOR byte strings.
	 *
	 * @param  array<int, int|string> $entries
	 */
	public static function intMap(array $entries): string
	{
		$pairs = [];

		foreach ($entries as $key => $value) {
			$pairs[] = [self::int($key), is_int($value) ? self::int($value) : self::byteString($value)];
		}

		return self::map($pairs);
	}

	private static function head(int $majorType, int $value): string
	{
		$initialByte = $majorType << 5;

		if ($value < 24) {
			return chr($initialByte | $value);
		}

		if ($value <= 0xFF) {
			return chr($initialByte | 24) . chr($value);
		}

		if ($value <= 0xFFFF) {
			return chr($initialByte | 25) . pack('n', $value);
		}

		if ($value <= 0xFFFFFFFF) {
			return chr($initialByte | 26) . pack('N', $value);
		}

		return chr($initialByte | 27) . pack('J', $value);
	}
}
