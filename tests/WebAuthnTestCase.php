<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Throwable;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Json\JsonObject;
use WebAuthnXTests\Cbor\CborTestEncoder;

use function hex2bin;
use function json_encode;
use function str_replace;

use const JSON_THROW_ON_ERROR;

abstract class WebAuthnTestCase extends TestCase
{
	/**
	 * Decodes a (possibly space-separated) hex string into a binary string.
	 */
	protected static function bytesFromHex(string $hex): string
	{
		$binary = hex2bin(str_replace(' ', '', $hex));

		if ($binary === false) {
			throw new RuntimeException('Invalid hex string in test data');
		}

		return $binary;
	}

	/**
	 * Encodes an integer-keyed CBOR map (as used by COSE keys) with {@see CborTestEncoder}
	 * and parses it back into a {@see CborMap}.
	 *
	 * @param  array<int, int|string> $entries
	 */
	protected static function cborMap(array $entries): CborMap
	{
		return BytesReader::read(
			CborTestEncoder::intMap($entries),
			CborMap::fromBytesReader(...),
		);
	}

	/**
	 * Builds a {@see JsonObject} from a PHP array, the way the browser-supplied response JSON
	 * parses. The array is cast to an object first so an empty array still encodes as `{}`
	 * (a JSON object) rather than `[]`.
	 *
	 * @param  array<string, mixed> $data
	 */
	protected static function jsonObject(array $data): JsonObject
	{
		return JsonObject::fromString(json_encode((object) $data, JSON_THROW_ON_ERROR));
	}

	/**
	 * @template T of Throwable
	 * @param  class-string<T>   $type
	 * @param  callable(): mixed $cb
	 * @param-immediately-invoked-callable $cb
	 */
	protected static function assertException(string $type, ?string $message, callable $cb): void
	{
		try {
			$cb();

		} catch (Throwable $e) {
			self::assertInstanceOf($type, $e);

			if ($message !== null) {
				self::assertStringMatchesFormat($message, $e->getMessage());
			}

			return;
		}

		self::fail("Failed asserting that exception of type {$type} is thrown.");
	}
}
