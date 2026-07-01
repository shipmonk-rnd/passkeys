<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use PHPUnit\Framework\Constraint\Exception as ExceptionConstraint;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Throwable;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;

use function chr;
use function file_get_contents;
use function file_put_contents;
use function getenv;
use function hex2bin;
use function is_file;
use function is_int;
use function pack;
use function str_replace;
use function strlen;

abstract class WebAuthnTestCase extends TestCase
{
	/**
	 * Decodes a (possibly space-separated) hex string into {@see Bytes}.
	 */
	protected static function bytesFromHex(string $hex): Bytes
	{
		$binary = hex2bin(str_replace(' ', '', $hex));

		if ($binary === false) {
			throw new RuntimeException('Invalid hex string in test data');
		}

		return Bytes::fromBinaryString($binary);
	}

	/**
	 * Encodes an integer-keyed CBOR map (as used by COSE keys) and parses it back
	 * into a {@see CborMap}. Integer values are encoded as CBOR integers; string
	 * values as CBOR byte strings.
	 *
	 * @param  array<int, int|string> $entries
	 */
	protected static function cborMap(array $entries): CborMap
	{
		$body = '';
		$count = 0;

		foreach ($entries as $key => $value) {
			$body .= self::cborInt($key);
			$body .= is_int($value) ? self::cborInt($value) : self::cborByteString($value);
			$count++;
		}

		$cbor = self::cborHead(5, $count) . $body;

		return BytesReader::read(
			Bytes::fromBinaryString($cbor),
			static fn (BytesReader $reader): CborMap => CborMap::fromBytesReader($reader),
		);
	}

	private static function cborInt(int $value): string
	{
		return $value >= 0
			? self::cborHead(0, $value)
			: self::cborHead(1, -1 - $value);
	}

	private static function cborByteString(string $bytes): string
	{
		return self::cborHead(2, strlen($bytes)) . $bytes;
	}

	private static function cborHead(int $majorType, int $value): string
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

	protected static function assertSnapshot(string $snapshotPath, string $actual): void
	{
		if (is_file($snapshotPath) && getenv('UPDATE_SNAPSHOTS') === false) {
			$expected = file_get_contents($snapshotPath);

			if ($expected === false) {
				self::fail("Failed to read snapshot file {$snapshotPath}");
			}

			self::assertSame($expected, $actual);

		} elseif (getenv('CI') === false) {
			if (file_put_contents($snapshotPath, $actual) !== strlen($actual)) {
				self::fail("Failed to write snapshot file {$snapshotPath}");
			}

		} else {
			self::fail("Snapshot file {$snapshotPath} does not exist. Run tests locally to generate it.");
		}
	}

	/**
	 * @template T of Throwable
	 * @param  class-string<T>   $type
	 * @param  callable(): mixed $cb
	 */
	protected static function assertException(string $type, ?string $message, callable $cb): void
	{
		try {
			$cb();
			self::assertThat(null, new ExceptionConstraint($type));

		} catch (Throwable $e) {
			self::assertThat($e, new ExceptionConstraint($type));

			if ($message !== null) {
				self::assertStringMatchesFormat($message, $e->getMessage());
			}
		}
	}
}
