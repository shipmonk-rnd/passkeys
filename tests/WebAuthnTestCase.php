<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use PHPUnit\Framework\Constraint\Exception as ExceptionConstraint;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Throwable;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;

use function file_get_contents;
use function file_put_contents;
use function getenv;
use function hex2bin;
use function is_file;
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
	 * Encodes an integer-keyed CBOR map (as used by COSE keys) with {@see CborTestEncoder}
	 * and parses it back into a {@see CborMap}.
	 *
	 * @param  array<int, int|string> $entries
	 */
	protected static function cborMap(array $entries): CborMap
	{
		return BytesReader::read(
			Bytes::fromBinaryString(CborTestEncoder::intMap($entries)),
			static fn (BytesReader $reader): CborMap => CborMap::fromBytesReader($reader),
		);
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
