<?php declare(strict_types = 1);

namespace WebAuthnX\Binary;

use Closure;
use LogicException;

use function is_float;
use function ord;
use function preg_match;
use function strlen;
use function substr;
use function unpack;

use const INF;
use const NAN;

/**
 * Sequential reader over a binary string, reading big-endian integers, floats and raw byte
 * substrings while tracking the current offset. The whole input must be consumed — leftover
 * bytes are an error, so a parser cannot silently ignore trailing data.
 */
class BytesReader
{
	private readonly int $length;

	/**
	 * @param string $data binary string to read from
	 */
	private function __construct(
		private readonly string $data,
		private int $offset,
	) {
		$this->length = strlen($data);
	}

	/**
	 * @template T
	 *
	 * @param  string $bytes binary string to read from
	 * @param  Closure(self): T $callback
	 * @param-immediately-invoked-callable $callback
	 * @return T
	 * @throws BytesReaderException
	 */
	public static function read(string $bytes, Closure $callback): mixed
	{
		$reader = new self($bytes, 0);
		$result = $callback($reader);
		$reader->end();

		return $result;
	}

	/**
	 * @throws BytesReaderException
	 */
	public function u8(): int
	{
		return ord($this->readRaw(1));
	}

	/**
	 * @throws BytesReaderException
	 */
	public function u16(): int
	{
		$bytes = $this->readRaw(2);

		return (ord($bytes[0]) << 8) | ord($bytes[1]);
	}

	/**
	 * @throws BytesReaderException
	 */
	public function u32(): int
	{
		$bytes = $this->readRaw(4);

		return (ord($bytes[0]) << 24)
			| (ord($bytes[1]) << 16)
			| (ord($bytes[2]) << 8)
			| ord($bytes[3]);
	}

	/**
	 * @throws BytesReaderException
	 */
	public function u64(): int
	{
		$bytes = $this->readRaw(8);

		$value = 0;
		for ($i = 0; $i < 8; $i++) {
			$value = ($value << 8) | ord($bytes[$i]);
		}

		// A set most significant bit overflows PHP's signed 64-bit integer into a negative value.
		if ($value < 0) {
			throw new BytesReaderException('Value is too large for 64-bit signed integer');
		}

		return $value;
	}

	/**
	 * @throws BytesReaderException
	 */
	public function f16(): float
	{
		$value = $this->u16();
		$exponent = ($value >> 10) & 0x1f;
		$mantissa = $value & 0x3ff;

		$float = match ($exponent) {
			0x00 => $mantissa * (2 ** -24),
			0x1f => $mantissa !== 0 ? NAN : INF,
			default => ($mantissa + 1024) * (2 ** ($exponent - 25)),
		};

		return ($value & 0x8000) !== 0 ? -$float : $float;
	}

	/**
	 * @throws BytesReaderException
	 */
	public function f32(): float
	{
		return $this->unpackFloat('G', 4);
	}

	/**
	 * @throws BytesReaderException
	 */
	public function f64(): float
	{
		return $this->unpackFloat('E', 8);
	}

	/**
	 * @return string raw bytes, without any validation
	 * @throws BytesReaderException
	 */
	public function bytes(int $length): string
	{
		if ($length < 0) {
			throw new LogicException('Length must be non-negative');
		}

		return $this->readRaw($length);
	}

	/**
	 * @return string validated UTF-8 string
	 * @throws BytesReaderException
	 */
	public function utf8(int $length): string
	{
		if ($length < 0) {
			throw new LogicException('Length must be non-negative');
		}

		$binaryString = $this->readRaw($length);

		if (preg_match('//u', $binaryString) !== 1) {
			throw new BytesReaderException('Invalid UTF-8 string');
		}

		return $binaryString;
	}

	/**
	 * @throws BytesReaderException
	 */
	private function readRaw(int $length): string
	{
		if ($this->offset + $length > $this->length) {
			throw new BytesReaderException('Unexpected end of data');
		}

		$raw = substr($this->data, $this->offset, $length);
		$this->offset += $length;

		return $raw;
	}

	/**
	 * @throws BytesReaderException
	 */
	private function unpackFloat(string $format, int $length): float
	{
		$value = unpack($format, $this->readRaw($length));

		if ($value === false || !isset($value[1]) || !is_float($value[1])) {
			throw new LogicException('Failed to unpack data'); // unreachable, every 4/8-byte sequence is a valid IEEE 754 float
		}

		return $value[1];
	}

	/**
	 * @throws BytesReaderException
	 */
	private function end(): void
	{
		if ($this->offset !== $this->length) {
			throw new BytesReaderException('Unexpected data after end');
		}
	}
}
