<?php declare(strict_types = 1);

namespace WebAuthnX\Binary;

use Closure;
use LogicException;

use function preg_match;
use function unpack;

use const INF;
use const NAN;
use const PHP_INT_SIZE;

class BytesReader
{
	/**
	 * @param  int<0, max> $offset
	 */
	private function __construct(
		private readonly Bytes $bytes,
		private int $offset,
	) {
	}

	/**
	 * @template T
	 *
	 * @param  Closure(self): T $callback
	 * @return T
	 * @throws BytesReaderException
	 */
	public static function read(Bytes $bytes, Closure $callback): mixed
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
		return $this->unpack('C', 1);
	}

	/**
	 * @throws BytesReaderException
	 */
	public function u16(): int
	{
		return $this->unpack('n', 2);
	}

	/**
	 * @throws BytesReaderException
	 */
	public function u32(): int
	{
		$value = $this->unpack('N', 4);

		if (PHP_INT_SIZE === 4 && $value < 0) {
			throw new BytesReaderException('Value is too large for 32-bit signed integer');
		}

		return $value;
	}

	/**
	 * @throws BytesReaderException
	 */
	public function u64(): int
	{
		if (PHP_INT_SIZE < 8) {
			throw new BytesReaderException('64-bit integers are not supported');
		}

		$value = $this->unpack('J', 8);

		if (PHP_INT_SIZE === 8 && $value < 0) {
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

		return ($value & 0x8000) ? -$float : $float;
	}

	/**
	 * @throws BytesReaderException
	 */
	public function f32(): float
	{
		return $this->unpack('G', 4);
	}

	/**
	 * @throws BytesReaderException
	 */
	public function f64(): float
	{
		return $this->unpack('E', 8);
	}

	/**
	 * @throws BytesReaderException
	 */
	public function bytes(int $length): Bytes
	{
		if ($length < 0) {
			throw new LogicException('Length must be non-negative');
		}

		if ($this->offset + $length > $this->bytes->length) {
			throw new BytesReaderException('Unexpected end of data');
		}

		$bytes = $this->bytes->slice($this->offset, $length);
		$this->offset += $length;

		return $bytes;
	}

	/**
	 * @throws BytesReaderException
	 */
	public function utf8(int $length): string
	{
		$binaryString = $this->bytes($length)->toBinaryString();

		if (preg_match('//u', $binaryString) !== 1) {
			throw new BytesReaderException('Invalid UTF-8 string');
		}

		return $binaryString;
	}

	/**
	 * @throws BytesReaderException
	 */
	private function unpack(string $format, int $length): mixed
	{
		if ($this->offset + $length > $this->bytes->length) {
			throw new BytesReaderException('Unexpected end of data');
		}

		$value = unpack($format, $this->bytes->data, $this->bytes->offset + $this->offset);

		if ($value === false) {
			throw new BytesReaderException('Failed to unpack data');
		}

		$this->offset += $length;
		return $value[1];
	}

	/**
	 * @throws BytesReaderException
	 */
	private function end(): void
	{
		if ($this->offset !== $this->bytes->length) {
			throw new BytesReaderException('Unexpected data after end');
		}
	}
}
