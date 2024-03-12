<?php declare(strict_types = 1);

namespace WebAuthnX\Binary;

use LogicException;

use function strlen;
use function substr;

readonly class Bytes
{
	/**
	 * @param  int<0, max> $offset
	 * @param  int<0, max> $length
	 */
	private function __construct(
		public string $data,
		public int $offset,
		public int $length,
	) {
	}

	public static function fromBinaryString(string $bytes): self
	{
		return new self($bytes, 0, strlen($bytes));
	}

	public function toBinaryString(): string
	{
		return substr($this->data, $this->offset, $this->length);
	}

	public function slice(int $offset, int $length): self
	{
		if ($offset < 0 || $length < 0 || $offset + $length > $this->length) {
			throw new LogicException('Invalid offset or length');
		}

		return new self($this->data, $this->offset + $offset, $length);
	}
}
