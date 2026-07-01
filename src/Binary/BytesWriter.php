<?php declare(strict_types = 1);

namespace WebAuthnX\Binary;

class BytesWriter
{
	private function __construct(
		private string $bytes,
	) {
	}

	public static function createEmpty(): mixed
	{
		return new self('');
	}

	public function bytes(string $bytes): void
	{
		$this->bytes .= $bytes;
	}

	public function u8(int $value): void
	{
		$this->bytes .= pack('C', $value);
	}
}
