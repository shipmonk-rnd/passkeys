<?php declare(strict_types = 1);

namespace WebAuthnX\Cbor;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;

use function is_array;
use function is_int;
use function is_string;

readonly class CborMap
{
	/**
	 * @param  array<int|string, mixed> $map
	 */
	private function __construct(
		private array $map,
	) {
	}

	/**
	 * @throws InvalidCborException
	 * @throws CborMapException
	 */
	public static function fromBytesReader(BytesReader $bytesReader): self
	{
		$data = CborDecoder::decode($bytesReader);

		if (!is_array($data)) {
			throw new CborMapException('CBOR value is not a map');
		}

		return new self($data);
	}

	public function has(int|string $key): bool
	{
		return array_key_exists($key, $this->map);
	}

	/**
	 * @throws CborMapException
	 */
	public function getInt(int|string $key): int
	{
		$value = $this->getMixed($key);

		if (!is_int($value)) {
			throw new CborMapException("Key '$key' is not an integer");
		}

		return $value;
	}

	/**
	 * @throws CborMapException
	 */
	public function getString(int|string $key): string
	{
		$value = $this->getMixed($key);

		if (!is_string($value)) {
			throw new CborMapException("Key '$key' is not a string");
		}

		return $value;
	}

	/**
	 * @throws CborMapException
	 */
	public function getBytes(int|string $key): Bytes
	{
		$value = $this->getMixed($key);

		if (!$value instanceof Bytes) {
			throw new CborMapException("Key '$key' is not a byte string");
		}

		return $value;
	}

	/**
	 * @throws CborMapException
	 */
	public function getMap(int|string $key): self
	{
		$value = $this->getMixed($key);

		if (!is_array($value)) {
			throw new CborMapException("Key '$key' is not a map");
		}

		return new self($value);
	}

	/**
	 * @throws CborMapException
	 */
	private function getMixed(int|string $key): mixed
	{
		if (!array_key_exists($key, $this->map)) {
			throw new CborMapException("Key '$key' not found");
		}

		return $this->map[$key];
	}
}
