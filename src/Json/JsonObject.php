<?php declare(strict_types = 1);

namespace WebAuthnX\Json;

use JsonException;
use stdClass;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Base64\InvalidBase64Exception;
use WebAuthnX\Binary\Bytes;
use function is_array;
use function is_string;


/**
 * @api
 */
readonly class JsonObject
{
	private function __construct(
		private stdClass $object,
	) {
	}


	/**
	 * @throws JsonObjectException
	 */
	public static function fromString(string $json): self
	{
		try {
			$data = json_decode($json, flags: JSON_THROW_ON_ERROR);

		} catch (JsonException $e) {
			throw new JsonObjectException('Invalid JSON', previous: $e);
		}

		if (!$data instanceof stdClass) {
			throw new JsonObjectException('JSON is not an object');
		}

		return new self($data);
	}


	/**
	 * @throws JsonObjectException
	 */
	public static function fromBytes(Bytes $bytes): self
	{
		return self::fromString($bytes->toBinaryString());
	}


	/**
	 * @throws JsonObjectException
	 */
	public function getOptionalBoolean(string $key): ?bool
	{
		if (!isset($this->object->$key)) {
			return null;
		}

		if (!is_bool($this->object->$key)) {
			throw new JsonObjectException("Value of key '$key' is not a boolean");
		}

		return $this->object->$key;
	}


	/**
	 * @throws JsonObjectException
	 */
	public function getString(string $key): string
	{
		if (!isset($this->object->$key)) {
			throw new JsonObjectException("Missing key '$key' in JSON object");
		}

		if (!is_string($this->object->$key)) {
			throw new JsonObjectException("Value of key '$key' is not a string");
		}

		return $this->object->$key;
	}


	/**
	 * @return list<string>|null
	 * @throws JsonObjectException
	 */
	public function getOptionalStringList(string $key): ?array
	{
		if (!isset($this->object->$key)) {
			return null;
		}

		if (!is_array($this->object->$key)) {
			throw new JsonObjectException("Value of key '$key' is not an array");
		}

		$list = [];

		foreach ($this->object->$key as $item) {
			if (!is_string($item)) {
				throw new JsonObjectException("Value of key '$key' is not an array of strings");
			}

			$list[] = $item;
		}

		return $list;
	}


	/**
	 * @throws JsonObjectException
	 */
	public function getObject(string $key): self
	{
		if (!isset($this->object->$key)) {
			throw new JsonObjectException("Missing key '$key' in JSON object");
		}

		if (!$this->object->$key instanceof stdClass) {
			throw new JsonObjectException("Value of key '$key' is not an object");
		}

		return new self($this->object->$key);
	}


	/**
	 * @throws JsonObjectException
	 */
	public function getOptionalObject(string $key): ?self
	{
		if (!isset($this->object->$key)) {
			return null;
		}

		return $this->getObject($key);
	}


	/**
	 * @throws JsonObjectException
	 */
	public function getOptionalString(string $key): ?string
	{
		if (!isset($this->object->$key)) {
			return null;
		}

		if (!is_string($this->object->$key)) {
			throw new JsonObjectException("Value of key '$key' is not a string");
		}

		return $this->object->$key;
	}


	/**
	 * @throws JsonObjectException
	 * @throws InvalidBase64Exception
	 */
	public function getBytes(string $key): Bytes
	{
		return Bytes::fromBinaryString(Base64::urlDecode($this->getString($key)));
	}


	/**
	 * @throws JsonObjectException
	 * @throws InvalidBase64Exception
	 */
	public function getOptionalBytes(string $key): ?Bytes
	{
		if (!isset($this->object->$key)) {
			return null;
		}

		return Bytes::fromBinaryString(Base64::urlDecode($this->getString($key)));
	}
}
