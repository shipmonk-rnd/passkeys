<?php declare(strict_types = 1);

namespace WebAuthnXTests\Json;

use WebAuthnX\Json\JsonObject;
use WebAuthnX\Json\JsonObjectException;
use WebAuthnXTests\WebAuthnTestCase;

class JsonObjectTest extends WebAuthnTestCase
{
	public function testFromStringRejectsInvalidJson(): void
	{
		self::assertException(
			JsonObjectException::class,
			'Invalid JSON',
			static fn () => JsonObject::fromString('{not valid json'),
		);
	}

	public function testFromStringRejectsNonObject(): void
	{
		self::assertException(
			JsonObjectException::class,
			'JSON is not an object',
			static fn () => JsonObject::fromString('[1, 2, 3]'),
		);
	}

	public function testGetOptionalBooleanReturnsValue(): void
	{
		$object = JsonObject::fromArray(['yes' => true, 'no' => false]);

		self::assertTrue($object->getOptionalBoolean('yes'));
		self::assertFalse($object->getOptionalBoolean('no'));
	}

	public function testGetOptionalBooleanReturnsNullWhenAbsent(): void
	{
		self::assertNull(JsonObject::fromArray([])->getOptionalBoolean('missing'));
	}

	public function testGetOptionalBooleanRejectsNonBoolean(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Value of key 'flag' is not a boolean",
			static fn () => JsonObject::fromArray(['flag' => 'true'])->getOptionalBoolean('flag'),
		);
	}
}
