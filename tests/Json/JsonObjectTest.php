<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Json;

use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\Json\JsonObjectException;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function array_map;

class JsonObjectTest extends PasskeysTestCase
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
        $object = self::jsonObject(['yes' => true, 'no' => false]);

        self::assertTrue($object->getOptionalBoolean('yes'));
        self::assertFalse($object->getOptionalBoolean('no'));
    }

    public function testGetOptionalBooleanReturnsNullWhenAbsent(): void
    {
        self::assertNull(self::jsonObject([])->getOptionalBoolean('missing'));
    }

    public function testGetOptionalBooleanRejectsNonBoolean(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Value of key 'flag' is not a boolean",
            static fn () => self::jsonObject(['flag' => 'true'])->getOptionalBoolean('flag'),
        );
    }

    public function testGetIntReturnsValue(): void
    {
        self::assertSame(-7, self::jsonObject(['alg' => -7])->getInt('alg'));
    }

    public function testGetIntRejectsMissingKey(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Missing key 'alg' in JSON object",
            static fn () => self::jsonObject([])->getInt('alg'),
        );
    }

    public function testGetIntRejectsNonInteger(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Value of key 'alg' is not an integer",
            static fn () => self::jsonObject(['alg' => '-7'])->getInt('alg'),
        );
    }

    public function testGetObjectListReturnsValues(): void
    {
        $list = self::jsonObject(['params' => [['alg' => -7], ['alg' => -257]]])->getObjectList('params');

        self::assertSame([-7, -257], array_map(static fn (JsonObject $item) => $item->getInt('alg'), $list));
    }

    public function testGetObjectListRejectsMissingKey(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Missing key 'params' in JSON object",
            static fn () => self::jsonObject([])->getObjectList('params'),
        );
    }

    public function testGetOptionalObjectListReturnsNullWhenAbsent(): void
    {
        self::assertNull(self::jsonObject([])->getOptionalObjectList('params'));
    }

    public function testGetOptionalObjectListRejectsNonArray(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Value of key 'params' is not an array",
            static fn () => self::jsonObject(['params' => 'nope'])->getOptionalObjectList('params'),
        );
    }

    public function testGetOptionalObjectListRejectsNonObjectItem(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Value of key 'params' is not an array of objects",
            static fn () => self::jsonObject(['params' => [1, 2]])->getOptionalObjectList('params'),
        );
    }

}
