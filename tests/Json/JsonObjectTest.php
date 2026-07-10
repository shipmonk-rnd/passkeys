<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Json;

use PHPUnit\Framework\Attributes\CoversClass;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\Json\JsonObjectException;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function array_map;

#[CoversClass(JsonObject::class)]
final class JsonObjectTest extends PasskeysTestCase
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

    public function testGetStringReturnsValue(): void
    {
        self::assertSame('example.com', self::jsonObject(['rpId' => 'example.com'])->getString('rpId'));
    }

    public function testGetStringRejectsMissingKey(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Missing key 'rpId' in JSON object",
            static fn () => self::jsonObject([])->getString('rpId'),
        );
    }

    public function testGetStringRejectsNonString(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Value of key 'rpId' is not a string",
            static fn () => self::jsonObject(['rpId' => 42])->getString('rpId'),
        );
    }

    public function testGetOptionalStringReturnsValueOrNull(): void
    {
        self::assertSame('example.com', self::jsonObject(['rpId' => 'example.com'])->getOptionalString('rpId'));
        self::assertNull(self::jsonObject([])->getOptionalString('rpId'));
    }

    public function testGetOptionalStringRejectsNonString(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Value of key 'rpId' is not a string",
            static fn () => self::jsonObject(['rpId' => 42])->getOptionalString('rpId'),
        );
    }

    public function testGetObjectReturnsNestedObject(): void
    {
        $rp = self::jsonObject(['rp' => ['id' => 'example.com']])->getObject('rp');

        self::assertSame('example.com', $rp->getString('id'));
    }

    public function testGetObjectRejectsMissingKey(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Missing key 'rp' in JSON object",
            static fn () => self::jsonObject([])->getObject('rp'),
        );
    }

    public function testGetObjectRejectsNonObject(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Value of key 'rp' is not an object",
            static fn () => self::jsonObject(['rp' => 'nope'])->getObject('rp'),
        );
    }

    public function testGetOptionalObjectReturnsObjectOrNull(): void
    {
        self::assertNull(self::jsonObject([])->getOptionalObject('rp'));
        self::assertSame(
            'example.com',
            self::jsonObject(['rp' => ['id' => 'example.com']])->getOptionalObject('rp')?->getString('id'),
        );
    }

    public function testGetOptionalStringListReturnsValuesOrNull(): void
    {
        self::assertSame(
            ['usb', 'nfc'],
            self::jsonObject(['transports' => ['usb', 'nfc']])->getOptionalStringList('transports'),
        );
        self::assertNull(self::jsonObject([])->getOptionalStringList('transports'));
    }

    public function testGetOptionalStringListRejectsNonArray(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Value of key 'transports' is not an array",
            static fn () => self::jsonObject(['transports' => 'usb'])->getOptionalStringList('transports'),
        );
    }

    public function testGetOptionalStringListRejectsNonStringItem(): void
    {
        self::assertException(
            JsonObjectException::class,
            "Value of key 'transports' is not an array of strings",
            static fn () => self::jsonObject(['transports' => [1, 2]])->getOptionalStringList('transports'),
        );
    }

    public function testGetBytesDecodesBase64Url(): void
    {
        self::assertSame('hello', self::jsonObject(['id' => Base64::urlEncode('hello')])->getBytes('id'));
    }

    public function testGetOptionalBytesDecodesBase64UrlOrNull(): void
    {
        self::assertSame('hello', self::jsonObject(['id' => Base64::urlEncode('hello')])->getOptionalBytes('id'));
        self::assertNull(self::jsonObject([])->getOptionalBytes('id'));
    }

}
