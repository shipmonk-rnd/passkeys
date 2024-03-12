<?php declare(strict_types = 1);

namespace WebAuthnXTests\Binary;

use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use WebAuthnX\Binary\Bytes;
use WebAuthnXTests\WebAuthnTestCase;

#[CoversClass(Bytes::class)]
class BytesTest extends WebAuthnTestCase
{
	public function testFromBinaryString(): void
	{
		$bytes = Bytes::fromBinaryString('');
		self::assertSame('', $bytes->data);
		self::assertSame(0, $bytes->offset);
		self::assertSame(0, $bytes->length);

		$bytes = Bytes::fromBinaryString('abc');
		self::assertSame('abc', $bytes->data);
		self::assertSame(0, $bytes->offset);
	}

	public function testToBinaryString(): void
	{
		self::assertSame('', Bytes::fromBinaryString('')->toBinaryString());
		self::assertSame('abc', Bytes::fromBinaryString('abc')->toBinaryString());
	}

	public function testSlice(): void
	{
		$bytes = Bytes::fromBinaryString('abc');
		self::assertSame('a', $bytes->slice(0, 1)->toBinaryString());
		self::assertSame('b', $bytes->slice(1, 1)->toBinaryString());
		self::assertSame('c', $bytes->slice(2, 1)->toBinaryString());
		self::assertSame('ab', $bytes->slice(0, 2)->toBinaryString());
		self::assertSame('bc', $bytes->slice(1, 2)->toBinaryString());
		self::assertSame('abc', $bytes->slice(0, 3)->toBinaryString());

		self::assertSame('b', $bytes->slice(1, 2)->slice(0, 1)->toBinaryString());
		self::assertSame('c', $bytes->slice(1, 2)->slice(1, 1)->toBinaryString());
		self::assertSame('', $bytes->slice(1, 2)->slice(1, 0)->toBinaryString());

		$this->assertException(LogicException::class, 'Invalid offset or length', function () use ($bytes): void {
			$bytes->slice(0, 4);
		});

		$this->assertException(LogicException::class, 'Invalid offset or length', function () use ($bytes): void {
			$bytes->slice(1, 3);
		});

		$this->assertException(LogicException::class, 'Invalid offset or length', function () use ($bytes): void {
			$bytes->slice(2, 2);
		});
	}
}
