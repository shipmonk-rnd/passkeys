<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Binary;

use ShipMonk\Passkeys\Binary\BytesReader;
use ShipMonk\Passkeys\Binary\BytesReaderException;
use ShipMonk\PasskeysTests\PasskeysTestCase;

final class BytesReaderTest extends PasskeysTestCase
{

    public function testRead(): void
    {
        self::assertSame(
            123,
            BytesReader::read('', static function (): int {
                return 123;
            }),
        );

        self::assertException(
            BytesReaderException::class,
            'Unexpected data after end',
            static function (): void {
                BytesReader::read('ABC', static function (BytesReader $reader): void {
                    $reader->u8();
                });
            },
        );
    }

    public function testU8(): void
    {
        BytesReader::read("\x00\x01\x02\x03", static function (BytesReader $reader): void {
            self::assertSame(0, $reader->u8());
            self::assertSame(1, $reader->u8());
            self::assertSame(2, $reader->u8());
            self::assertSame(3, $reader->u8());
        });

        self::assertException(
            BytesReaderException::class,
            'Unexpected end of data',
            static function (): void {
                BytesReader::read('', static function (BytesReader $reader): void {
                    $reader->u8();
                });
            },
        );
    }

    public function testU16(): void
    {
        BytesReader::read("\x00\x01\x02\x03", static function (BytesReader $reader): void {
            self::assertSame(1, $reader->u16());
            self::assertSame(515, $reader->u16());
        });

        self::assertException(
            BytesReaderException::class,
            'Unexpected end of data',
            static function (): void {
                BytesReader::read('', static function (BytesReader $reader): void {
                    $reader->u16();
                });
            },
        );

        self::assertException(
            BytesReaderException::class,
            'Unexpected end of data',
            static function (): void {
                BytesReader::read("\x00", static function (BytesReader $reader): void {
                    $reader->u16();
                });
            },
        );
    }

    public function testU32(): void
    {
        BytesReader::read("\x00\x01\x02\x03", static function (BytesReader $reader): void {
            self::assertSame(66_051, $reader->u32());
        });

        self::assertException(
            BytesReaderException::class,
            'Unexpected end of data',
            static function (): void {
                BytesReader::read('', static function (BytesReader $reader): void {
                    $reader->u32();
                });
            },
        );
    }

    public function testU64(): void
    {
        BytesReader::read("\x00\x01\x02\x03\x04\x05\x06\x07", static function (BytesReader $reader): void {
            self::assertSame(283_686_952_306_183, $reader->u64());
        });

        BytesReader::read("\x7f\xff\xff\xff\xff\xff\xff\xff", static function (BytesReader $reader): void {
            self::assertSame(9_223_372_036_854_775_807, $reader->u64());
        });

        self::assertException(
            BytesReaderException::class,
            'Value is too large for 64-bit signed integer',
            static function (): void {
                BytesReader::read("\x80\x00\x00\x00\x00\x00\x00\x00", static function (BytesReader $reader): void {
                    $reader->u64();
                });
            },
        );

        self::assertException(
            BytesReaderException::class,
            'Unexpected end of data',
            static function (): void {
                BytesReader::read('', static function (BytesReader $reader): void {
                    $reader->u64();
                });
            },
        );
    }

    public function testBytes(): void
    {
        BytesReader::read("\x00\x01\x02\x03", static function (BytesReader $reader): void {
            self::assertSame("\x00\x01\x02", $reader->bytes(3));
            self::assertSame("\x03", $reader->bytes(1));
        });

        BytesReader::read('AB', static function (BytesReader $reader): void {
            self::assertSame('A', $reader->bytes(1));
            self::assertSame('', $reader->bytes(0));
            self::assertSame('B', $reader->bytes(1));
        });

        self::assertException(
            BytesReaderException::class,
            'Unexpected end of data',
            static function (): void {
                BytesReader::read('', static function (BytesReader $reader): void {
                    $reader->bytes(1);
                });
            },
        );

        self::assertException(
            BytesReaderException::class,
            'Unexpected end of data',
            static function (): void {
                BytesReader::read('A', static function (BytesReader $reader): void {
                    $reader->bytes(2);
                });
            },
        );
    }

    public function testUtf8(): void
    {
        BytesReader::read('abc', static function (BytesReader $reader): void {
            self::assertSame('abc', $reader->utf8(3));
        });

        BytesReader::read("\u{1F525}", static function (BytesReader $reader): void {
            self::assertSame("\u{1F525}", $reader->utf8(4));
        });

        self::assertException(
            BytesReaderException::class,
            'Invalid UTF-8 string',
            static function (): void {
                BytesReader::read("\u{1F525}", static function (BytesReader $reader): void {
                    $reader->utf8(3);
                });
            },
        );

        self::assertException(
            BytesReaderException::class,
            'Invalid UTF-8 string',
            static function (): void {
                BytesReader::read("\u{D800}", static function (BytesReader $reader): void {
                    $reader->utf8(3);
                });
            },
        );

        self::assertException(
            BytesReaderException::class,
            'Unexpected end of data',
            static function (): void {
                BytesReader::read('', static function (BytesReader $reader): void {
                    $reader->utf8(1);
                });
            },
        );

        self::assertException(
            BytesReaderException::class,
            'Unexpected end of data',
            static function (): void {
                BytesReader::read('A', static function (BytesReader $reader): void {
                    $reader->utf8(2);
                });
            },
        );
    }

}
