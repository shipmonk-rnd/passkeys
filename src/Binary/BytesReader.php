<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Binary;

use Closure;
use function ord;
use function preg_match;
use function strlen;
use function substr;

/**
 * Sequential reader over a binary string, reading big-endian integers and raw byte
 * substrings while tracking the current offset. The whole input must be consumed — leftover
 * bytes are an error, so a parser cannot silently ignore trailing data.
 */
final class BytesReader
{

    private readonly int $length;

    private int $offset = 0;

    /**
     * @param string $data binary string to read from
     */
    private function __construct(
        private readonly string $data,
    )
    {
        $this->length = strlen($data);
    }

    /**
     * @param string           $bytes    binary string to read from
     * @param Closure(self): T $callback
     * @return T
     *
     * @template T
     *
     * @param-immediately-invoked-callable $callback
     * @throws BytesReaderException
     */
    public static function read(
        string $bytes,
        Closure $callback,
    ): mixed
    {
        $reader = new self($bytes);
        $result = $callback($reader);
        $reader->end();

        return $result;
    }

    /**
     * @return int<0, 255>
     *
     * @throws BytesReaderException
     */
    public function u8(): int
    {
        return ord($this->bytes(1));
    }

    /**
     * @return int<0, 65535>
     *
     * @throws BytesReaderException
     */
    public function u16(): int
    {
        $bytes = $this->bytes(2);

        return (ord($bytes[0]) << 8) + ord($bytes[1]);
    }

    /**
     * @return int<0, 4294967295>
     *
     * @throws BytesReaderException
     */
    public function u32(): int
    {
        $bytes = $this->bytes(4);

        return (ord($bytes[0]) << 24)
            + (ord($bytes[1]) << 16)
            + (ord($bytes[2]) << 8)
            + (ord($bytes[3]));
    }

    /**
     * @return non-negative-int
     *
     * @throws BytesReaderException
     */
    public function u64(): int
    {
        $bytes = $this->bytes(8);

        $value = 0;
        for ($i = 0; $i < 8; $i++) {
            $value = ($value << 8) | ord($bytes[$i]);
        }

        // A set most significant bit overflows PHP's signed 64-bit integer into a negative value.
        if ($value < 0) {
            throw new BytesReaderException('Value is too large for 64-bit signed integer');
        }

        return $value;
    }

    /**
     * @param  non-negative-int $length
     * @return string raw bytes, without any validation
     *
     * @throws BytesReaderException
     */
    public function bytes(int $length): string
    {
        if ($this->offset + $length > $this->length) {
            throw new BytesReaderException('Unexpected end of data');
        }

        $raw = substr($this->data, $this->offset, $length);
        $this->offset += $length;

        return $raw;
    }

    /**
     * @param  non-negative-int $length
     * @return string validated UTF-8 string
     *
     * @throws BytesReaderException
     */
    public function utf8(int $length): string
    {
        $binaryString = $this->bytes($length);

        if (preg_match('//u', $binaryString) !== 1) {
            throw new BytesReaderException('Invalid UTF-8 string');
        }

        return $binaryString;
    }

    /**
     * @throws BytesReaderException
     */
    private function end(): void
    {
        if ($this->offset !== $this->length) {
            throw new BytesReaderException('Unexpected data after end');
        }
    }

}
