<?php declare(strict_types = 1);

namespace WebAuthnX\Cbor;

use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Binary\BytesReaderException;

use function array_key_exists;
use function dechex;
use function is_int;
use function is_string;

/**
 * Implements decoder for subset of {@link https://www.rfc-editor.org/rfc/rfc8949.html CBOR} that is required by
 * WebAuthn specification.
 *
 * It targets the {@link https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctap2-canonical-cbor-encoding-form CTAP2 canonical CBOR encoding form}:
 * it does not support indefinite-length values or tagged values, and rejects duplicate map keys.
 * It does not, however, fully enforce canonicalness — it accepts non-minimal integer/length
 * encodings and out-of-order map keys. That is deliberate: WebAuthn signature verification does
 * not depend on the exact CBOR byte encoding (COSE keys are re-encoded to DER before use), so
 * decoding leniently is safe here.
 *
 * Byte strings and text strings both decode to a PHP string and are indistinguishable afterwards
 * (text strings are additionally validated as UTF-8). This too is deliberate leniency: no consumer
 * needs to tell the two apart at the same map key, only the decoded value matters.
 */
class CborDecoder
{

	/**
	 * @throws InvalidCborException
	 */
	public static function decode(BytesReader $bytes): mixed
	{
		try {
			$byte = $bytes->u8();

			return match ($byte) {
				// positive integer or zero
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 => $byte,
				0x18 => $bytes->u8(),
				0x19 => $bytes->u16(),
				0x1a => $bytes->u32(),
				0x1b => $bytes->u64(),

				// negative integer
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
				0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 => ~($byte & 0x1f),
				0x38 => ~$bytes->u8(),
				0x39 => ~$bytes->u16(),
				0x3a => ~$bytes->u32(),
				0x3b => ~$bytes->u64(),

				// byte string
				0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
				0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
				0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57 => $bytes->bytes($byte & 0x1f),
				0x58 => $bytes->bytes($bytes->u8()),
				0x59 => $bytes->bytes($bytes->u16()),
				0x5a => $bytes->bytes($bytes->u32()),
				0x5b => $bytes->bytes($bytes->u64()),

				// utf-8 string
				0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
				0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
				0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77 => $bytes->utf8($byte & 0x1f),
				0x78 => $bytes->utf8($bytes->u8()),
				0x79 => $bytes->utf8($bytes->u16()),
				0x7a => $bytes->utf8($bytes->u32()),
				0x7b => $bytes->utf8($bytes->u64()),

				// array
				0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
				0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
				0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 => self::decodeArray($bytes, $byte & 0x1f),
				0x98 => self::decodeArray($bytes, $bytes->u8()),
				0x99 => self::decodeArray($bytes, $bytes->u16()),
				0x9a => self::decodeArray($bytes, $bytes->u32()),
				0x9b => self::decodeArray($bytes, $bytes->u64()),

				// map
				0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
				0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
				0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 => self::decodeMap($bytes, $byte & 0x1f),
				0xb8 => self::decodeMap($bytes, $bytes->u8()),
				0xb9 => self::decodeMap($bytes, $bytes->u16()),
				0xba => self::decodeMap($bytes, $bytes->u32()),
				0xbb => self::decodeMap($bytes, $bytes->u64()),

				// literal
				0xf4 => false,
				0xf5 => true,
				0xf6 => null,

				// float
				0xf9 => $bytes->f16(),
				0xfa => $bytes->f32(),
				0xfb => $bytes->f64(),

				// unsupported
				default => match (true) {
					($byte & 0x1f) === 31 => throw new InvalidCborException('Indefinite-length values are not supported'),
					($byte >> 5) === 6 => throw new InvalidCborException('Tagged values are not supported'),
					($byte >> 5) === 7 => throw new InvalidCborException('Unrecognized simple value byte 0x' . dechex($byte)),
					default => throw new InvalidCborException('Unrecognized CBOR initial byte 0x' . dechex($byte)),
				},
			};

		} catch (BytesReaderException $e) {
			throw new InvalidCborException($e->getMessage(), 0, $e);
		}
	}

	/**
	 * @return list<mixed>
	 * @throws InvalidCborException
	 */
	private static function decodeArray(BytesReader $bytes, int $length): array
	{
		$array = [];

		while ($length-- > 0) {
			$array[] = self::decode($bytes);
		}

		return $array;
	}

	/**
	 * @return array<mixed>
	 * @throws InvalidCborException
	 */
	private static function decodeMap(BytesReader $bytes, int $length): array
	{
		$map = [];

		while ($length-- > 0) {
			$key = self::decode($bytes);
			$value = self::decode($bytes);

			if (!is_string($key) && !is_int($key)) {
				throw new InvalidCborException('Invalid CBOR map key type');
			}

			if (array_key_exists($key, $map)) {
				throw new InvalidCborException("Duplicate CBOR map key {$key}");
			}

			$map[$key] = $value;
		}

		return $map;
	}
}
