<?php declare(strict_types = 1);

namespace WebAuthnX;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;

readonly class AuthenticatorData
{
	public const FLAG_USER_PRESENT = 1 << 0;
	public const FLAG_USER_VERIFIED = 1 << 2;
	public const FLAG_BACKUP_ELIGIBILITY = 1 << 3;
	public const FLAG_BACKUP_STATE = 1 << 4;
	public const FLAG_ATTESTED_CREDENTIAL_DATA = 1 << 6;
	public const FLAG_EXTENSION_DATA = 1 << 7;

	private function __construct(
		public Bytes $rpIdHash,
		public int $flags,
		public int $signCount,
		public ?AttestedCredentialData $attestedCredentialData,
		public ?CborMap $extensions,
	) {
	}

	public static function fromBytes(Bytes $bytes): AuthenticatorData
	{
		return BytesReader::read($bytes, static function (BytesReader $bytesReader): self {
			$rpIdHash = $bytesReader->bytes(32);
			$flags = $bytesReader->u8();
			$signCount = $bytesReader->u32();

			$attestedCredentialData = $flags & self::FLAG_ATTESTED_CREDENTIAL_DATA
				? AttestedCredentialData::fromBytesReader($bytesReader)
				: null;

			$extensions = $flags & self::FLAG_EXTENSION_DATA
				? CborMap::fromBytesReader($bytesReader) // keys are utf-8 strings
				: null;

			return new self(
				$rpIdHash,
				$flags,
				$signCount,
				$attestedCredentialData,
				$extensions,
			);
		});
	}
}
