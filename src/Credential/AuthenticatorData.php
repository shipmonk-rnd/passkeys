<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

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

	/**
	 * Whether the user was present (UP flag). {@see https://w3c.github.io/webauthn/#concept-user-present}
	 */
	public function isUserPresent(): bool
	{
		return ($this->flags & self::FLAG_USER_PRESENT) !== 0;
	}

	/**
	 * Whether the user was verified (UV flag). {@see https://w3c.github.io/webauthn/#concept-user-verified}
	 */
	public function isUserVerified(): bool
	{
		return ($this->flags & self::FLAG_USER_VERIFIED) !== 0;
	}

	/**
	 * Whether the credential is backup eligible (BE flag). {@see https://w3c.github.io/webauthn/#backup-eligible}
	 */
	public function isBackupEligible(): bool
	{
		return ($this->flags & self::FLAG_BACKUP_ELIGIBILITY) !== 0;
	}

	/**
	 * Whether the credential is currently backed up (BS flag). {@see https://w3c.github.io/webauthn/#backup-state}
	 */
	public function isBackupState(): bool
	{
		return ($this->flags & self::FLAG_BACKUP_STATE) !== 0;
	}

	/**
	 * Whether attested credential data is included (AT flag). Always matches
	 * {@see $attestedCredentialData} being non-null, since parsing is driven by this flag.
	 */
	public function hasAttestedCredentialData(): bool
	{
		return ($this->flags & self::FLAG_ATTESTED_CREDENTIAL_DATA) !== 0;
	}

	/**
	 * Whether extension data is included (ED flag). Always matches {@see $extensions} being non-null.
	 */
	public function hasExtensionData(): bool
	{
		return ($this->flags & self::FLAG_EXTENSION_DATA) !== 0;
	}
}
