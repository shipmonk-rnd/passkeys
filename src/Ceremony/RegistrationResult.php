<?php declare(strict_types = 1);

namespace WebAuthnX\Ceremony;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cose\CoseKey;

/**
 * The outcome of a successful registration ceremony — the data a relying party persists as a
 * {@see CredentialRecord} (WebAuthn §7.1 step 27). Reaching this object at all means every §7.1
 * check passed; failures are signalled by {@see VerificationException} instead.
 *
 * @api
 */
final readonly class RegistrationResult
{
	/** Attestation conveyed no statement (`fmt: "none"`); no trust path was evaluated. */
	public const ATTESTATION_NONE = 'none';

	/**
	 * Self attestation (`fmt: "packed"` without `x5c`, §6.5.3): the statement was signed by the
	 * credential private key itself and the signature was verified. It proves possession of that
	 * key but says nothing about the authenticator's make or provenance — treat it with the same
	 * (lack of) trust as {@see self::ATTESTATION_NONE}.
	 */
	public const ATTESTATION_SELF = 'self';

	/**
	 * @param  bool              $userVerified whether the UV flag was set (the record's `uvInitialized`)
	 * @param  list<string>|null $transports   transports reported by the client, to seed later `allowCredentials`
	 * @param  self::ATTESTATION_* $attestationType how the credential was attested (no conveyed trust either way)
	 */
	public function __construct(
		public Bytes $credentialId,
		public CoseKey $publicKey,
		public int $signCount,
		public bool $userVerified,
		public bool $backupEligible,
		public bool $backupState,
		public Bytes $aaguid,
		public ?array $transports,
		public string $attestationType,
	) {
	}

	/**
	 * Assembles the persistable {@see CredentialRecord} for this registration, associating it with
	 * the user handle from the creation options' `user.id`.
	 */
	public function toCredentialRecord(Bytes $userHandle): CredentialRecord
	{
		return new CredentialRecord(
			credentialId: $this->credentialId,
			publicKey: $this->publicKey,
			signCount: $this->signCount,
			userHandle: $userHandle,
			uvInitialized: $this->userVerified,
			backupEligible: $this->backupEligible,
			backupState: $this->backupState,
			transports: $this->transports,
		);
	}
}
