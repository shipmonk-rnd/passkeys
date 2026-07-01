<?php declare(strict_types = 1);

namespace WebAuthnX\Ceremony;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cose\CoseKey;

/**
 * The persistent state a relying party stores for a registered credential, as described by the
 * {@link https://w3c.github.io/webauthn/#credential-record credential record} in WebAuthn §7.1
 * step 27. The library never persists this itself — the caller stores it after a successful
 * registration (see {@see RegistrationResult::toCredentialRecord()}) and hands it back, looked
 * up via a {@see CredentialStore}, on each authentication.
 *
 * @api
 */
final readonly class CredentialRecord
{
	/**
	 * @param  list<string>|null $transports as reported by the client at registration
	 */
	public function __construct(
		public Bytes $credentialId,
		public CoseKey $publicKey,
		public int $signCount,
		public Bytes $userHandle,
		public bool $uvInitialized,
		public bool $backupEligible,
		public bool $backupState,
		public ?array $transports = null,
	) {
	}
}
