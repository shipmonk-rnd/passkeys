<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use WebAuthnX\Ceremony\AuthenticationResult;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Enum\UserVerificationRequirement;
use WebAuthnX\Passkey\PasskeyFlow;
use WebAuthnX\Passkey\PendingAuthentication;
use WebAuthnX\Passkey\PendingRegistration;
use WebAuthnX\Passkey\RegisteredPasskey;

use function base64_encode;

/**
 * A trivial in-memory {@see PasskeyFlow} for the flow tests, standing in for the relying party's
 * real storage and session. Users and credentials are seeded via {@see addUser()} /
 * {@see addCredential()}; policy defaults can be overridden per-instance through the
 * constructor so the tests need no subclass per scenario.
 */
final class InMemoryPasskeyFlow extends PasskeyFlow
{
	/** @var array<string, string> username → raw user handle */
	private array $users = [];

	/** @var array<string, CredentialRecord> base64(credential id) → record */
	private array $credentials = [];

	/** @var array<string, PendingAuthentication> base64(challenge) → pending ceremony */
	public private(set) array $pendingAuthentications = [];

	/** @var array<string, PendingRegistration> base64(challenge) → pending ceremony */
	public private(set) array $pendingRegistrations = [];

	/** @var list<AuthenticationResult> everything passed to updateCredential() */
	public private(set) array $updatedCredentials = [];

	/** @var list<RegisteredPasskey> everything passed to saveCredential() */
	public private(set) array $savedPasskeys = [];

	/**
	 * @param list<string> $origins
	 */
	public function __construct(
		private readonly string $rpId = 'example.com',
		private readonly array $origins = ['https://example.com'],
		private readonly ?UserVerificationRequirement $userVerification = null,
		private readonly bool $crossOriginAllowed = false,
	) {
		parent::__construct();
	}

	public function addUser(string $username, string $userHandle): void
	{
		$this->users[$username] = $userHandle;
	}

	public function addCredential(CredentialRecord $record): void
	{
		$this->credentials[base64_encode($record->credentialId)] = $record;
	}

	public function findByCredentialId(string $credentialId): ?CredentialRecord
	{
		return $this->credentials[base64_encode($credentialId)] ?? null;
	}

	protected function getRelyingPartyId(): string
	{
		return $this->rpId;
	}

	protected function getRelyingPartyName(): string
	{
		return 'Example RP';
	}

	protected function getAllowedOrigins(): array
	{
		return $this->origins;
	}

	protected function findUserHandleByUsername(string $username): ?string
	{
		return $this->users[$username] ?? null;
	}

	protected function findCredentialsByUserHandle(string $userHandle): array
	{
		$records = [];

		foreach ($this->credentials as $record) {
			if ($record->userHandle === $userHandle) {
				$records[] = $record;
			}
		}

		return $records;
	}

	protected function rememberPendingAuthentication(PendingAuthentication $pending): void
	{
		$this->pendingAuthentications[base64_encode($pending->challenge)] = $pending;
	}

	protected function consumePendingAuthentication(string $challenge): ?PendingAuthentication
	{
		$key = base64_encode($challenge);
		$pending = $this->pendingAuthentications[$key] ?? null;
		unset($this->pendingAuthentications[$key]);

		return $pending;
	}

	protected function rememberPendingRegistration(PendingRegistration $pending): void
	{
		$this->pendingRegistrations[base64_encode($pending->challenge)] = $pending;
	}

	protected function consumePendingRegistration(string $challenge): ?PendingRegistration
	{
		$key = base64_encode($challenge);
		$pending = $this->pendingRegistrations[$key] ?? null;
		unset($this->pendingRegistrations[$key]);

		return $pending;
	}

	protected function saveCredential(RegisteredPasskey $passkey): void
	{
		$this->savedPasskeys[] = $passkey;
		$this->addCredential($passkey->toCredentialRecord());
	}

	protected function updateCredential(AuthenticationResult $result): void
	{
		$this->updatedCredentials[] = $result;
	}

	protected function getUserVerificationRequirement(): UserVerificationRequirement
	{
		return $this->userVerification ?? parent::getUserVerificationRequirement();
	}

	protected function isCrossOriginAllowed(): bool
	{
		return $this->crossOriginAllowed || parent::isCrossOriginAllowed();
	}
}
