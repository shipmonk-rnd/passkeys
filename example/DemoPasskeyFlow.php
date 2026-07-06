<?php declare(strict_types = 1);

namespace WebAuthnXDemo;

use WebAuthnX\Ceremony\AuthenticationResult;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Passkey\PasskeyFlow;
use WebAuthnX\Passkey\PendingAuthentication;

use function array_shift;
use function array_key_exists;
use function base64_decode;
use function base64_encode;
use function count;

/**
 * The demo's {@see PasskeyFlow}: account/credential lookups delegate to {@see PasskeyStore},
 * pending ceremonies live in the PHP session (keyed by base64 challenge, capped so a page that
 * keeps requesting options cannot grow the session unboundedly). Policy hooks are left at their
 * defaults — user verification required, 300 s timeout, 32-byte challenges.
 */
final class DemoPasskeyFlow extends PasskeyFlow
{
	/** How many unfinished ceremonies to keep per browser session (oldest dropped first). */
	private const int MAX_PENDING = 8;

	/**
	 * @param list<string> $origins
	 */
	public function __construct(
		private readonly PasskeyStore $store,
		private readonly string $rpId,
		private readonly array $origins,
	) {
		parent::__construct();
		$_SESSION['pending_authentications'] ??= [];
	}

	public function findByCredentialId(string $credentialId): ?CredentialRecord
	{
		return $this->store->findByCredentialId($credentialId);
	}

	protected function getRelyingPartyId(): string
	{
		return $this->rpId;
	}

	protected function getAllowedOrigins(): array
	{
		return $this->origins;
	}

	protected function findUserHandleByUsername(string $username): ?string
	{
		$user = $this->store->findUserByEmail($username);

		return $user === null ? null : base64_decode($user['user_handle']);
	}

	protected function findCredentialsByUserHandle(string $userHandle): array
	{
		$records = [];

		foreach ($this->store->credentialsForUser($userHandle) as $row) {
			$record = $this->store->findByCredentialId(base64_decode($row['credential_id']));

			if ($record !== null) {
				$records[] = $record;
			}
		}

		return $records;
	}

	protected function rememberPendingAuthentication(PendingAuthentication $pending): void
	{
		// One scalar "column" per ceremony: the pinned user handle (or null), under the challenge.
		$_SESSION['pending_authentications'][base64_encode($pending->challenge)] =
			$pending->userHandle === null ? null : base64_encode($pending->userHandle);

		while (count($_SESSION['pending_authentications']) > self::MAX_PENDING) {
			array_shift($_SESSION['pending_authentications']);
		}
	}

	protected function consumePendingAuthentication(string $challenge): ?PendingAuthentication
	{
		$key = base64_encode($challenge);

		if (!array_key_exists($key, $_SESSION['pending_authentications'])) {
			return null;
		}

		$userHandle = $_SESSION['pending_authentications'][$key];
		unset($_SESSION['pending_authentications'][$key]);

		return new PendingAuthentication($challenge, $userHandle === null ? null : base64_decode($userHandle));
	}

	protected function updateCredential(AuthenticationResult $result): void
	{
		// A real relying party would also persist $result->backupState and $result->userVerified
		// (uvInitialized), and could alert on $result->possibleClone; the demo tracks the counter.
		$this->store->updateSignCount($result->credentialId, $result->newSignCount);
	}
}
