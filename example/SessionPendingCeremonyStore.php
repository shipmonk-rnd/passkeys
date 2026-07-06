<?php declare(strict_types = 1);

namespace WebAuthnXDemo;

use WebAuthnX\Passkey\PendingAuthentication;
use WebAuthnX\Passkey\PendingCeremonyStore;
use WebAuthnX\Passkey\PendingRegistration;

use function array_key_exists;
use function array_shift;
use function base64_decode;
use function base64_encode;
use function count;

/**
 * The demo's {@see PendingCeremonyStore}: pending ceremonies live in the PHP session — the right
 * scope, since a ceremony belongs to one browser session — keyed by base64 challenge and capped so
 * a page that keeps requesting options cannot grow the session unboundedly.
 */
final class SessionPendingCeremonyStore implements PendingCeremonyStore
{
	/** How many unfinished ceremonies to keep per browser session (oldest dropped first). */
	private const int MAX_PENDING = 8;

	public function __construct()
	{
		$_SESSION['pending_authentications'] ??= [];
		$_SESSION['pending_registrations'] ??= [];
	}

	public function rememberPendingAuthentication(PendingAuthentication $pending): void
	{
		// One scalar "column" per ceremony: the pinned user handle (or null), under the challenge.
		$_SESSION['pending_authentications'][base64_encode($pending->challenge)] =
			$pending->userHandle === null ? null : base64_encode($pending->userHandle);

		while (count($_SESSION['pending_authentications']) > self::MAX_PENDING) {
			array_shift($_SESSION['pending_authentications']);
		}
	}

	public function consumePendingAuthentication(string $challenge): ?PendingAuthentication
	{
		$key = base64_encode($challenge);

		if (!array_key_exists($key, $_SESSION['pending_authentications'])) {
			return null;
		}

		$userHandle = $_SESSION['pending_authentications'][$key];
		unset($_SESSION['pending_authentications'][$key]);

		return new PendingAuthentication($challenge, $userHandle === null ? null : base64_decode($userHandle));
	}

	public function rememberPendingRegistration(PendingRegistration $pending): void
	{
		$_SESSION['pending_registrations'][base64_encode($pending->challenge)] = base64_encode($pending->userHandle);

		while (count($_SESSION['pending_registrations']) > self::MAX_PENDING) {
			array_shift($_SESSION['pending_registrations']);
		}
	}

	public function consumePendingRegistration(string $challenge): ?PendingRegistration
	{
		$key = base64_encode($challenge);
		$userHandle = $_SESSION['pending_registrations'][$key] ?? null;
		unset($_SESSION['pending_registrations'][$key]);

		return $userHandle === null ? null : new PendingRegistration($challenge, base64_decode($userHandle));
	}
}
