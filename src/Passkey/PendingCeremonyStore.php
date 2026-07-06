<?php declare(strict_types = 1);

namespace WebAuthnX\Passkey;

/**
 * Transient storage for the ceremonies a {@see PasskeyFlow} has started but not yet finished,
 * keyed by their challenge. Implement it on something browser-session-scoped — the PHP session, a
 * short-TTL cache — never on durable storage: a pending ceremony is worthless minutes later, and
 * the consume-on-read semantics below are what make each challenge single-use.
 *
 * @api
 */
interface PendingCeremonyStore
{
	/**
	 * Stores a pending ceremony, keyed by its challenge. The challenge is raw bytes — fine as a
	 * PHP array key (arrays and session serialization are binary-safe), but encode it for a
	 * backend whose keys are not. Scope the storage to the browser session, and bound it: cap the
	 * number of concurrently pending ceremonies (a handful is plenty) or expire them, since a page
	 * may start several without finishing any.
	 */
	public function rememberPendingAuthentication(PendingAuthentication $pending): void;

	/**
	 * Returns **and deletes** the pending ceremony stored under this challenge, or null when
	 * there is none. The deletion is what makes each challenge single-use — the anti-replay
	 * control.
	 *
	 * The challenge comes out of the (yet unverified) response, so treat it as untrusted input:
	 * look it up, never evaluate it.
	 *
	 * @param string $challenge raw challenge bytes
	 */
	public function consumePendingAuthentication(string $challenge): ?PendingAuthentication;

	/**
	 * The registration counterpart of {@see self::rememberPendingAuthentication()} — same keying
	 * and bounding advice, but keep the two stores separate so a response can never finish a
	 * ceremony of the other kind.
	 */
	public function rememberPendingRegistration(PendingRegistration $pending): void;

	/**
	 * Returns **and deletes** the pending registration ceremony stored under this challenge, or
	 * null when there is none; see {@see self::consumePendingAuthentication()}.
	 *
	 * @param string $challenge raw challenge bytes
	 */
	public function consumePendingRegistration(string $challenge): ?PendingRegistration;
}
