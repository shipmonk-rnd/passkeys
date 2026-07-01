<?php declare(strict_types = 1);

namespace WebAuthnX\Ceremony;

use InvalidArgumentException;
use WebAuthnX\Binary\Bytes;

/**
 * The relying-party state an authentication ceremony is verified against (WebAuthn §7.2): the
 * challenge that was issued, the RP ID and accepted origins, the `allowCredentials` list (if any),
 * the user-verification / cross-origin policy, and — when the user was identified before the
 * ceremony — the user handle their account is expected to carry.
 *
 * @api
 */
final readonly class AuthenticationExpectations
{
	/** WebAuthn §13.4.3 recommends challenges carry at least 16 bytes of entropy. */
	private const MIN_CHALLENGE_LENGTH = 16;

	/**
	 * @param  string           $rpId                   the RP ID whose SHA-256 must equal `authData.rpIdHash`
	 * @param  list<string>     $origins                exact, expected client-data origins (scheme+host+port)
	 * @param  list<Bytes>|null $allowedCredentialIds   the ids from `allowCredentials`; null or empty means a
	 *     discoverable-credential (usernameless) ceremony where no membership check applies (§7.2 step 5)
	 * @param  bool             $requireUserVerification whether the UV flag must be set (§7.2 step 17)
	 * @param  bool             $allowCrossOrigin       whether a cross-origin (iframe) assertion is acceptable
	 * @param  list<string>     $allowedTopOrigins      exact top origins accepted when the RP is sub-framed
	 *     (only consulted when `allowCrossOrigin` is true and the client reports a `topOrigin`)
	 * @param  Bytes|null       $expectedUserHandle     set when the user was identified before the ceremony
	 *     (e.g. by username); the located record — and any returned `userHandle` — must match it (§7.2 step 6)
	 * @throws InvalidArgumentException if the challenge is shorter than 16 bytes
	 */
	public function __construct(
		public Bytes $challenge,
		public string $rpId,
		public array $origins,
		public ?array $allowedCredentialIds = null,
		public bool $requireUserVerification = false,
		public bool $allowCrossOrigin = false,
		public array $allowedTopOrigins = [],
		public ?Bytes $expectedUserHandle = null,
	) {
		if ($challenge->length < self::MIN_CHALLENGE_LENGTH) {
			throw new InvalidArgumentException('Challenge must be at least ' . self::MIN_CHALLENGE_LENGTH . ' bytes');
		}
	}
}
