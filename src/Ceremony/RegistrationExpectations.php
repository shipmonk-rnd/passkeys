<?php declare(strict_types = 1);

namespace WebAuthnX\Ceremony;

use InvalidArgumentException;
use WebAuthnX\Binary\Bytes;

/**
 * The relying-party state a registration ceremony is verified against (WebAuthn §7.1): the
 * challenge that was issued, the RP ID and the origins the RP will accept, the algorithms it
 * offered in `pubKeyCredParams`, and its user-verification / cross-origin / mediation policy.
 */
final readonly class RegistrationExpectations
{
	/** WebAuthn §13.4.3 recommends challenges carry at least 16 bytes of entropy. */
	private const MIN_CHALLENGE_LENGTH = 16;

	/**
	 * @param  string             $rpId              the RP ID whose SHA-256 must equal `authData.rpIdHash`
	 * @param  list<string>       $origins           exact, expected client-data origins (scheme+host+port)
	 * @param  list<int>          $allowedAlgorithms COSE algorithm identifiers offered in `pubKeyCredParams`
	 * @param  bool               $requireUserVerification whether the UV flag must be set (§7.1 step 16)
	 * @param  bool               $allowCrossOrigin  whether a cross-origin (iframe) creation is acceptable
	 * @param  list<string>       $allowedTopOrigins exact top origins accepted when the RP is sub-framed
	 *     (only consulted when `allowCrossOrigin` is true and the client reports a `topOrigin`)
	 * @param  bool               $conditionalMediation set when `mediation: "conditional"` was used, which
	 *     relaxes the User Present requirement of §7.1 step 15
	 * @throws InvalidArgumentException if the challenge is shorter than 16 bytes
	 */
	public function __construct(
		public Bytes $challenge,
		public string $rpId,
		public array $origins,
		public array $allowedAlgorithms,
		public bool $requireUserVerification = false,
		public bool $allowCrossOrigin = false,
		public array $allowedTopOrigins = [],
		public bool $conditionalMediation = false,
	) {
		if ($challenge->length < self::MIN_CHALLENGE_LENGTH) {
			throw new InvalidArgumentException('Challenge must be at least ' . self::MIN_CHALLENGE_LENGTH . ' bytes');
		}
	}
}
