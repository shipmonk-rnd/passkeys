<?php declare(strict_types = 1);

namespace WebAuthnX;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
 */
readonly class PublicKeyCredentialCreationOptions
{
	/**
	 * @param  list<PublicKeyCredentialParameters>      $pubKeyCredParams
	 * @param  list<PublicKeyCredentialDescriptor>|null $excludeCredentials
	 * @param  list<PublicKeyCredentialHints::*>|null   $hints
	 */
	public function __construct(
		public PublicKeyCredentialRpEntity $rp,
		public PublicKeyCredentialUserEntity $user,
		public string $challenge,
		public array $pubKeyCredParams,
		public ?int $timeout = null,
		public ?array $excludeCredentials = null,
		public ?AuthenticatorSelectionCriteria $authenticatorSelection = null,
		public ?array $hints = null,
	) {
	}
}
