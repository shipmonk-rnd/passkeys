<?php declare(strict_types = 1);

namespace WebAuthnX;

readonly class AuthenticatorSelectionCriteria
{
	/**
	 * @param  AuthenticatorAttachment::*|null     $authenticatorAttachment
	 * @param  ResidentKeyRequirement::*|null      $residentKey
	 * @param  bool|null                           $requireResidentKey
	 * @param  UserVerificationRequirement::*|null $userVerification
	 */
	public function __construct(
		public ?string $authenticatorAttachment = null,
		public ?string $residentKey = null,
		public ?bool $requireResidentKey = null,
		public ?string $userVerification = null,
	) {
	}
}
