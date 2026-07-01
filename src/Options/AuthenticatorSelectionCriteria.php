<?php declare(strict_types = 1);

namespace WebAuthnX\Options;

use JsonSerializable;
use WebAuthnX\Enum\AuthenticatorAttachment;
use WebAuthnX\Enum\ResidentKeyRequirement;
use WebAuthnX\Enum\UserVerificationRequirement;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-authenticatorselectioncriteria
 */
readonly class AuthenticatorSelectionCriteria implements JsonSerializable
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

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		$data = [];

		if ($this->authenticatorAttachment !== null) {
			$data['authenticatorAttachment'] = $this->authenticatorAttachment;
		}

		if ($this->residentKey !== null) {
			$data['residentKey'] = $this->residentKey;
		}

		if ($this->requireResidentKey !== null) {
			$data['requireResidentKey'] = $this->requireResidentKey;
		}

		if ($this->userVerification !== null) {
			$data['userVerification'] = $this->userVerification;
		}

		return $data;
	}
}
