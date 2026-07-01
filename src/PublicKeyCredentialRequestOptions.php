<?php declare(strict_types = 1);

namespace WebAuthnX;

use JsonSerializable;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Binary\Bytes;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * Options for an authentication ceremony, serializable to the
 * {@link https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptionsjson PublicKeyCredentialRequestOptionsJSON}
 * form consumed by the browser.
 *
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions
 */
readonly class PublicKeyCredentialRequestOptions implements JsonSerializable
{
	/**
	 * @param  list<PublicKeyCredentialDescriptor>|null $allowCredentials
	 * @param  UserVerificationRequirement::*|null      $userVerification
	 * @param  list<PublicKeyCredentialHints::*>|null   $hints
	 */
	public function __construct(
		public Bytes $challenge,
		public ?int $timeout = null,
		public ?string $rpId = null,
		public ?array $allowCredentials = null,
		public ?string $userVerification = null,
		public ?array $hints = null,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		$data = [
			'challenge' => Base64::urlEncode($this->challenge->toBinaryString()),
		];

		if ($this->timeout !== null) {
			$data['timeout'] = $this->timeout;
		}

		if ($this->rpId !== null) {
			$data['rpId'] = $this->rpId;
		}

		if ($this->allowCredentials !== null) {
			$data['allowCredentials'] = $this->allowCredentials;
		}

		if ($this->userVerification !== null) {
			$data['userVerification'] = $this->userVerification;
		}

		if ($this->hints !== null) {
			$data['hints'] = $this->hints;
		}

		return $data;
	}

	public function toJson(): string
	{
		// Default escaping (slashes escaped to "<\/…") is kept deliberately: it neutralises a
		// "</script>" breakout if a relying party inlines this JSON into an HTML <script> block.
		return json_encode($this, JSON_THROW_ON_ERROR);
	}
}
