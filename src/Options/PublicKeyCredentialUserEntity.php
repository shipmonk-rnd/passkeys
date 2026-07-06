<?php declare(strict_types = 1);

namespace WebAuthnX\Options;

use JsonSerializable;
use WebAuthnX\Base64\Base64;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentityjson
 * @api
 */
readonly class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity implements JsonSerializable
{
	/**
	 * @param string $id raw user handle bytes (an opaque identifier, at most 64 bytes — not an email or username); base64url encoding happens on serialization
	 */
	public function __construct(
		public string $id,
		string $name,
		public string $displayName,
	) {
		parent::__construct($name);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		return [
			'id' => Base64::urlEncode($this->id),
			'name' => $this->name,
			'displayName' => $this->displayName,
		];
	}
}
