<?php declare(strict_types = 1);

namespace WebAuthnX\Options;

use JsonSerializable;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Binary\Bytes;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentityjson
 * @api
 */
readonly class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity implements JsonSerializable
{
	public function __construct(
		public Bytes $id,
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
			'id' => Base64::urlEncode($this->id->toBinaryString()),
			'name' => $this->name,
			'displayName' => $this->displayName,
		];
	}
}
