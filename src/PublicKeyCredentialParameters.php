<?php declare(strict_types = 1);

namespace WebAuthnX;

use JsonSerializable;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters
 */
readonly class PublicKeyCredentialParameters implements JsonSerializable
{
	/**
	 * @param  PublicKeyCredentialType::* $type
	 * @param  CoseAlgorithmIdentifier::* $alg
	 */
	public function __construct(
		public string $type,
		public int $alg,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		return [
			'type' => $this->type,
			'alg' => $this->alg,
		];
	}
}
