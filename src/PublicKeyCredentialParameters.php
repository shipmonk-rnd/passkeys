<?php declare(strict_types = 1);

namespace WebAuthnX;

use WebAuthnX\Cose\CoseAlgorithmIdentifier;


readonly class PublicKeyCredentialParameters
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
}
