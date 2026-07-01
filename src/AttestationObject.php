<?php declare(strict_types = 1);

namespace WebAuthnX;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cbor\CborMap;

readonly class AttestationObject
{
	private function __construct(
		public Bytes $authData,
		public string $fmt,
		public CborMap $attStmt,
	) {
	}

	public static function fromCborMap(CborMap $map): AttestationObject
	{
		return new static(
			$map->getBytes('authData'),
			$map->getString('fmt'),
			$map->getMap('attStmt'), // keys are utf-8 strings
		);
	}

	public function parseAuthenticatorData(): AuthenticatorData
	{
		return AuthenticatorData::fromBytes($this->authData);
	}
}
