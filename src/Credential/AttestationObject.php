<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;

/**
 * @api
 */
readonly class AttestationObject
{
	private function __construct(
		public Bytes $authData,
		public string $fmt,
		public CborMap $attStmt,
	) {
	}

	/**
	 * @throws CborMapException
	 */
	public static function fromCborMap(CborMap $map): AttestationObject
	{
		return new self(
			$map->getBytes('authData'),
			$map->getString('fmt'),
			$map->getMap('attStmt'), // keys are utf-8 strings
		);
	}

	/**
	 * @throws MalformedDataException
	 */
	public function parseAuthenticatorData(): AuthenticatorData
	{
		return AuthenticatorData::fromBytes($this->authData);
	}
}
