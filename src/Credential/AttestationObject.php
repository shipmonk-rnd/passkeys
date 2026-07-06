<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Credential;

use ShipMonk\WebAuthn\Cbor\CborMap;
use ShipMonk\WebAuthn\Cbor\CborMapException;

/**
 * @api
 */
readonly class AttestationObject
{

    /**
     * @param string $authData raw authenticator data bytes; parse with {@see self::parseAuthenticatorData()}
     */
    private function __construct(
        public string $authData,
        public string $fmt,
        public CborMap $attStmt,
    )
    {
    }

    /**
     * @throws CborMapException
     */
    public static function fromCborMap(CborMap $map): AttestationObject
    {
        return new self(
            $map->getString('authData'),
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
