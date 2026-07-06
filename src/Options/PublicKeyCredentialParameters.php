<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Options;

use JsonSerializable;
use ShipMonk\WebAuthn\Cose\CoseAlgorithmIdentifier;
use ShipMonk\WebAuthn\Enum\PublicKeyCredentialType;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters
 * @api
 */
readonly class PublicKeyCredentialParameters implements JsonSerializable
{

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    public function __construct(
        public PublicKeyCredentialType $type,
        public int $alg,
    )
    {
    }

    /**
     * @return array{
     *     type: PublicKeyCredentialType,
     *     alg: CoseAlgorithmIdentifier::*,
     * }
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type,
            'alg' => $this->alg,
        ];
    }

}
