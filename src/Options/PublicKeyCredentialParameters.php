<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Options;

use JsonSerializable;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Enum\PublicKeyCredentialType;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters
 * @api
 */
final readonly class PublicKeyCredentialParameters implements JsonSerializable
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
