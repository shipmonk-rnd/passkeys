<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Options;

/**
 * @api
 */
abstract readonly class PublicKeyCredentialEntity
{

    public function __construct(
        public string $name,
    )
    {
    }

}
