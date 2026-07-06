<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Options;

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
