<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Options;

/**
 * @api
 */
abstract class PublicKeyCredentialEntity
{

    public function __construct(
        public readonly string $name,
    )
    {
    }

}
