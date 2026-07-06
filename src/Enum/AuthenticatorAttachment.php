<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Enum;

/**
 * @api
 */
enum AuthenticatorAttachment: string
{

    case PLATFORM = 'platform';
    case CROSS_PLATFORM = 'cross-platform';

}
