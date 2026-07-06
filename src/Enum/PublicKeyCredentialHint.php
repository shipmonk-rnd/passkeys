<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Enum;

/**
 * @api
 */
enum PublicKeyCredentialHint: string
{

    case SECURITY_KEY = 'security-key';
    case CLIENT_DEVICE = 'client-device';
    case HYBRID = 'hybrid';

}
