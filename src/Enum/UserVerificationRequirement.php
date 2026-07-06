<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Enum;

/**
 * @api
 */
enum UserVerificationRequirement: string
{

    case DISCOURAGED = 'discouraged';
    case PREFERRED = 'preferred';
    case REQUIRED = 'required';

}
