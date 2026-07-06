<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Enum;

/**
 * @api
 */
enum ResidentKeyRequirement: string
{

    case DISCOURAGED = 'discouraged';
    case PREFERRED = 'preferred';
    case REQUIRED = 'required';

}
