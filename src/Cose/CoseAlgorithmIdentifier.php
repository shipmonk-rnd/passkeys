<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

/**
 * @api
 */
class CoseAlgorithmIdentifier
{

    /**
     * ECDSA w/ SHA-256
     */
    final public const int ES256 = -7;

    /**
     * ECDSA w/ SHA-384
     */
    final public const int ES384 = -35;

    /**
     * ECDSA w/ SHA-512
     */
    final public const int ES512 = -36;

    /**
     * RSASSA-PKCS1-v1_5 w/ SHA-256
     */
    final public const int RS256 = -257;

    /**
     * EdDSA (Ed25519 or Ed448)
     */
    final public const int EdDSA = -8;

    /**
     * EdDSA w/ Ed25519, fully specified (RFC 9864); equivalent to {@see self::EdDSA} on that curve
     */
    final public const int Ed25519 = -19;

    /**
     * EdDSA w/ Ed448, fully specified (RFC 9864); equivalent to {@see self::EdDSA} on that curve
     */
    final public const int Ed448 = -53;

}
