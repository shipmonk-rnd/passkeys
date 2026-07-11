<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Cose;

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
     * EdDSA; polymorphic in plain COSE, but WebAuthn §5.8.5 restricts it to Ed25519
     */
    final public const int EdDSA = -8;

    /**
     * EdDSA w/ Ed448, fully specified (RFC 9864); the only identifier usable for Ed448 within WebAuthn
     */
    final public const int Ed448 = -53;

}
