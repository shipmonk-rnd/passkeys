<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Cose;

/**
 * @api
 */
final class CoseAlgorithmIdentifier
{

    /**
     * ECDSA w/ SHA-256
     */
    public const ES256 = -7;

    /**
     * ECDSA w/ SHA-384
     */
    public const ES384 = -35;

    /**
     * ECDSA w/ SHA-512
     */
    public const ES512 = -36;

    /**
     * RSASSA-PKCS1-v1_5 w/ SHA-256
     */
    public const RS256 = -257;

    /**
     * EdDSA; polymorphic in plain COSE, but WebAuthn §5.8.5 restricts it to Ed25519
     */
    public const EdDSA = -8;

}
