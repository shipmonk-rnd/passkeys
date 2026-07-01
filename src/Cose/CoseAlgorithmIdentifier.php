<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

/**
 * @api
 */
class CoseAlgorithmIdentifier
{
	/** ECDSA w/ SHA-256 */
	final public const ES256 = -7;

	/** ECDSA w/ SHA-384 */
	final public const ES384 = -35;

	/** ECDSA w/ SHA-512 */
	final public const ES512 = -36;

	/** RSASSA-PKCS1-v1_5 w/ SHA-256 */
	final public const RS256 = -257;

	/** EdDSA (Ed25519) */
	final public const EdDSA = -8;
}
