<?php declare(strict_types = 1);

namespace WebAuthnX\Crypto;

use WebAuthnX\Binary\Bytes;

use function hash;

/**
 * Thin wrappers around the hash functions used by WebAuthn, e.g. to compute the
 * RP ID hash and the client-data hash.
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data authenticator data (rpIdHash)
 */
final class Hash
{
	public static function sha256(Bytes $data): Bytes
	{
		return Bytes::fromBinaryString(hash('sha256', $data->toBinaryString(), binary: true));
	}
}
