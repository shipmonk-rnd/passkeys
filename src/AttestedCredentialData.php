<?php declare(strict_types = 1);

namespace WebAuthnX;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;

readonly class AttestedCredentialData
{
	private function __construct(
		public Bytes $aaGuid,
		public Bytes $credentialId,
		public CborMap $credentialPublicKey,
	) {
	}

	public static function fromBytesReader(BytesReader $bytesReader): AttestedCredentialData
	{
		$aaGuid = $bytesReader->bytes(16);
		$credentialIdLength = $bytesReader->u16();
		$credentialId = $bytesReader->bytes($credentialIdLength);
		$credentialPublicKey = CborMap::fromBytesReader($bytesReader);

		return new AttestedCredentialData($aaGuid, $credentialId, $credentialPublicKey);
	}
}
