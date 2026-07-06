<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Binary\BytesReaderException;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnX\Cbor\InvalidCborException;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Cose\CoseKeyException;

/**
 * @api
 */
readonly class AttestedCredentialData
{
    /**
     * @param string $aaGuid       raw AAGUID bytes (16 bytes)
     * @param string $credentialId raw credential id bytes
     */
    private function __construct(
        public string $aaGuid,
        public string $credentialId,
        public CoseKey $credentialPublicKey,
    ) {
    }

    /**
     * @throws BytesReaderException
     * @throws InvalidCborException
     * @throws CborMapException
     * @throws CoseKeyException
     */
    public static function fromBytesReader(BytesReader $bytesReader): AttestedCredentialData
    {
        $aaGuid = $bytesReader->bytes(16);
        $credentialIdLength = $bytesReader->u16();
        $credentialId = $bytesReader->bytes($credentialIdLength);
        $credentialPublicKey = CoseKey::fromCborMap(CborMap::fromBytesReader($bytesReader));

        return new AttestedCredentialData($aaGuid, $credentialId, $credentialPublicKey);
    }
}
