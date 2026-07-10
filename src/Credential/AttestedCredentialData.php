<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Credential;

use ShipMonk\Passkeys\Binary\BytesReader;
use ShipMonk\Passkeys\Binary\BytesReaderException;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cbor\CborMapException;
use ShipMonk\Passkeys\Cbor\InvalidCborException;
use ShipMonk\Passkeys\Cose\CoseKey;
use ShipMonk\Passkeys\Cose\CoseKeyException;

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
    )
    {
    }

    /**
     * @throws BytesReaderException
     * @throws CborMapException
     * @throws CoseKeyException
     * @throws InvalidCborException
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
