<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Credential;

use ShipMonk\WebAuthn\Binary\BytesReader;
use ShipMonk\WebAuthn\Binary\BytesReaderException;
use ShipMonk\WebAuthn\Cbor\CborMap;
use ShipMonk\WebAuthn\Cbor\CborMapException;
use ShipMonk\WebAuthn\Cbor\InvalidCborException;
use ShipMonk\WebAuthn\Cose\CoseKey;
use ShipMonk\WebAuthn\Cose\CoseKeyException;

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
