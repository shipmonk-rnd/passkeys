<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Options;

use JsonSerializable;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Enum\PublicKeyCredentialType;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptorjson
 * @api
 */
final readonly class PublicKeyCredentialDescriptor implements JsonSerializable
{

    /**
     * @param string            $id         raw credential id bytes; base64url encoding happens on serialization
     * @param list<string>|null $transports usually {@see AuthenticatorTransport} values,
     *              but a relying party should echo whatever it stored at registration — clients ignore
     *              unknown values
     */
    public function __construct(
        public PublicKeyCredentialType $type,
        public string $id,
        public ?array $transports = null,
    )
    {
    }

    /**
     * @return array{
     *     type: PublicKeyCredentialType,
     *     id: string,
     *     transports?: list<string>,
     * }
     */
    public function jsonSerialize(): array
    {
        $data = [
            'type' => $this->type,
            'id' => Base64::urlEncode($this->id),
        ];

        if ($this->transports !== null) {
            $data['transports'] = $this->transports;
        }

        return $data;
    }

}
