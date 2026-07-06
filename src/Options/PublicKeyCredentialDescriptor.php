<?php declare(strict_types = 1);

namespace WebAuthnX\Options;

use JsonSerializable;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Enum\PublicKeyCredentialType;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptorjson
 * @api
 */
readonly class PublicKeyCredentialDescriptor implements JsonSerializable
{

    /**
     * @param PublicKeyCredentialType::* $type
     * @param string                     $id         raw credential id bytes; base64url encoding
     *                                 happens on serialization
     * @param list<string>|null          $transports usually {@see AuthenticatorTransport} values,
     *              but a relying party should echo whatever it stored at registration — clients ignore
     *              unknown values
     */
    public function __construct(
        public string $type,
        public string $id,
        public ?array $transports = null,
    )
    {
    }

    /**
     * @return array<string, mixed>
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
