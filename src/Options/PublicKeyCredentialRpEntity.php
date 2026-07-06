<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Options;

use JsonSerializable;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
 * @api
 */
readonly class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity implements JsonSerializable
{

    /**
     * `$id` is optional: when null it is omitted from the serialized options and the browser
     * defaults the RP ID to the caller's effective domain.
     */
    public function __construct(
        string $name,
        public ?string $id = null,
    )
    {
        parent::__construct($name);
    }

    /**
     * @return array{
     *     name: string,
     *     id?: string,
     * }
     */
    public function jsonSerialize(): array
    {
        $data = ['name' => $this->name];

        if ($this->id !== null) {
            $data['id'] = $this->id;
        }

        return $data;
    }

}
