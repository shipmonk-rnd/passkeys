<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Options;

use InvalidArgumentException;
use JsonSerializable;
use ShipMonk\Passkeys\Base64\Base64;
use function strlen;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentityjson
 * @api
 */
final readonly class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity implements JsonSerializable
{

    /**
     * The {@link https://w3c.github.io/webauthn/#user-handle user handle} must be 1 to 64 bytes.
     */
    private const int MAX_ID_LENGTH = 64;

    /**
     * @param string $id raw user handle bytes — an opaque identifier, not an email or username
     *
     * @throws InvalidArgumentException if the id is empty or longer than 64 bytes
     */
    public function __construct(
        public string $id,
        string $name,
        public string $displayName,
    )
    {
        if ($id === '' || strlen($id) > self::MAX_ID_LENGTH) {
            throw new InvalidArgumentException('User handle must be 1 to ' . self::MAX_ID_LENGTH . ' bytes');
        }

        parent::__construct($name);
    }

    /**
     * @return array{
     *     id: string,
     *     name: string,
     *     displayName: string,
     * }
     */
    public function jsonSerialize(): array
    {
        return [
            'id' => Base64::urlEncode($this->id),
            'name' => $this->name,
            'displayName' => $this->displayName,
        ];
    }

}
