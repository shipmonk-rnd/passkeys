<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Signal;

use JsonSerializable;
use ShipMonk\Passkeys\Base64\Base64;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * The payload for `PublicKeyCredential.signalCurrentUserDetails()` (WebAuthn §5.1.10.4): the user's
 * current `name` / `displayName`, so the credential provider keeps the metadata it shows for their
 * passkeys current. It only updates existing passkeys' metadata — it never adds or prunes.
 *
 * {@see \ShipMonk\Passkeys\PasskeyFlow::currentUserDetailsSignal()} builds it and documents when to send it.
 *
 * @see https://w3c.github.io/webauthn/#sctn-signalCurrentUserDetails
 * @api
 */
final readonly class CurrentUserDetailsSignal implements JsonSerializable
{

    /**
     * @param string $rpId        the {@link https://w3c.github.io/webauthn/#rp-id RP ID} the credentials are scoped to
     * @param string $userId      raw user handle bytes
     * @param string $name        the account's current human-readable identifier (email/username)
     * @param string $displayName the account's current friendly label
     */
    public function __construct(
        public string $rpId,
        public string $userId,
        public string $name,
        public string $displayName,
    )
    {
    }

    /**
     * @return array{
     *     rpId: string,
     *     userId: string,
     *     name: string,
     *     displayName: string,
     * }
     */
    public function jsonSerialize(): array
    {
        return [
            'rpId' => $this->rpId,
            'userId' => Base64::urlEncode($this->userId),
            'name' => $this->name,
            'displayName' => $this->displayName,
        ];
    }

    public function toJson(): string
    {
        return json_encode($this, JSON_THROW_ON_ERROR);
    }

}
