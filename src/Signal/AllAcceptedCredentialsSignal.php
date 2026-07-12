<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Signal;

use JsonSerializable;
use ShipMonk\Passkeys\Base64\Base64;
use stdClass;
use function array_map;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * The payload for `PublicKeyCredential.signalAllAcceptedCredentials()` (WebAuthn §5.1.10.3): the
 * *complete*, authoritative set of credential ids the relying party still accepts for a user, so the
 * credential provider can prune any passkey no longer in the list. It only ever prunes — omitting a
 * still-valid credential hides it from the provider and can lock the user out — and never adds one
 * the provider does not already hold.
 *
 * {@see \ShipMonk\Passkeys\PasskeyFlow::allAcceptedCredentialsSignal()} builds it and documents when to send it.
 *
 * @see https://w3c.github.io/webauthn/#sctn-signalAllAcceptedCredentials
 * @api
 */
final readonly class AllAcceptedCredentialsSignal implements JsonSerializable
{

    /**
     * @param string       $rpId                     the {@link https://w3c.github.io/webauthn/#rp-id RP ID} the credentials are scoped to
     * @param string       $userId                   raw user handle bytes
     * @param list<string> $allAcceptedCredentialIds raw credential id bytes for every credential still accepted for the user
     */
    public function __construct(
        public string $rpId,
        public string $userId,
        public array $allAcceptedCredentialIds,
    )
    {
    }

    /**
     * @return stdClass&object{
     *     rpId: string,
     *     userId: string,
     *     allAcceptedCredentialIds: list<string>,
     * }
     */
    public function jsonSerialize(): stdClass
    {
        return (object) [
            'rpId' => $this->rpId,
            'userId' => Base64::urlEncode($this->userId),
            'allAcceptedCredentialIds' => array_map(
                static fn (string $credentialId) => Base64::urlEncode($credentialId),
                $this->allAcceptedCredentialIds,
            ),
        ];
    }

    public function toJson(): string
    {
        return json_encode($this, JSON_THROW_ON_ERROR);
    }

}
