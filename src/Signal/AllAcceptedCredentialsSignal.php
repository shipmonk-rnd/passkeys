<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Signal;

use JsonSerializable;
use ShipMonk\Passkeys\Base64\Base64;
use function array_map;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * The payload for `PublicKeyCredential.signalAllAcceptedCredentials()` (WebAuthn §5.1.10.3): gives
 * the credential provider the *complete* set of credential ids the relying party currently accepts
 * for a user, so it can prune any passkey no longer in the list. Signal it after a successful
 * sign-in and whenever the user's credential set changes (a passkey removed, the account deleted —
 * pass an empty list to prune them all).
 *
 * The list must be authoritative and complete: a provider hides any of its passkeys you omit, so an
 * incomplete list can lock the user out of a valid passkey. It only ever prunes — it cannot add a
 * credential the provider does not already hold.
 *
 * @see https://w3c.github.io/webauthn/#sctn-signalAllAcceptedCredentials
 * @api
 */
readonly class AllAcceptedCredentialsSignal implements JsonSerializable
{

    /**
     * @param string       $rpId                     the {@link https://w3c.github.io/webauthn/#rp-id RP ID} the credentials are scoped to
     * @param string       $userId                   raw user handle bytes; base64url encoding happens on serialization
     * @param list<string> $allAcceptedCredentialIds raw credential id bytes for every credential still accepted for the user; base64url encoding happens on serialization
     */
    public function __construct(
        public string $rpId,
        public string $userId,
        public array $allAcceptedCredentialIds,
    )
    {
    }

    /**
     * @return array{
     *     rpId: string,
     *     userId: string,
     *     allAcceptedCredentialIds: list<string>,
     * }
     */
    public function jsonSerialize(): array
    {
        return [
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
