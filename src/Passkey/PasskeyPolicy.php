<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Passkey;

use ShipMonk\WebAuthn\Cose\CoseAlgorithmIdentifier;
use ShipMonk\WebAuthn\Enum\ResidentKeyRequirement;
use ShipMonk\WebAuthn\Enum\UserVerificationRequirement;
use ShipMonk\WebAuthn\Options\PublicKeyCredentialRequestOptions;

/**
 * The policy choices of a {@see PasskeyFlow}, with defaults that are right for passkeys. Pass an
 * instance to the flow's constructor to deviate from a default — the natural fit for DI-container
 * wiring, where subclassing the flow just to override one getter would be noise:
 *
 * ```php
 * new PasskeyFlow(
 *     rpId: 'example.com',
 *     rpName: 'Example',
 *     origins: ['https://example.com'],
 *     store: $store,
 *     pendingCeremonyStore: $ceremonyStore,
 *     policy: new PasskeyPolicy(userVerification: UserVerificationRequirement::PREFERRED),
 * );
 * ```
 *
 * Each property is the default of the matching protected {@see PasskeyFlow} method; overriding
 * the method (for dynamic or exotic policies) still wins over the value here.
 *
 * @api
 */
final readonly class PasskeyPolicy
{

    /**
     * @param UserVerificationRequirement                $userVerification  how much the ceremony must prove about the human. The default
     *            `required` makes a passkey carry both factors (possession + PIN/biometric); use `preferred` for maximal authenticator
     *            compatibility (e.g. security keys without a PIN), trading away the second factor.
     * @param non-empty-list<CoseAlgorithmIdentifier::*> $allowedAlgorithms the COSE algorithms offered at registration, best first,
     *      and enforced on the attested key (WebAuthn §7.1 step 20). The default triple covers what real-world authenticators produce.
     * @param ResidentKeyRequirement                     $residentKey       whether new credentials must be discoverable (client-side). The
     *            default `required` is what makes the credential a passkey, and what the usernameless flow depends on.
     * @param int|null                                   $timeout           the ceremony timeout in milliseconds sent to the client (a hint;
     *            clients ignore it for conditional mediation), or null to omit it. Defaults to the spec-recommended 300 s.
     * @param bool                                       $allowCrossOrigin  whether an assertion made in a cross-origin iframe is acceptable.
     *            When enabling this, also set `$allowedTopOrigins`.
     * @param list<string>                               $allowedTopOrigins the exact top-level origins allowed to embed your login page in an
     *            iframe. Only consulted when `$allowCrossOrigin` is true and the client reports a top origin.
     */
    public function __construct(
        public UserVerificationRequirement $userVerification = UserVerificationRequirement::REQUIRED,
        public array $allowedAlgorithms = [
            CoseAlgorithmIdentifier::ES256,
            CoseAlgorithmIdentifier::RS256,
            CoseAlgorithmIdentifier::EdDSA,
        ],
        public ResidentKeyRequirement $residentKey = ResidentKeyRequirement::REQUIRED,
        public ?int $timeout = PublicKeyCredentialRequestOptions::RECOMMENDED_TIMEOUT,
        public bool $allowCrossOrigin = false,
        public array $allowedTopOrigins = [],
    )
    {
    }

}
