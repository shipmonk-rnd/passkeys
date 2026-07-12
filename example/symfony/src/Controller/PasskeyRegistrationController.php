<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Controller;

use ShipMonk\Passkeys\Ceremony\VerificationException;
use ShipMonk\Passkeys\PasskeyFlow;
use ShipMonk\PasskeysSymfonyDemo\Account\UserSession;
use ShipMonk\PasskeysSymfonyDemo\Passkey\DoctrinePasskeyStore;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use function base64_decode;

/**
 * Passkey management for the already-signed-in account: add a passkey, and remove one. There is no
 * signed-out registration path — the only way to a passkey is from a session that has already
 * proved who it is (password login), which is the trust model a real password-first service should
 * follow.
 */
final class PasskeyRegistrationController extends AbstractController
{

    public function __construct(
        private readonly UserSession $userSession,
        private readonly DoctrinePasskeyStore $store,
        private readonly PasskeyFlow $flow,
    )
    {
    }

    // Enrol an additional passkey for the signed-in account (navigator.credentials.create). The flow
    // issues the challenge, excludes already-enrolled authenticators, and asks for a discoverable
    // credential with user verification — the passkey defaults.
    #[Route('/register/options', methods: ['POST'])]
    public function options(): JsonResponse
    {
        $user = $this->userSession->getUser();

        if ($user === null) {
            return $this->mustBeSignedIn();
        }

        $options = $this->flow->registrationOptions($user->getUserHandle(), $user->getEmail());

        return JsonResponse::fromJsonString($options->toJson());
    }

    #[Route('/register/verify', methods: ['POST'])]
    public function verify(Request $request): JsonResponse
    {
        $user = $this->userSession->getUser();

        if ($user === null) {
            return $this->mustBeSignedIn();
        }

        try {
            // $expectedUserHandle pins the ceremony to the signed-in account: a pending registration
            // minted in another session (for another user) is rejected before anything is verified
            // or persisted, so a passkey can never be attached across accounts.
            $this->flow->register($request->getContent(), expectedUserHandle: $user->getUserHandle());

            return $this->json(['ok' => true]);

        } catch (VerificationException $e) {
            return $this->json(['ok' => false, 'reason' => $e->reason, 'message' => $e->getMessage()], Response::HTTP_BAD_REQUEST);
        }
    }

    // Remove one of the account's passkeys.
    #[Route('/passkeys/remove', methods: ['POST'])]
    public function remove(Request $request): JsonResponse
    {
        $user = $this->userSession->getUser();

        if ($user === null) {
            return $this->mustBeSignedIn();
        }

        $credentialId = base64_decode($request->getPayload()->getString('id'), strict: true);

        if ($credentialId === false) {
            return $this->json(['ok' => false, 'message' => 'A credential id is required.'], Response::HTTP_BAD_REQUEST);
        }

        // Scoped to the user, so an account can only ever delete its own passkey.
        $this->store->deleteCredential($user, $credentialId);

        // The account's accepted-credential set just changed: hand the browser the *complete*
        // remaining set (WebAuthn §5.1.10) so its credential provider prunes the passkey it still
        // lists. Read straight from the store after the delete, so it stays authoritative.
        $signal = $this->flow->allAcceptedCredentialsSignal($user->getUserHandle());

        return $this->json(['ok' => true, 'signal' => $signal]);
    }

    private function mustBeSignedIn(): JsonResponse
    {
        return $this->json(['ok' => false, 'message' => 'You must be signed in.'], Response::HTTP_UNAUTHORIZED);
    }

}
