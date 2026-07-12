<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Controller;

use DateTimeInterface;
use ShipMonk\Passkeys\Ceremony\VerificationException;
use ShipMonk\Passkeys\PasskeyFlow;
use ShipMonk\PasskeysSymfonyDemo\Account\UserSession;
use ShipMonk\PasskeysSymfonyDemo\Entity\PasskeyCredential;
use ShipMonk\PasskeysSymfonyDemo\Passkey\DoctrinePasskeyStore;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use function array_map;
use function base64_decode;
use function base64_encode;

/**
 * Passkey management for the already-signed-in account: add a passkey, and remove one. There is no
 * signed-out registration path — the only way to a passkey is from a session that has already
 * proved who it is (password login), which is the trust model a real password-first service should
 * follow.
 */
final class PasskeyManageController extends AbstractController
{

    public function __construct(
        private readonly UserSession $userSession,
        private readonly DoctrinePasskeyStore $store,
        private readonly PasskeyFlow $flow,
    )
    {
    }

    #[Route('/passkeys/list', methods: ['GET'])]
    public function list(): JsonResponse
    {
        $user = $this->userSession->getUser();

        if ($user === null) {
            return $this->mustBeSignedIn();
        }

        $passkeys = array_map(
            static fn (PasskeyCredential $credential): array => [
                'id' => base64_encode($credential->getCredentialId()),
                'attachment' => $credential->getAuthenticatorAttachment(),
                'createdAt' => $credential->getCreatedAt()->format(DateTimeInterface::ATOM),
            ],
            $user->getCredentials(),
        );

        return $this->json(['credentials' => $passkeys]);
    }

    // Enrol an additional passkey for the signed-in account (navigator.credentials.create). The flow
    // issues the challenge, excludes already-enrolled authenticators, and asks for a discoverable
    // credential with user verification — the passkey defaults.
    #[Route('/passkeys/register-options', methods: ['POST'])]
    public function options(): JsonResponse
    {
        $user = $this->userSession->getUser();

        if ($user === null) {
            return $this->mustBeSignedIn();
        }

        return $this->json($this->flow->registrationOptions($user->getUserHandle(), $user->getEmail()));
    }

    #[Route('/passkeys/register', methods: ['POST'])]
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

        // base64_decode('', strict: true) returns '' (not false), so guard against an empty id too.
        $credentialId = base64_decode($request->getPayload()->getString('id'), strict: true);

        if ($credentialId === false || $credentialId === '') {
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
