<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Controller;

use LogicException;
use Psr\Log\LoggerInterface;
use ShipMonk\Passkeys\Ceremony\VerificationException;
use ShipMonk\Passkeys\PasskeyFlow;
use ShipMonk\PasskeysSymfonyDemo\Account\UserSession;
use ShipMonk\PasskeysSymfonyDemo\Passkey\DoctrinePasskeyStore;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Usernameless passkey sign-in (navigator.credentials.get). The options carry no allowCredentials,
 * so a discoverable passkey identifies the account by its user handle. The same options feed both
 * the explicit "sign in with a passkey" button and the conditional-mediation (autofill) request the
 * page starts in the background.
 */
final class PasskeyLoginController extends AbstractController
{

    public function __construct(
        private readonly UserSession $userSession,
        private readonly DoctrinePasskeyStore $store,
        private readonly PasskeyFlow $flow,
        private readonly LoggerInterface $logger,
    )
    {
    }

    #[Route('/login/passkey-options', methods: ['POST'])]
    public function options(): JsonResponse
    {
        return $this->json($this->flow->authenticationOptions());
    }

    #[Route('/login/passkey', methods: ['POST'])]
    public function verify(Request $request): JsonResponse
    {
        try {
            $result = $this->flow->authenticate($request->getContent());
            $user = $this->store->findUserByHandle($result->userHandle) ?? throw new LogicException('User not found');
            $this->userSession->signIn($user);

            return $this->json(['ok' => true, 'email' => $user->getEmail()]);

        } catch (VerificationException $e) {
            // Log the reason, but answer every failure alike: the reasons tell a registered
            // credential from an unknown one, which would help an attacker probe accounts.
            $this->logger->info('Passkey sign-in failed', ['reason' => $e->reason, 'message' => $e->getMessage()]);

            return $this->json(['ok' => false, 'message' => 'Sign-in failed'], Response::HTTP_BAD_REQUEST);
        }
    }

}
