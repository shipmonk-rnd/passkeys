<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Controller;

use DateTimeInterface;
use ShipMonk\PasskeysSymfonyDemo\Account\UserSession;
use ShipMonk\PasskeysSymfonyDemo\Entity\Credential;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use function array_map;
use function base64_encode;

/**
 * The page itself, plus the session-state endpoints behind it: `/me` (who is signed in and the
 * passkeys they can manage) and `/logout`.
 */
final class HomeController extends AbstractController
{

    public function __construct(
        private readonly UserSession $userSession,
    )
    {
    }

    #[Route('/', methods: ['GET'])]
    public function index(): Response
    {
        return $this->render('index.html.twig');
    }

    #[Route('/me', methods: ['GET'])]
    public function me(): JsonResponse
    {
        $user = $this->userSession->getUser();

        if ($user === null) {
            return $this->json(['authenticated' => false]);
        }

        $credentials = array_map(static fn (Credential $credential): array => [
            // The opaque id the page echoes back to /passkeys/remove (raw bytes are not JSON-safe).
            'id' => base64_encode($credential->getCredentialId()),
            'attachment' => $credential->getAuthenticatorAttachment(),
            'createdAt' => $credential->getCreatedAt()->format(DateTimeInterface::ATOM),
        ], $user->getCredentials());

        return $this->json([
            'authenticated' => true,
            'email' => $user->getEmail(),
            'credentials' => $credentials,
        ]);
    }

    #[Route('/logout', methods: ['POST'])]
    public function logout(): JsonResponse
    {
        $this->userSession->signOut();

        return $this->json(['ok' => true]);
    }

}
