<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Controller;

use ShipMonk\PasskeysSymfonyDemo\Account\UserSession;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use function dirname;

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
        return new BinaryFileResponse(
            dirname(__DIR__, 2) . '/templates/index.html',
            headers: ['Content-Type' => 'text/html; charset=UTF-8'],
        );
    }

    #[Route('/me', methods: ['GET'])]
    public function me(): JsonResponse
    {
        $user = $this->userSession->getUser();

        if ($user === null) {
            return $this->json(['authenticated' => false]);
        }

        return $this->json(['authenticated' => true, 'email' => $user->getEmail()]);
    }

    #[Route('/logout', methods: ['POST'])]
    public function logout(): JsonResponse
    {
        $this->userSession->signOut();

        return $this->json(['ok' => true]);
    }

}
