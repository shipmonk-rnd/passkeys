<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Controller;

use ShipMonk\PasskeysSymfonyDemo\Account\UserSession;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

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

        return $this->json(['authenticated' => true, 'email' => $user->getEmail()]);
    }

    #[Route('/logout', methods: ['POST'])]
    public function logout(): JsonResponse
    {
        $this->userSession->signOut();

        return $this->json(['ok' => true]);
    }

}
