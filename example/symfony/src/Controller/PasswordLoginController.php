<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Controller;

use ShipMonk\PasskeysSymfonyDemo\Account\UserSession;
use ShipMonk\PasskeysSymfonyDemo\Passkey\DoctrinePasskeyStore;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use function password_verify;

final class PasswordLoginController extends AbstractController
{

    public function __construct(
        private readonly UserSession $userSession,
        private readonly DoctrinePasskeyStore $store,
    )
    {
    }

    #[Route('/login/password', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $payload = $request->getPayload();
        $email = $payload->getString('email');
        $password = $payload->getString('password');

        if ($email === '' || $password === '') {
            return $this->json(['ok' => false, 'message' => 'Email and password are required.'], Response::HTTP_BAD_REQUEST);
        }

        $user = $this->store->findUserByEmail($email);

        if ($user === null || !password_verify($password, $user->getPasswordHash())) {
            return $this->json(['ok' => false, 'message' => 'Invalid email or password.'], Response::HTTP_UNAUTHORIZED);
        }

        $this->userSession->signIn($user);

        return $this->json(['ok' => true, 'email' => $user->getEmail()]);
    }

}
