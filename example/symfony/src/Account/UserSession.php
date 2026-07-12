<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Account;

use ShipMonk\PasskeysSymfonyDemo\Entity\User;
use ShipMonk\PasskeysSymfonyDemo\Passkey\DoctrinePasskeyStore;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * A real service would use Symfony Security (a `UserInterface`, a firewall, a passkey authenticator).
 */
final class UserSession
{

    private const string USER_ID_KEY = 'auth_user_id';

    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly DoctrinePasskeyStore $store,
    )
    {
    }

    public function signIn(User $user): void
    {
        $session = $this->requestStack->getSession();
        $session->migrate(destroy: true);
        $session->set(self::USER_ID_KEY, $user->getId());
    }

    public function signOut(): void
    {
        $this->requestStack->getSession()->invalidate();
    }

    public function getUser(): ?User
    {
        $userId = $this->requestStack->getSession()->get(self::USER_ID_KEY);

        return $userId === null ? null : $this->store->findUserById((int) $userId);
    }

}
