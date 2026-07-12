<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Account;

use ShipMonk\PasskeysSymfonyDemo\Entity\User;
use ShipMonk\PasskeysSymfonyDemo\Passkey\DoctrinePasskeyStore;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The demo's tiny "who is signed in" layer, kept on the Symfony session. It deliberately does *not*
 * use the Symfony Security firewall: the example is about wiring the passkeys library, not building
 * a full authentication stack, so — exactly like the plain-PHP example's `$_SESSION['auth_user_id']`
 * — the signed-in account is just a user id in the session. A real service would use Symfony
 * Security (a `UserInterface`, a firewall, a passkey authenticator).
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

    /**
     * Both password and passkey sign-in land here. The session id is rotated on every sign-in so a
     * fixed, pre-authentication id can't be reused to ride the new session (session fixation).
     */
    public function signIn(User $user): void
    {
        $session = $this->requestStack->getSession();
        $session->migrate(destroy: true);
        $session->set(self::USER_ID_KEY, $user->getId());
    }

    public function signOut(): void
    {
        $this->requestStack->getSession()->remove(self::USER_ID_KEY);
    }

    public function getUser(): ?User
    {
        $userId = $this->requestStack->getSession()->get(self::USER_ID_KEY);

        return $userId === null ? null : $this->store->findUserById((int) $userId);
    }

}
