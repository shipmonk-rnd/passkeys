<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Passkey;

use Doctrine\ORM\EntityManagerInterface;
use LogicException;
use ShipMonk\Passkeys\Ceremony\AuthenticationResult;
use ShipMonk\Passkeys\Ceremony\CredentialRecord;
use ShipMonk\Passkeys\Options\PublicKeyCredentialUserEntity;
use ShipMonk\Passkeys\PasskeyStore;
use ShipMonk\Passkeys\RegisteredPasskey;
use ShipMonk\PasskeysSymfonyDemo\Entity\PasskeyCredential;
use ShipMonk\PasskeysSymfonyDemo\Entity\User;
use function array_map;

/**
 * The library's {@see PasskeyStore} backed by Doctrine ORM — the durable storage a
 * {@see \ShipMonk\Passkeys\PasskeyFlow} runs against. It translates between the library's
 * {@see CredentialRecord} / {@see RegisteredPasskey} DTOs and the {@see User} / {@see PasskeyCredential}
 * entities, and adds the account lookups the demo's own endpoints need (password login, the
 * manage-passkeys page).
 *
 * The binary WebAuthn fields are mapped by the entities themselves (Doctrine's built-in `binary`
 * type; {@see \ShipMonk\PasskeysSymfonyDemo\Entity\PasskeyCredential} converts the public key
 * to/from a {@see \ShipMonk\Passkeys\Cose\CoseKey}), so nothing here encodes anything: it is plain
 * `find` / `persist` / `remove`, the same calls a production relying party would make against its
 * own entities.
 */
final class DoctrinePasskeyStore implements PasskeyStore
{

    public function __construct(
        private readonly EntityManagerInterface $entityManager,
    )
    {
    }

    // -- PasskeyStore (the library's interface) -----------------------------------------------

    public function findCredentialByCredentialId(string $credentialId): ?CredentialRecord
    {
        return $this->entityManager->find(PasskeyCredential::class, $credentialId)?->toCredentialRecord();
    }

    public function findUserHandleByUsername(string $username): ?string
    {
        // The demo's usernames are emails. Only the two-step login flow consults this; the demo's
        // passkey sign-in is usernameless, so it goes unused here — but the interface requires it.
        return $this->findUserByEmail($username)?->getUserHandle();
    }

    /**
     * @return list<CredentialRecord>
     */
    public function findCredentialsByUserHandle(string $userHandle): array
    {
        $user = $this->findUserByHandle($userHandle);

        if ($user === null) {
            return [];
        }

        return array_map(
            static fn (PasskeyCredential $credential) => $credential->toCredentialRecord(),
            $user->getCredentials(),
        );
    }

    public function findUserEntityByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
    {
        $user = $this->findUserByHandle($userHandle);

        if ($user === null) {
            return null;
        }

        return new PublicKeyCredentialUserEntity(id: $user->getUserHandle(), name: $user->getEmail(), displayName: $user->getEmail());
    }

    public function saveCredential(RegisteredPasskey $passkey): void
    {
        $user = $this->findUserByHandle($passkey->userHandle);

        if ($user === null) {
            // Cannot happen: the ceremony is pinned to a signed-in account (see the register endpoint).
            throw new LogicException('No account exists for the registered passkey');
        }

        $this->entityManager->persist(new PasskeyCredential($user, $passkey));
        $this->entityManager->flush();
    }

    public function updateCredential(AuthenticationResult $result): void
    {
        // A real relying party could additionally alert on $result->possibleClone.
        $credential = $this->entityManager->find(PasskeyCredential::class, $result->credentialId);

        if ($credential === null) {
            return;
        }

        $credential->applyAuthenticationResult($result);
        $this->entityManager->flush();
    }

    // -- account lookups the demo's own endpoints need ----------------------------------------

    public function findUserByEmail(string $email): ?User
    {
        return $this->entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
    }

    public function findUserById(int $id): ?User
    {
        return $this->entityManager->find(User::class, $id);
    }

    public function findUserByHandle(string $userHandle): ?User
    {
        return $this->entityManager->getRepository(User::class)->findOneBy(['passkeyUserHandle' => $userHandle]);
    }

    /**
     * Removes one of a user's credentials — the "remove passkey" action on the manage page. Scoped
     * to the owning user, so a signed-in account can only ever delete its own passkey, never one
     * addressed by credential id alone.
     *
     * @param string $credentialId raw credential id bytes
     */
    public function deleteCredential(
        User $user,
        string $credentialId,
    ): void
    {
        $credential = $this->entityManager->find(PasskeyCredential::class, $credentialId);

        if ($credential === null || $credential->getUser()->getId() !== $user->getId()) {
            return;
        }

        $this->entityManager->remove($credential);
        $this->entityManager->flush();
    }

}
