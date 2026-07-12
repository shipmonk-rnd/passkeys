<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use LogicException;
use ShipMonk\Passkeys\Options\PublicKeyCredentialUserEntity;
use function array_values;

/**
 * A demo account. The primary key is a plain auto-increment integer, as in a real schema; the
 * WebAuthn user handle is a separate value — 64 opaque random bytes, as
 * {@see \ShipMonk\Passkeys\PasskeyFlow::generateUserHandle()} mints — in its own unique binary
 * column. One account has many {@see PasskeyCredential}s.
 *
 * There is no self-service signup in this demo: accounts are seeded on first boot (see
 * {@see \ShipMonk\PasskeysSymfonyDemo\Kernel::boot()}) with a bcrypt password hash. Passkeys are
 * only ever added later, from an authenticated session — the pattern a real password-first relying
 * party should follow.
 */
#[ORM\Entity]
class User
{

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(unique: true)]
    private string $email;

    #[ORM\Column]
    private string $passwordHash;

    #[ORM\Column(type: Types::BINARY, length: PublicKeyCredentialUserEntity::MAX_ID_LENGTH, unique: true)]
    private string $passkeyUserHandle;

    /**
     * @var Collection<int, PasskeyCredential>
     */
    #[ORM\OneToMany(targetEntity: PasskeyCredential::class, mappedBy: 'user', cascade: ['remove'], orphanRemoval: true)]
    private Collection $credentials;

    public function __construct(
        string $email,
        string $passwordHash,
        string $passkeyUserHandle,
    )
    {
        $this->email = $email;
        $this->passwordHash = $passwordHash;
        $this->passkeyUserHandle = $passkeyUserHandle;
        $this->credentials = new ArrayCollection();
    }

    public function getId(): int
    {
        return $this->id ?? throw new LogicException('User has not been persisted yet');
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function getPasswordHash(): string
    {
        return $this->passwordHash;
    }

    /**
     * @return string raw user handle bytes
     */
    public function getUserHandle(): string
    {
        return $this->passkeyUserHandle;
    }

    /**
     * @return list<PasskeyCredential>
     */
    public function getCredentials(): array
    {
        return array_values($this->credentials->toArray());
    }

}
