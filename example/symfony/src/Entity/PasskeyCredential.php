<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Entity;

use DateTimeImmutable;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use ShipMonk\Passkeys\Ceremony\AuthenticationResult;
use ShipMonk\Passkeys\Ceremony\CredentialRecord;
use ShipMonk\Passkeys\Ceremony\RelyingParty;
use ShipMonk\Passkeys\Cose\CoseKey;
use ShipMonk\Passkeys\RegisteredPasskey;

/**
 * A registered passkey — the {@link https://w3c.github.io/webauthn/#credential-record credential
 * record} of WebAuthn §7.1 step 27 as a Doctrine entity. It converts to and from the library's
 * {@see CredentialRecord}, which is all a {@see \ShipMonk\Passkeys\PasskeyFlow} sees. The credential
 * id and the public key are plain Doctrine `binary` columns (raw bytes); the public key round-trips
 * through {@see CoseKey::toBytes()} / {@see CoseKey::fromBytes()} right here in the entity.
 *
 * The `authenticator_attachment` and `created_at` columns are the relying party's own additions
 * (used to label the passkey on the manage page), not part of the credential record.
 */
#[ORM\Entity]
class PasskeyCredential
{

    #[ORM\Id]
    #[ORM\Column(type: Types::BINARY, length: RelyingParty::MAX_CREDENTIAL_ID_LENGTH)]
    private string $credentialId;

    #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'credentials')]
    #[ORM\JoinColumn(nullable: false)]
    private User $user;

    #[ORM\Column(type: Types::BINARY)]
    private string $publicKey;

    #[ORM\Column]
    private int $signCount;

    #[ORM\Column]
    private bool $uvInitialized;

    #[ORM\Column]
    private bool $backupEligible;

    #[ORM\Column]
    private bool $backupState;

    /**
     * @var list<string>|null as reported by the client at registration
     */
    #[ORM\Column(type: Types::JSON, nullable: true)]
    private ?array $transports;

    #[ORM\Column(nullable: true)]
    private ?string $authenticatorAttachment;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private DateTimeImmutable $createdAt;

    public function __construct(
        User $user,
        RegisteredPasskey $passkey,
    )
    {
        $record = $passkey->toCredentialRecord();

        $this->credentialId = $record->credentialId;
        $this->user = $user;
        $this->publicKey = $record->publicKey->toBytes();
        $this->signCount = $record->signCount;
        $this->uvInitialized = $record->uvInitialized;
        $this->backupEligible = $record->backupEligible;
        $this->backupState = $record->backupState;
        $this->transports = $record->transports;
        $this->authenticatorAttachment = $passkey->authenticatorAttachment?->value;
        $this->createdAt = new DateTimeImmutable();
    }

    /**
     * The record the library reads on every authentication (WebAuthn §7.2 step 6).
     */
    public function toCredentialRecord(): CredentialRecord
    {
        return new CredentialRecord(
            credentialId: $this->credentialId,
            publicKey: CoseKey::fromBytes($this->publicKey),
            signCount: $this->signCount,
            userHandle: $this->user->getUserHandle(),
            uvInitialized: $this->uvInitialized,
            backupEligible: $this->backupEligible,
            backupState: $this->backupState,
            transports: $this->transports,
        );
    }

    /**
     * Persists the new state after a successful assertion, per {@see AuthenticationResult}: bump the
     * sign counter, track the current backup state, and latch user-verification once it happens.
     */
    public function applyAuthenticationResult(AuthenticationResult $result): void
    {
        $this->signCount = $result->newSignCount;
        $this->backupState = $result->backupState;
        $this->uvInitialized = $this->uvInitialized || $result->userVerified;
    }

    /**
     * @return string raw credential id bytes
     */
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function getAuthenticatorAttachment(): ?string
    {
        return $this->authenticatorAttachment;
    }

    public function getCreatedAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

}
