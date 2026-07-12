<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Command;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use ShipMonk\Passkeys\PasskeyFlow;
use ShipMonk\PasskeysSymfonyDemo\Entity\User;
use ShipMonk\PasskeysSymfonyDemo\Passkey\DoctrinePasskeyStore;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use function password_hash;
use const PASSWORD_DEFAULT;

/**
 * `app:setup` — creates the database schema and seeds the two demo accounts idempotently. Run it
 * once after `composer install`, before starting the server.
 *
 * There is no self-service signup in this demo (real services rarely let a passkey be the *first*
 * credential), so instead of an insert-on-registration path the accounts are seeded here with a
 * bcrypt password hash and a freshly minted 64-byte WebAuthn user handle
 * ({@see PasskeyFlow::generateUserHandle()}). Passkeys are only ever added later, from an
 * authenticated session.
 */
#[AsCommand(name: 'app:setup', description: 'Create the database schema and seed the demo accounts')]
final class SetupCommand extends Command
{

    /**
     * The demo's fixed accounts as email => plaintext password. A real service gets its users from
     * normal user-management and would never hard-code a password.
     */
    private const array DEMO_ACCOUNTS = [
        'alice@example.com' => 'alice',
        'bob@example.com' => 'bob',
    ];

    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly DoctrinePasskeyStore $store,
        private readonly PasskeyFlow $flow,
    )
    {
        parent::__construct();
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int
    {
        $io = new SymfonyStyle($input, $output);

        $schemaTool = new SchemaTool($this->entityManager);
        $schemaTool->updateSchema($this->entityManager->getMetadataFactory()->getAllMetadata());
        $io->writeln('Schema is up to date.');

        foreach (self::DEMO_ACCOUNTS as $email => $password) {
            if ($this->store->findUserByEmail($email) !== null) {
                $io->writeln("Account <comment>{$email}</comment> already exists — skipping.");
                continue;
            }

            $this->entityManager->persist(new User(
                email: $email,
                passwordHash: password_hash($password, PASSWORD_DEFAULT),
                passkeyUserHandle: $this->flow->generateUserHandle(),
            ));
            $io->writeln("Seeded <comment>{$email}</comment> / <comment>{$password}</comment>.");
        }

        $this->entityManager->flush();
        $io->success('Setup complete. Start the server, then open http://localhost:8000');

        return Command::SUCCESS;
    }

}
