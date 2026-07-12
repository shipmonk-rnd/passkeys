<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo;

use Doctrine\Bundle\DoctrineBundle\DoctrineBundle;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use ShipMonk\Passkeys\PasskeyFlow;
use ShipMonk\Passkeys\PasskeyStore;
use ShipMonk\Passkeys\PendingCeremonyStore;
use ShipMonk\PasskeysSymfonyDemo\Entity\User;
use ShipMonk\PasskeysSymfonyDemo\Passkey\DoctrinePasskeyStore;
use ShipMonk\PasskeysSymfonyDemo\Passkey\SessionPendingCeremonyStore;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use function dirname;
use function is_file;
use function password_hash;
use function random_bytes;
use const PASSWORD_DEFAULT;

final class Kernel extends BaseKernel
{

    use MicroKernelTrait;

    /**
     * The demo's fixed accounts as email => plaintext password, seeded on first boot. A real service
     * gets its users from normal user management and would never hard-code a password.
     */
    private const array DEMO_ACCOUNTS = [
        'alice@example.com' => 'alice',
        'bob@example.com' => 'bob',
    ];

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new DoctrineBundle();
        yield new TwigBundle();
    }

    public function getProjectDir(): string
    {
        return dirname(__DIR__);
    }

    public function boot(): void
    {
        parent::boot();

        if (!is_file($this->getProjectDir() . '/var/passkeys.sqlite')) {
            $this->initializeDatabase();
        }
    }

    private function initializeDatabase(): void
    {
        $entityManager = $this->container->get('doctrine.orm.default_entity_manager');
        assert($entityManager instanceof EntityManagerInterface);

        new SchemaTool($entityManager)->createSchema($entityManager->getMetadataFactory()->getAllMetadata());

        foreach (self::DEMO_ACCOUNTS as $email => $password) {
            $entityManager->persist(new User(
                email: $email,
                passwordHash: password_hash($password, PASSWORD_DEFAULT),
                passkeyUserHandle: random_bytes(64), // 64 opaque random bytes — exactly what PasskeyFlow::generateUserHandle() mints.
            ));
        }

        $entityManager->flush();
    }

    private function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'passkeys-symfony-demo-not-a-real-secret',
            'session' => ['enabled' => true],
        ]);

        $container->extension('doctrine', [
            'dbal' => [
                'url' => 'sqlite:///%kernel.project_dir%/var/passkeys.sqlite',
            ],
            'orm' => [
                'mappings' => [
                    'Demo' => [
                        'type' => 'attribute',
                        'dir' => '%kernel.project_dir%/src/Entity',
                        'prefix' => 'ShipMonk\\PasskeysSymfonyDemo\\Entity',
                    ],
                ],
            ],
        ]);

        $services = $container->services()
            ->defaults()
            ->autowire()
            ->autoconfigure();

        $services->load('ShipMonk\\PasskeysSymfonyDemo\\', __DIR__);

        $services->set(PasskeyFlow::class)
            ->arg('$rpId', 'localhost')
            ->arg('$rpName', 'ShipMonk\Passkeys Symfony Demo')
            ->arg('$origins', ['http://localhost:8000']);

        $services->alias(PasskeyStore::class, DoctrinePasskeyStore::class);
        $services->alias(PendingCeremonyStore::class, SessionPendingCeremonyStore::class);
    }

    private function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import(__DIR__ . '/Controller/', 'attribute');
    }

}
