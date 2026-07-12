<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo;

use Doctrine\Bundle\DoctrineBundle\DoctrineBundle;
use ShipMonk\Passkeys\PasskeyFlow;
use ShipMonk\Passkeys\PasskeyStore;
use ShipMonk\Passkeys\PendingCeremonyStore;
use ShipMonk\PasskeysSymfonyDemo\Doctrine\BinaryStringType;
use ShipMonk\PasskeysSymfonyDemo\Doctrine\CoseKeyType;
use ShipMonk\PasskeysSymfonyDemo\Passkey\DoctrinePasskeyStore;
use ShipMonk\PasskeysSymfonyDemo\Passkey\SessionPendingCeremonyStore;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use function dirname;

/**
 * The whole application, configured inline with {@see MicroKernelTrait}: it registers the three
 * bundles it needs, wires the container, and imports the attribute routes on the controllers. This
 * is the file to read to see how {@see PasskeyFlow} is plugged into Symfony.
 *
 * Because the example runs off the *root* `vendor/` (the packages are `require-dev` of the library),
 * {@see self::getProjectDir()} is pinned to this directory — otherwise Symfony's default would walk
 * up to the repository's own `composer.json` and scatter `var/` and the SQLite file at the root.
 */
final class Kernel extends BaseKernel
{

    use MicroKernelTrait;

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

    private function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            // A demo secret; a real app keeps this out of source (env var / secrets vault).
            'secret' => 'passkeys-symfony-demo-not-a-real-secret',
            'http_method_override' => false,
            // Native file-based sessions; the sign-in state and pending ceremonies live here.
            'session' => [
                'handler_id' => null,
                'cookie_secure' => 'auto',
                'cookie_samesite' => 'lax',
            ],
        ]);

        $container->extension('twig', [
            'default_path' => '%kernel.project_dir%/templates',
        ]);

        $container->extension('doctrine', [
            'dbal' => [
                'url' => 'sqlite:///%kernel.project_dir%/var/passkeys.sqlite',
                // The custom types that keep the binary WebAuthn columns as plain PHP values.
                'types' => [
                    BinaryStringType::NAME => BinaryStringType::class,
                    CoseKeyType::NAME => CoseKeyType::class,
                ],
            ],
            'orm' => [
                'controller_resolver' => ['auto_mapping' => false],
                'mappings' => [
                    'Demo' => [
                        'type' => 'attribute',
                        'dir' => '%kernel.project_dir%/src/Entity',
                        'prefix' => 'ShipMonk\\PasskeysSymfonyDemo\\Entity',
                        'is_bundle' => false,
                    ],
                ],
            ],
        ]);

        $services = $container->services()
            ->defaults()
            ->autowire()
            ->autoconfigure();

        // Controllers and the two store implementations are ordinary autowired services. Entities
        // (managed by Doctrine) and the DBAL types (instantiated by Doctrine, not the container) are
        // not services.
        $services->load('ShipMonk\\PasskeysSymfonyDemo\\', __DIR__ . '/')
            ->exclude(__DIR__ . '/{Entity,Doctrine,Kernel.php}');

        // The high-level flow with this relying party's identity. rpId / origin assume localhost:8000
        // (WebAuthn treats localhost as a secure context); change them together if you serve it
        // elsewhere. The two stores are autowired from the aliases below; RelyingParty uses its default.
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
