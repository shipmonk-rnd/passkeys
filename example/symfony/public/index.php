<?php declare(strict_types = 1);

use ShipMonk\PasskeysSymfonyDemo\Kernel;

// The example runs off the repository's root vendor/ (the Symfony/Doctrine packages are require-dev
// of the library), hence the three levels up rather than the usual dirname(__DIR__).'/vendor'.
require_once __DIR__ . '/../../../vendor/autoload_runtime.php';

// No symfony/dotenv here: the app's home is this directory, not the vendor's parent, so the
// environment is hardcoded instead of discovered from a .env at the project root.
return static fn (): Kernel => new Kernel('dev', debug: true);
