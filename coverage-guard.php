<?php declare(strict_types = 1);

use ShipMonk\CoverageGuard\Config;
use ShipMonk\CoverageGuard\Excluder\IgnoreThrowNewExceptionLineExcluder;
use ShipMonk\CoverageGuard\Rule\EnforceCoverageForMethodsRule;

$config = new Config();

// Every method must be fully covered, except for lines that throw LogicException.
$config->addExecutableLineExcluder(new IgnoreThrowNewExceptionLineExcluder([
    LogicException::class,
]));
$config->addRule(new EnforceCoverageForMethodsRule(requiredCoveragePercentage: 100));

return $config;
