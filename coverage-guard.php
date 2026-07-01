<?php declare(strict_types = 1);

use ShipMonk\CoverageGuard\Config;
use ShipMonk\CoverageGuard\Rule\EnforceCoverageForMethodsRule;

// This library aims for ~100% line coverage (see docs/implementation-plan.md, Phase D).
// PHPUnit already reports the overall percentage; coverage-guard's job here is to make that
// discipline enforceable per method, so no core parsing/crypto method can silently regress
// to untested. Two complementary rules express the intent:

$config = new Config();

// 1. No method may be left entirely untested — catches a whole new method shipped without a test.
$config->addRule(new EnforceCoverageForMethodsRule(
	requiredCoveragePercentage: 1,
	minExecutableLines: 1,
));

// 2. Any method of real size must be fully covered — catches a substantial branch left untested.
//    The threshold of 5 executable lines exempts only trivial accessors and the single
//    unreachable defensive guard in BytesReader::unpackFloat (its `unpack()` cannot fail because
//    readRaw() always returns exactly the requested number of bytes; the branch stays for the
//    type-checker and cannot be exercised).
$config->addRule(new EnforceCoverageForMethodsRule(
	requiredCoveragePercentage: 100,
	minExecutableLines: 5,
));

return $config;
