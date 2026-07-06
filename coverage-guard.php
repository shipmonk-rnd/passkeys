<?php declare(strict_types = 1);

use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\Throw_;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use ShipMonk\CoverageGuard\Config;
use ShipMonk\CoverageGuard\Hierarchy\ClassMethodBlock;
use ShipMonk\CoverageGuard\Hierarchy\CodeBlock;
use ShipMonk\CoverageGuard\Rule\CoverageError;
use ShipMonk\CoverageGuard\Rule\CoverageRule;
use ShipMonk\CoverageGuard\Rule\InspectionContext;

$config = new Config();

// Every method must be fully covered, except for lines that throw LogicException.
$config->addRule(new class implements CoverageRule {

	public function inspect(CodeBlock $codeBlock, InspectionContext $context): ?CoverageError
	{
		if (!$codeBlock instanceof ClassMethodBlock) {
			return null;
		}

		$exemptLinesCount = $this->countUncoveredLogicExceptionThrowLines($codeBlock);
		$uncoveredLinesCount = $codeBlock->getExecutableLinesCount() - $codeBlock->getCoveredLinesCount() - $exemptLinesCount;

		if ($uncoveredLinesCount <= 0) {
			return null;
		}

		$className = $context->getClassName() ?? 'anonymous';
		$methodName = $codeBlock->getMethodName();
		$lineWord = $uncoveredLinesCount === 1 ? 'line' : 'lines';

		return CoverageError::create("Method <bold>{$className}::{$methodName}</bold> has {$uncoveredLinesCount} uncovered {$lineWord}, expected full coverage (only LogicException throws are exempt).");
	}

	/**
	 * @return int number of uncovered executable lines occupied by `throw new LogicException(...)` expressions
	 */
	private function countUncoveredLogicExceptionThrowLines(ClassMethodBlock $codeBlock): int
	{
		$blockLines = $codeBlock->getLines();
		$throwLinesCount = 0;

		foreach (new NodeFinder()->findInstanceOf([$codeBlock->getNode()], Throw_::class) as $throw) {
			$new = $throw->expr;

			if (!$new instanceof New_ || !$new->class instanceof Name || $new->class->toString() !== 'LogicException') {
				continue;
			}

			for ($lineNumber = $throw->getStartLine(); $lineNumber <= $throw->getEndLine(); $lineNumber++) {
				$line = $blockLines[$lineNumber - $codeBlock->getStartLineNumber()];

				if ($line->isExecutable() && !$line->isCovered()) {
					$throwLinesCount++;
				}
			}
		}

		return $throwLinesCount;
	}

});

return $config;
