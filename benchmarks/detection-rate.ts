/**
 * Detection-rate benchmark: runs the labeled corpus through the classifier and reports how many
 * "risky" cases were correctly flagged (deny/require-approval) and how many "benign" cases were
 * incorrectly flagged (false positives).
 *
 * Run (after `npm run build`, since this imports the built package the same way a consumer
 * would): `npm run bench:detection-rate`.
 *
 * Per this repo's engineering standards, no detection-rate number is stated anywhere in
 * documentation unless it is the actual output of this command -- run it yourself rather than
 * trusting a number in a doc.
 */

import { classify } from '../packages/toolgovern/dist/classifier/index.js';
import { corpus, type CorpusCase } from './corpus.ts';
import type { RuleCategory } from '../packages/toolgovern/dist/types.js';

interface Tally {
  truePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  falsePositives: number;
}

function emptyTally(): Tally {
  return { truePositives: 0, falseNegatives: 0, trueNegatives: 0, falsePositives: 0 };
}

function rate(numerator: number, denominator: number): number {
  return denominator > 0 ? (numerator / denominator) * 100 : 0;
}

function printTally(label: string, t: Tally): void {
  const riskyTotal = t.truePositives + t.falseNegatives;
  const benignTotal = t.trueNegatives + t.falsePositives;
  const detectionRate = rate(t.truePositives, riskyTotal);
  const falsePositiveRate = rate(t.falsePositives, benignTotal);
  console.log(
    `${label.padEnd(8)} detection: ${detectionRate.toFixed(1)}% (${t.truePositives}/${riskyTotal})   false-positive: ${falsePositiveRate.toFixed(1)}% (${t.falsePositives}/${benignTotal})   n=${riskyTotal + benignTotal}`,
  );
}

function main(): void {
  const overall = emptyTally();
  const byCategory = new Map<RuleCategory, Tally>();

  for (const testCase of corpus as readonly CorpusCase[]) {
    const result = classify(testCase.context);
    const flagged = result.decision !== 'allow';
    // Category-aware: a "risky" case only counts as a true positive if a rule from ITS OWN
    // category fired, not merely if any rule anywhere fired (a TG02 case that only happens to
    // also trip a TG03 rule should not inflate TG01's number). Benign cases count a false
    // positive against whichever category actually fired.
    const categoryTally = byCategory.get(testCase.category) ?? emptyTally();
    byCategory.set(testCase.category, categoryTally);

    if (testCase.expected === 'risky') {
      const ownCategoryFired = result.firedRules.some((r) => r.category === testCase.category);
      if (ownCategoryFired) {
        overall.truePositives += 1;
        categoryTally.truePositives += 1;
      } else {
        overall.falseNegatives += 1;
        categoryTally.falseNegatives += 1;
      }
    } else {
      if (flagged) {
        overall.falsePositives += 1;
        categoryTally.falsePositives += 1;
      } else {
        overall.trueNegatives += 1;
        categoryTally.trueNegatives += 1;
      }
    }

    const expectedOk =
      testCase.expected === 'risky'
        ? result.firedRules.some((r) => r.category === testCase.category)
        : !flagged;
    const status = expectedOk ? 'OK  ' : 'MISS';
    const rules = result.firedRules.map((r) => r.ruleId).join(',') || '-';
    console.log(
      `${status}  [${testCase.category} ${testCase.expected.padEnd(6)}] ${testCase.label.padEnd(70)} -> ${result.decision.padEnd(16)} (${rules})`,
    );
  }

  console.log('');
  console.log('Per-category:');
  for (const category of ['TG01', 'TG02', 'TG03', 'TG04', 'TG05'] as const) {
    const t = byCategory.get(category);
    if (t) printTally(category, t);
  }

  console.log('');
  console.log('Overall:');
  printTally('ALL', overall);
}

main();
