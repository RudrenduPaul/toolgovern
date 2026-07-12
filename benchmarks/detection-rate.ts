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
import { corpus } from './corpus.ts';

function main(): void {
  let truePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;
  let falsePositives = 0;

  for (const testCase of corpus) {
    const result = classify(testCase.context);
    const flagged = result.decision !== 'allow';

    if (testCase.expected === 'risky') {
      if (flagged) truePositives += 1;
      else falseNegatives += 1;
    } else {
      if (flagged) falsePositives += 1;
      else trueNegatives += 1;
    }

    const status = flagged === (testCase.expected === 'risky') ? 'OK  ' : 'MISS';
    const rules = result.firedRules.map((r) => r.ruleId).join(',') || '-';
    console.log(
      `${status}  [${testCase.expected.padEnd(6)}] ${testCase.label.padEnd(32)} -> ${result.decision.padEnd(16)} (${rules})`,
    );
  }

  const riskyTotal = truePositives + falseNegatives;
  const benignTotal = trueNegatives + falsePositives;
  const detectionRate = riskyTotal > 0 ? (truePositives / riskyTotal) * 100 : 0;
  const falsePositiveRate = benignTotal > 0 ? (falsePositives / benignTotal) * 100 : 0;

  console.log('');
  console.log(`Corpus size: ${corpus.length} (${riskyTotal} risky, ${benignTotal} benign)`);
  console.log(
    `Detection rate (true positives / risky):     ${detectionRate.toFixed(1)}% (${truePositives}/${riskyTotal})`,
  );
  console.log(
    `False positive rate (false positives / benign): ${falsePositiveRate.toFixed(1)}% (${falsePositives}/${benignTotal})`,
  );
}

main();
