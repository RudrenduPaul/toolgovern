/**
 * Per-call classifier latency benchmark. The middleware runs inline on every tool call with no
 * network round-trip, so this measures wall-clock time for `classify()` alone -- the actual
 * per-call overhead `governTool()` adds on top of the wrapped tool's own execution time.
 *
 * Run (after `npm run build`, since this imports the built package the same way a consumer
 * would): `npm run bench:latency`.
 *
 * Per this repo's engineering standards, no latency number is stated anywhere in documentation
 * unless it is the actual output of this command, run on the machine making the claim.
 */

import { classify } from '../packages/toolgovern/dist/classifier/index.js';
import { corpus } from './corpus.ts';

const WARMUP_ITERATIONS = 200;
const MEASURED_ITERATIONS = 5000;

function percentile(sortedNs: readonly number[], p: number): number {
  const index = Math.min(sortedNs.length - 1, Math.floor((p / 100) * sortedNs.length));
  return sortedNs[index] ?? 0;
}

function main(): void {
  // Warm up the JIT before measuring.
  for (let i = 0; i < WARMUP_ITERATIONS; i += 1) {
    for (const testCase of corpus) classify(testCase.context);
  }

  const samplesNs: number[] = [];
  for (let i = 0; i < MEASURED_ITERATIONS; i += 1) {
    const testCase = corpus[i % corpus.length]!;
    const start = process.hrtime.bigint();
    classify(testCase.context);
    const end = process.hrtime.bigint();
    samplesNs.push(Number(end - start));
  }

  samplesNs.sort((a, b) => a - b);
  const meanNs = samplesNs.reduce((sum, n) => sum + n, 0) / samplesNs.length;

  console.log(`Samples: ${samplesNs.length} calls across a ${corpus.length}-case corpus`);
  console.log(`Mean:   ${(meanNs / 1000).toFixed(2)} us/call`);
  console.log(`p50:    ${(percentile(samplesNs, 50) / 1000).toFixed(2)} us/call`);
  console.log(`p95:    ${(percentile(samplesNs, 95) / 1000).toFixed(2)} us/call`);
  console.log(`p99:    ${(percentile(samplesNs, 99) / 1000).toFixed(2)} us/call`);
}

main();
