#!/usr/bin/env node
/**
 * toolgovern-cli -- validate policy files and audit local gate traces without needing the
 * hosted dashboard.
 *
 *   toolgovern-cli validate ./toolgovern.policy.yml
 *   toolgovern-cli audit ./toolgovern-trace.jsonl --since 24h --decision deny
 *
 * Every command function below returns a `CliResult` (exit code + stdout/stderr text) instead of
 * writing to `process.stdout`/`process.stderr` directly, so the command logic is testable in
 * isolation -- `main()` is the only place that touches the real process streams.
 */

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parse as parseYaml } from 'yaml';
import {
  validatePolicy,
  filterTrace,
  readTrace,
  verifyChain,
  type TraceQuery,
  type TraceEntry,
} from 'toolgovern';

export interface CliResult {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface ParsedFlags {
  readonly positional: readonly string[];
  readonly flags: Readonly<Record<string, string | boolean>>;
}

export function parseArgs(argv: readonly string[]): ParsedFlags {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

export const USAGE = [
  'Usage:',
  '  toolgovern-cli validate <policy-file>',
  '  toolgovern-cli audit <trace-file> [--since <window>] [--decision <allow|deny|require-approval>] [--agent <id>] [--rule <ruleId>] [--verify-chain] [--key-file <path>]',
  '',
  '  --key-file  Path to the secret key file used to verify hmac-sha256-signed trace entries.',
  '              Only needed if the trace was written with a TraceWriter secretKey. Entries',
  '              signed with the default unkeyed sha256 scheme verify without it.',
  '',
].join('\n');

export function validateCommand(policyFile: string | undefined): CliResult {
  if (!policyFile) {
    return { code: 2, stdout: '', stderr: `validate requires a <policy-file> argument.\n${USAGE}` };
  }

  let raw: unknown;
  try {
    raw = parseYaml(readFileSync(policyFile, 'utf8'));
  } catch (error) {
    return {
      code: 1,
      stdout: '',
      stderr: `Failed to read/parse "${policyFile}": ${(error as Error).message}\n`,
    };
  }

  const result = validatePolicy(raw);
  if (result.valid) {
    return { code: 0, stdout: `OK  ${policyFile} is a valid toolgovern policy.\n`, stderr: '' };
  }

  const stderr = [`INVALID  ${policyFile}`, ...result.errors.map((e) => `  - ${e}`), ''].join('\n');
  return { code: 1, stdout: '', stderr };
}

const VALID_DECISIONS = new Set(['allow', 'deny', 'require-approval']);

export async function auditCommand(
  traceFile: string | undefined,
  flags: ParsedFlags['flags'],
): Promise<CliResult> {
  if (!traceFile) {
    return { code: 2, stdout: '', stderr: `audit requires a <trace-file> argument.\n${USAGE}` };
  }

  let entries;
  try {
    entries = await readTrace(traceFile);
  } catch (error) {
    return {
      code: 1,
      stdout: '',
      stderr: `Failed to read trace file "${traceFile}": ${(error as Error).message}\n`,
    };
  }

  let stdout = '';

  if (flags['verify-chain']) {
    let secretKey: Buffer | undefined;
    if (typeof flags['key-file'] === 'string') {
      try {
        secretKey = readFileSync(flags['key-file']);
      } catch (error) {
        return {
          code: 1,
          stdout: '',
          stderr: `Failed to read --key-file "${flags['key-file']}": ${(error as Error).message}\n`,
        };
      }
    }
    const verification = verifyChain(entries, { secretKey });
    if (!verification.valid) {
      const stderr = [
        `CHAIN INVALID  ${traceFile}`,
        ...verification.issues.map((issue) => `  - ${issue.traceId}: ${issue.reason}`),
        '',
      ].join('\n');
      return { code: 1, stdout: '', stderr };
    }
    stdout += `Chain OK -- ${entries.length} entries verified.\n`;
  }

  const decisionFlag = typeof flags.decision === 'string' ? flags.decision : undefined;
  if (decisionFlag && !VALID_DECISIONS.has(decisionFlag)) {
    return {
      code: 2,
      stdout: '',
      stderr: `--decision must be one of: allow, deny, require-approval (got "${decisionFlag}")\n`,
    };
  }

  const query: TraceQuery = {
    since: typeof flags.since === 'string' ? flags.since : undefined,
    decision: decisionFlag as TraceQuery['decision'],
    agentId: typeof flags.agent === 'string' ? flags.agent : undefined,
    ruleId: typeof flags.rule === 'string' ? flags.rule : undefined,
  };

  // filterTrace() throws on a malformed --since value (e.g. an unsupported unit like "1s") --
  // that is a user input-validation error, not an unexpected crash, so it gets the same clean,
  // no-stack-trace treatment as an invalid --decision above (exit code 2), not the generic
  // "Unexpected error" handler in main().
  let filtered: TraceEntry[];
  try {
    filtered = filterTrace(entries, query);
  } catch (error) {
    return { code: 2, stdout: '', stderr: `${(error as Error).message}\n` };
  }
  for (const entry of filtered) {
    const rules = entry.rule_fired.length > 0 ? entry.rule_fired.join(', ') : '(no rule fired)';
    stdout += `${entry.decision.toUpperCase().padEnd(16)} ${entry.agent_id} -> ${entry.tool}  [${rules}]  ${entry.timestamp}\n`;
  }
  stdout += `\n${filtered.length} of ${entries.length} trace entries matched.\n`;

  return { code: 0, stdout, stderr: '' };
}

export async function runCommand(argv: readonly string[]): Promise<CliResult> {
  const [command, ...rest] = argv;
  const { positional, flags } = parseArgs(rest);

  if (!command || command === '--help' || command === '-h') {
    return { code: command ? 0 : 2, stdout: command ? USAGE : '', stderr: command ? '' : USAGE };
  }

  if (command === 'validate') {
    return validateCommand(positional[0]);
  }

  if (command === 'audit') {
    return auditCommand(positional[0], flags);
  }

  return { code: 2, stdout: '', stderr: `Unknown command "${command}".\n${USAGE}` };
}

async function main(): Promise<void> {
  const result = await runCommand(process.argv.slice(2));
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  process.exitCode = result.code;
}

const isMainModule =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMainModule) {
  main().catch((error: unknown) => {
    process.stderr.write(`Unexpected error: ${(error as Error).stack ?? String(error)}\n`);
    process.exitCode = 1;
  });
}
