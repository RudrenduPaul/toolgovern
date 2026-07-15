#!/usr/bin/env node
/**
 * toolgovern-cli -- validate policy files, audit local gate traces, and scaffold framework
 * integration boilerplate, without needing the hosted dashboard.
 *
 *   toolgovern-cli validate ./toolgovern.policy.yml
 *   toolgovern-cli audit ./toolgovern-trace.jsonl --since 24h --decision deny
 *   toolgovern-cli init langgraph
 *
 * Every command function below returns a `CliResult` (exit code + stdout/stderr text) instead of
 * writing to `process.stdout`/`process.stderr` directly, so the command logic is testable in
 * isolation -- `main()` is the only place that touches the real process streams.
 */

import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
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

/**
 * Structured output envelope for `--json`. Every command that supports `--json` emits exactly one
 * of these as a single JSON object on stdout (never split across stdout/stderr, never mixed with
 * human-readable text) so another program -- an AI agent invoking this CLI, a script piping into
 * `jq` -- can parse the result without scraping formatted text. `ok` mirrors the exit code
 * (`code === 0`); `data` is present on success (and, for `validate`, also on a structural failure
 * so the caller gets the file/error list back either way); `error` is present on failure.
 */
export interface JsonEnvelope<T = unknown> {
  readonly ok: boolean;
  readonly command: string;
  readonly data?: T;
  readonly error?: { readonly message: string; readonly details?: readonly string[] };
}

function jsonResult<T>(code: number, envelope: JsonEnvelope<T>): CliResult {
  return { code, stdout: `${JSON.stringify(envelope, null, 2)}\n`, stderr: '' };
}

function isJsonFlag(flags: ParsedFlags['flags']): boolean {
  return flags.json === true || flags.json === 'true';
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
  '  toolgovern-cli validate <policy-file> [--json]',
  '  toolgovern-cli audit <trace-file> [--since <window>] [--decision <allow|deny|require-approval>] [--agent <id>] [--rule <ruleId>] [--verify-chain] [--key-file <path>] [--json]',
  '  toolgovern-cli init [oma|langgraph] [--policy <path>] [--out <path>] [--force] [--json]',
  '',
  '  --json      Emit a single structured JSON object on stdout instead of human-formatted text --',
  '              { ok, command, data } on success, { ok: false, command, error } on failure. Exit',
  '              code still reflects success/failure; nothing is ever split across stdout/stderr',
  '              in --json mode. Meant for another program (an agent, a script) to parse reliably.',
  '',
  '  --key-file  Path to the secret key file used to verify hmac-sha256-signed trace entries.',
  '              Only needed if the trace was written with a TraceWriter secretKey. Entries',
  '              signed with the default unkeyed sha256 scheme verify without it.',
  '',
  '  init        Scaffolds a working integration file wiring toolgovern into the detected (or',
  '              named) framework. Detects open-multi-agent/node_runner (-> oma) and',
  "              @langchain/langgraph (-> langgraph) in the current directory's package.json.",
  '',
].join('\n');

export function validateCommand(
  policyFile: string | undefined,
  flags: ParsedFlags['flags'] = {},
): CliResult {
  const json = isJsonFlag(flags);

  if (!policyFile) {
    const message = 'validate requires a <policy-file> argument.';
    if (json) return jsonResult(2, { ok: false, command: 'validate', error: { message } });
    return { code: 2, stdout: '', stderr: `${message}\n${USAGE}` };
  }

  let raw: unknown;
  try {
    raw = parseYaml(readFileSync(policyFile, 'utf8'));
  } catch (error) {
    const message = `Failed to read/parse "${policyFile}": ${(error as Error).message}`;
    if (json) return jsonResult(1, { ok: false, command: 'validate', error: { message } });
    return { code: 1, stdout: '', stderr: `${message}\n` };
  }

  const result = validatePolicy(raw);
  if (result.valid) {
    if (json) {
      return jsonResult(0, {
        ok: true,
        command: 'validate',
        data: { file: policyFile, valid: true, errors: [] },
      });
    }
    return { code: 0, stdout: `OK  ${policyFile} is a valid toolgovern policy.\n`, stderr: '' };
  }

  if (json) {
    return jsonResult(1, {
      ok: false,
      command: 'validate',
      data: { file: policyFile, valid: false, errors: result.errors },
      error: {
        message: `"${policyFile}" is not a valid toolgovern policy.`,
        details: result.errors,
      },
    });
  }
  const stderr = [`INVALID  ${policyFile}`, ...result.errors.map((e) => `  - ${e}`), ''].join('\n');
  return { code: 1, stdout: '', stderr };
}

const VALID_DECISIONS = new Set(['allow', 'deny', 'require-approval']);

export async function auditCommand(
  traceFile: string | undefined,
  flags: ParsedFlags['flags'],
): Promise<CliResult> {
  const json = isJsonFlag(flags);

  if (!traceFile) {
    const message = 'audit requires a <trace-file> argument.';
    if (json) return jsonResult(2, { ok: false, command: 'audit', error: { message } });
    return { code: 2, stdout: '', stderr: `${message}\n${USAGE}` };
  }

  let entries;
  try {
    entries = await readTrace(traceFile);
  } catch (error) {
    const message = `Failed to read trace file "${traceFile}": ${(error as Error).message}`;
    if (json) return jsonResult(1, { ok: false, command: 'audit', error: { message } });
    return { code: 1, stdout: '', stderr: `${message}\n` };
  }

  let stdout = '';
  let chain: { readonly verified: boolean; readonly entries: number } | undefined;

  if (flags['verify-chain']) {
    let secretKey: Buffer | undefined;
    if (typeof flags['key-file'] === 'string') {
      try {
        secretKey = readFileSync(flags['key-file']);
      } catch (error) {
        const message = `Failed to read --key-file "${flags['key-file']}": ${(error as Error).message}`;
        if (json) return jsonResult(1, { ok: false, command: 'audit', error: { message } });
        return { code: 1, stdout: '', stderr: `${message}\n` };
      }
    }
    const verification = verifyChain(entries, { secretKey });
    if (!verification.valid) {
      if (json) {
        return jsonResult(1, {
          ok: false,
          command: 'audit',
          data: {
            file: traceFile,
            chain: { verified: false, entries: entries.length },
            issues: verification.issues,
          },
          error: {
            message: `Chain verification failed for "${traceFile}".`,
            details: verification.issues.map((issue) => `${issue.traceId}: ${issue.reason}`),
          },
        });
      }
      const stderr = [
        `CHAIN INVALID  ${traceFile}`,
        ...verification.issues.map((issue) => `  - ${issue.traceId}: ${issue.reason}`),
        '',
      ].join('\n');
      return { code: 1, stdout: '', stderr };
    }
    chain = { verified: true, entries: entries.length };
    stdout += `Chain OK -- ${entries.length} entries verified.\n`;
  }

  const decisionFlag = typeof flags.decision === 'string' ? flags.decision : undefined;
  if (decisionFlag && !VALID_DECISIONS.has(decisionFlag)) {
    const message = `--decision must be one of: allow, deny, require-approval (got "${decisionFlag}")`;
    if (json) return jsonResult(2, { ok: false, command: 'audit', error: { message } });
    return { code: 2, stdout: '', stderr: `${message}\n` };
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
    const message = (error as Error).message;
    if (json) return jsonResult(2, { ok: false, command: 'audit', error: { message } });
    return { code: 2, stdout: '', stderr: `${message}\n` };
  }

  if (json) {
    return jsonResult(0, {
      ok: true,
      command: 'audit',
      data: {
        file: traceFile,
        chain,
        query,
        matched: filtered.length,
        total: entries.length,
        entries: filtered,
      },
    });
  }

  for (const entry of filtered) {
    const rules = entry.rule_fired.length > 0 ? entry.rule_fired.join(', ') : '(no rule fired)';
    stdout += `${entry.decision.toUpperCase().padEnd(16)} ${entry.agent_id} -> ${entry.tool}  [${rules}]  ${entry.timestamp}\n`;
  }
  stdout += `\n${filtered.length} of ${entries.length} trace entries matched.\n`;

  return { code: 0, stdout, stderr: '' };
}

export type ScaffoldFramework = 'oma' | 'langgraph';

/** Dependency names in a project's package.json that indicate the given framework is in use.
 *  `node_runner` is open-multi-agent's own runtime package name, per this repo's
 *  `integrations/oma` doc comments; `open-multi-agent` covers a project that depends on the
 *  framework by its own package name instead. */
const FRAMEWORK_DEPENDENCY_MARKERS: Record<ScaffoldFramework, readonly string[]> = {
  oma: ['open-multi-agent', 'node_runner'],
  langgraph: ['@langchain/langgraph'],
};

const DEFAULT_SCAFFOLD_PATH: Record<ScaffoldFramework, string> = {
  oma: 'toolgovern.oma.ts',
  langgraph: 'toolgovern.langgraph.ts',
};

interface PackageJsonShape {
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly devDependencies?: Readonly<Record<string, string>>;
}

export function detectFrameworks(pkg: PackageJsonShape): ScaffoldFramework[] {
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  const detected: ScaffoldFramework[] = [];
  for (const framework of Object.keys(FRAMEWORK_DEPENDENCY_MARKERS) as ScaffoldFramework[]) {
    if (FRAMEWORK_DEPENDENCY_MARKERS[framework].some((marker) => marker in deps)) {
      detected.push(framework);
    }
  }
  return detected;
}

function omaScaffold(policyPath: string): string {
  return `import { governedTool } from 'toolgovern-integration-oma';
import { loadPolicy, type ToolDefinition } from 'toolgovern';

// Load your real toolgovern policy -- see toolgovern.policy.example.yml in the toolgovern repo
// for the full schema, or replace this with an inline Policy object.
const policy = loadPolicy('${policyPath}');

/**
 * Wraps one of your framework's tools ({ name, execute(args) }) so every call is evaluated by
 * toolgovern's classifier before it reaches your real implementation. Register the *governed*
 * tool with your framework instead of the raw one, e.g.:
 *
 *   registry.register(governTool(myRawTool));
 */
export function governTool<Args extends Record<string, unknown>, Result>(
  tool: ToolDefinition<Args, Result>,
): ToolDefinition<Args, Result> {
  return governedTool(tool, policy);
}
`;
}

function langgraphScaffold(policyPath: string): string {
  return `import { ToolNode } from '@langchain/langgraph/prebuilt';
import type { StructuredToolInterface } from '@langchain/core/tools';
import { governedLangGraphTools } from 'toolgovern-integration-langgraph';
import { loadPolicy } from 'toolgovern';

// Load your real toolgovern policy -- see toolgovern.policy.example.yml in the toolgovern repo
// for the full schema, or replace this with an inline Policy object.
const policy = loadPolicy('${policyPath}');

/**
 * Wraps your LangChain tools array and returns a ToolNode that gates every call through
 * toolgovern's classifier before it reaches your real tool implementation. Pass this in place
 * of \`new ToolNode(myTools)\` wherever you build your graph.
 */
export function governedToolNode(
  myTools: readonly StructuredToolInterface[],
  agentId: string,
  sessionId: string,
): ToolNode {
  return new ToolNode(governedLangGraphTools(myTools, { ...policy, agentId, sessionId }));
}
`;
}

const SCAFFOLD_TEMPLATES: Record<ScaffoldFramework, (policyPath: string) => string> = {
  oma: omaScaffold,
  langgraph: langgraphScaffold,
};

export function initCommand(
  framework: string | undefined,
  flags: ParsedFlags['flags'],
  cwd: string,
): CliResult {
  const json = isJsonFlag(flags);
  let target: ScaffoldFramework;

  if (framework) {
    if (framework !== 'oma' && framework !== 'langgraph') {
      const message = `Unknown framework "${framework}". Supported: oma, langgraph.`;
      if (json) return jsonResult(2, { ok: false, command: 'init', error: { message } });
      return { code: 2, stdout: '', stderr: `${message}\n${USAGE}` };
    }
    target = framework;
  } else {
    let pkg: PackageJsonShape;
    try {
      pkg = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8')) as PackageJsonShape;
    } catch (error) {
      const message = `Could not read package.json in "${cwd}": ${(error as Error).message}`;
      if (json) return jsonResult(1, { ok: false, command: 'init', error: { message } });
      return { code: 1, stdout: '', stderr: `${message}\n` };
    }

    const detected = detectFrameworks(pkg);
    if (detected.length === 0) {
      const message =
        'No supported framework dependency detected in package.json (looked for ' +
        'open-multi-agent/node_runner, @langchain/langgraph). ' +
        'Pass one explicitly: toolgovern-cli init <oma|langgraph>';
      if (json) return jsonResult(1, { ok: false, command: 'init', error: { message } });
      return { code: 1, stdout: '', stderr: `${message}\n` };
    }
    if (detected.length > 1) {
      const message =
        `Multiple supported frameworks detected (${detected.join(', ')}). ` +
        'Pass one explicitly: toolgovern-cli init <framework>';
      if (json) return jsonResult(1, { ok: false, command: 'init', error: { message } });
      return { code: 1, stdout: '', stderr: `${message}\n` };
    }
    target = detected[0]!;
  }

  const policyPath = typeof flags.policy === 'string' ? flags.policy : './toolgovern.policy.yml';
  const outPath = typeof flags.out === 'string' ? flags.out : DEFAULT_SCAFFOLD_PATH[target];
  const fullOutPath = resolve(cwd, outPath);

  if (existsSync(fullOutPath) && !flags.force) {
    const message = `"${outPath}" already exists. Pass --force to overwrite.`;
    if (json) return jsonResult(1, { ok: false, command: 'init', error: { message } });
    return { code: 1, stdout: '', stderr: `${message}\n` };
  }

  const content = SCAFFOLD_TEMPLATES[target](policyPath);
  try {
    mkdirSync(dirname(fullOutPath), { recursive: true });
    writeFileSync(fullOutPath, content, 'utf8');
  } catch (error) {
    const message = `Failed to write "${outPath}": ${(error as Error).message}`;
    if (json) return jsonResult(1, { ok: false, command: 'init', error: { message } });
    return { code: 1, stdout: '', stderr: `${message}\n` };
  }

  if (json) {
    return jsonResult(0, {
      ok: true,
      command: 'init',
      data: { framework: target, outPath, policyPath },
    });
  }

  return {
    code: 0,
    stdout:
      `Scaffolded ${target} integration at ${outPath}.\n` +
      `Fill in your real tool(s) and confirm the policy path (${policyPath}) before running.\n`,
    stderr: '',
  };
}

export async function runCommand(argv: readonly string[]): Promise<CliResult> {
  const [command, ...rest] = argv;
  const { positional, flags } = parseArgs(rest);

  if (!command || command === '--help' || command === '-h') {
    return { code: command ? 0 : 2, stdout: command ? USAGE : '', stderr: command ? '' : USAGE };
  }

  if (command === 'validate') {
    return validateCommand(positional[0], flags);
  }

  if (command === 'audit') {
    return auditCommand(positional[0], flags);
  }

  if (command === 'init') {
    return initCommand(positional[0], flags, process.cwd());
  }

  const message = `Unknown command "${command}".`;
  if (isJsonFlag(flags)) {
    return jsonResult(2, { ok: false, command, error: { message } });
  }
  return { code: 2, stdout: '', stderr: `${message}\n${USAGE}` };
}

async function main(): Promise<void> {
  const result = await runCommand(process.argv.slice(2));
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  process.exitCode = result.code;
}

const isMainModule =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
if (isMainModule) {
  main().catch((error: unknown) => {
    process.stderr.write(`Unexpected error: ${(error as Error).stack ?? String(error)}\n`);
    process.exitCode = 1;
  });
}
