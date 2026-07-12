import { describe, expect, it, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadPolicy, PolicyValidationError } from '../../src/policy/loadPolicy.js';

const tempDirs: string[] = [];

async function writePolicyFile(contents: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'toolgovern-policy-'));
  tempDirs.push(dir);
  const filePath = join(dir, 'toolgovern.policy.yml');
  await writeFile(filePath, contents, 'utf8');
  return filePath;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('loadPolicy', () => {
  it('loads a valid YAML policy file', async () => {
    const filePath = await writePolicyFile(
      [
        'name: strict-shell',
        'scope:',
        '  network: false',
        '  filesystem:',
        '    - ./workspace',
        '  credentials: []',
      ].join('\n'),
    );

    const policy = loadPolicy(filePath);
    expect(policy.name).toBe('strict-shell');
    expect(policy.scope.filesystem).toEqual(['./workspace']);
  });

  it('loads a policy with rule overrides and a default decision', async () => {
    const filePath = await writePolicyFile(
      [
        'name: network-allowlist',
        'scope:',
        '  network:',
        '    - example.com',
        '  filesystem: []',
        '  credentials: []',
        'defaultDecision: allow',
        'rules:',
        '  disable: []',
        '  requireApproval:',
        '    - TG01-sudo',
      ].join('\n'),
    );

    const policy = loadPolicy(filePath);
    expect(policy.defaultDecision).toBe('allow');
    expect(policy.rules?.requireApproval).toEqual(['TG01-sudo']);
  });

  it('throws PolicyValidationError for a structurally invalid policy', async () => {
    const filePath = await writePolicyFile('name: broken\n');
    expect(() => loadPolicy(filePath)).toThrow(PolicyValidationError);
  });

  it('throws for malformed YAML', async () => {
    const filePath = await writePolicyFile('name: [unterminated\n  scope: {');
    expect(() => loadPolicy(filePath)).toThrow(/Failed to parse policy file/);
  });

  it('throws for a policy referencing an unknown rule ID', async () => {
    const filePath = await writePolicyFile(
      [
        'name: broken-rules',
        'scope:',
        '  network: false',
        '  filesystem: []',
        '  credentials: []',
        'rules:',
        '  disable:',
        '    - TG00-does-not-exist',
      ].join('\n'),
    );
    expect(() => loadPolicy(filePath)).toThrow(/TG00-does-not-exist/);
  });
});
