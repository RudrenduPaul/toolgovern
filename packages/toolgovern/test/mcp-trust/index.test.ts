import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import {
  assertMcpServerTrusted,
  isOriginAllowed,
  verifyMcpServerManifest,
  type McpManifestEnvelope,
  type PinnedPublicKey,
} from '../../src/mcp-trust/index.js';

function makeEd25519Key(keyId: string): {
  pinned: PinnedPublicKey;
  sign: (data: Buffer) => Buffer;
} {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    pinned: {
      keyId,
      algorithm: 'ed25519',
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    },
    sign: (data: Buffer) => cryptoSign(null, data, privateKey),
  };
}

function makeRsaKey(keyId: string): { pinned: PinnedPublicKey; sign: (data: Buffer) => Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    pinned: {
      keyId,
      algorithm: 'rsa-sha256',
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    },
    sign: (data: Buffer) => cryptoSign('sha256', data, privateKey),
  };
}

function envelopeFor(
  manifestText: string,
  key: { pinned: PinnedPublicKey; sign: (data: Buffer) => Buffer },
): McpManifestEnvelope {
  const signature = key.sign(Buffer.from(manifestText, 'utf8'));
  return {
    manifestBytes: manifestText,
    signatureB64: signature.toString('base64'),
    keyId: key.pinned.keyId,
  };
}

describe('isOriginAllowed', () => {
  it('allows an exact origin match', () => {
    expect(isOriginAllowed('https://mcp.example.com', ['https://mcp.example.com'])).toBe(true);
  });

  it('allows a bare-hostname allowlist entry to match a full-origin request', () => {
    expect(isOriginAllowed('https://mcp.example.com', ['mcp.example.com'])).toBe(true);
  });

  it('allows a full-origin request to match against a bare-hostname allowlist regardless of scheme', () => {
    expect(isOriginAllowed('http://mcp.example.com', ['mcp.example.com'])).toBe(true);
  });

  it('denies an origin not on the allowlist', () => {
    expect(isOriginAllowed('https://evil.io', ['https://mcp.example.com'])).toBe(false);
  });

  it('does NOT implicitly trust a subdomain of an allowed origin', () => {
    // This is the deliberate divergence from TG03's hostMatchesAllowed(): a connection-time
    // server allowlist defaults to exact match, not subdomain trust.
    expect(isOriginAllowed('https://evil.mcp.example.com', ['https://mcp.example.com'])).toBe(
      false,
    );
  });

  it('allows a subdomain only when the operator explicitly opts in with a "*." entry', () => {
    expect(isOriginAllowed('https://team-a.mcp.example.com', ['*.mcp.example.com'])).toBe(true);
    expect(isOriginAllowed('https://mcp.example.com', ['*.mcp.example.com'])).toBe(true);
  });

  it('denies unrelated hosts even with a "*." entry present', () => {
    expect(isOriginAllowed('https://evil.io', ['*.mcp.example.com'])).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(isOriginAllowed('https://MCP.Example.COM', ['mcp.example.com'])).toBe(true);
  });

  it('denies when the allowlist is empty', () => {
    expect(isOriginAllowed('https://mcp.example.com', [])).toBe(false);
  });

  it('denies an empty origin string', () => {
    expect(isOriginAllowed('', ['https://mcp.example.com'])).toBe(false);
  });

  it('ignores a blank allowlist entry rather than matching everything', () => {
    expect(isOriginAllowed('https://mcp.example.com', ['   '])).toBe(false);
  });
});

describe('verifyMcpServerManifest -- inline envelope', () => {
  it('allows a manifest whose Ed25519 signature verifies against the pinned key', async () => {
    const key = makeEd25519Key('key-1');
    const envelope = envelopeFor('{"name":"acme-mcp","tools":["read_file"]}', key);

    const result = await verifyMcpServerManifest(envelope, { pinnedKeys: [key.pinned] });

    expect(result.decision).toBe('allow');
    expect(result.reason).toContain('key-1');
  });

  it('allows a manifest whose RSA-SHA256 signature verifies against the pinned key', async () => {
    const key = makeRsaKey('rsa-key-1');
    const envelope = envelopeFor('{"name":"acme-mcp","tools":["read_file"]}', key);

    const result = await verifyMcpServerManifest(envelope, { pinnedKeys: [key.pinned] });

    expect(result.decision).toBe('allow');
  });

  it('DENIES a bit-flipped (tampered) manifest even though the original signature is still attached', async () => {
    // This is the genuine tampered-manifest proof: sign the original bytes, flip exactly one
    // character in the manifest text afterward, and confirm the untouched signature no longer
    // verifies against the mutated bytes.
    const key = makeEd25519Key('key-1');
    const original = '{"name":"acme-mcp","tools":["read_file"],"version":"1.0.0"}';
    const envelope = envelopeFor(original, key);

    // Flip a single character ('1' -> '2' in the version string) -- the signature field is left
    // completely unchanged, exactly like an attacker editing a manifest in place without being
    // able to re-sign it (no access to the private key).
    const tampered = original.replace('"1.0.0"', '"2.0.0"');
    expect(tampered).not.toBe(original);
    const tamperedEnvelope: McpManifestEnvelope = { ...envelope, manifestBytes: tampered };

    const result = await verifyMcpServerManifest(tamperedEnvelope, { pinnedKeys: [key.pinned] });

    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('does not verify');
  });

  it('DENIES a manifest signed by a key not in the pinned list', async () => {
    const signingKey = makeEd25519Key('untrusted-key');
    const pinnedKey = makeEd25519Key('trusted-key');
    const envelope = envelopeFor('{"name":"acme-mcp"}', signingKey);

    const result = await verifyMcpServerManifest(envelope, { pinnedKeys: [pinnedKey.pinned] });

    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('untrusted-key');
    expect(result.reason).toContain('not in the pinned key list');
  });

  it('DENIES when no pinned keys are configured at all -- never treated as "verification optional"', async () => {
    const key = makeEd25519Key('key-1');
    const envelope = envelopeFor('{"name":"acme-mcp"}', key);

    const result = await verifyMcpServerManifest(envelope, { pinnedKeys: [] });

    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('No pinned public keys configured');
  });

  it('DENIES a malformed (non-base64) signature rather than throwing', async () => {
    const key = makeEd25519Key('key-1');
    const envelope: McpManifestEnvelope = {
      manifestBytes: '{"name":"acme-mcp"}',
      signatureB64: '', // decodes to zero bytes -- not a valid signature
      keyId: key.pinned.keyId,
    };

    const result = await verifyMcpServerManifest(envelope, { pinnedKeys: [key.pinned] });

    expect(result.decision).toBe('deny');
  });

  it('DENIES a signature that verifies under the wrong algorithm label', async () => {
    // Sign with Ed25519, but pin the same public key material under the wrong declared
    // algorithm -- createPublicKey() will fail to parse an Ed25519 SPKI key as RSA, proving the
    // algorithm tag is load-bearing, not decorative.
    const key = makeEd25519Key('key-1');
    const envelope = envelopeFor('{"name":"acme-mcp"}', key);
    const mislabeledKey: PinnedPublicKey = { ...key.pinned, algorithm: 'rsa-sha256' };

    const result = await verifyMcpServerManifest(envelope, { pinnedKeys: [mislabeledKey] });

    expect(result.decision).toBe('deny');
  });
});

describe('verifyMcpServerManifest -- fetched manifest URL', () => {
  it('fetches the manifest URL and allows when the returned envelope verifies', async () => {
    const key = makeEd25519Key('key-1');
    const envelope = envelopeFor('{"name":"acme-mcp"}', key);
    const fetchImpl = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            manifest: envelope.manifestBytes,
            signature: envelope.signatureB64,
            keyId: envelope.keyId,
          }),
          { status: 200 },
        ),
    );

    const result = await verifyMcpServerManifest('https://mcp.example.com/manifest.json', {
      pinnedKeys: [key.pinned],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.decision).toBe('allow');
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it('fails closed when the manifest URL is unreachable (fetch rejects)', async () => {
    const key = makeEd25519Key('key-1');
    const fetchImpl = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    });

    const result = await verifyMcpServerManifest('https://down.example.com/manifest.json', {
      pinnedKeys: [key.pinned],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('unreachable');
  });

  it('fails closed on a non-2xx HTTP response', async () => {
    const key = makeEd25519Key('key-1');
    const fetchImpl = vi.fn(
      async () => new Response('not found', { status: 404, statusText: 'Not Found' }),
    );

    const result = await verifyMcpServerManifest('https://mcp.example.com/manifest.json', {
      pinnedKeys: [key.pinned],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('unreachable');
  });

  it('fails closed on a malformed response body missing required fields', async () => {
    const key = makeEd25519Key('key-1');
    const fetchImpl = vi.fn(
      async () => new Response(JSON.stringify({ manifest: 'x' }), { status: 200 }),
    );

    const result = await verifyMcpServerManifest('https://mcp.example.com/manifest.json', {
      pinnedKeys: [key.pinned],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.decision).toBe('deny');
  });

  it('fails closed when the manifest fetch hangs past the timeout', async () => {
    const key = makeEd25519Key('key-1');
    const fetchImpl = vi.fn(
      (_url: string, init?: { signal?: AbortSignal }) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new Error('The operation was aborted'));
          });
        }),
    );

    const result = await verifyMcpServerManifest('https://slow.example.com/manifest.json', {
      pinnedKeys: [key.pinned],
      fetchImpl: fetchImpl as unknown as typeof fetch,
      timeoutMs: 20,
    });

    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('unreachable');
  }, 10_000);

  it('throws a clear error rather than silently allowing when no fetch implementation is available', async () => {
    const key = makeEd25519Key('key-1');
    const originalFetch = globalThis.fetch;
    // @ts-expect-error -- deliberately simulating an environment with no global fetch
    delete globalThis.fetch;
    try {
      const result = await verifyMcpServerManifest('https://mcp.example.com/manifest.json', {
        pinnedKeys: [key.pinned],
      });
      expect(result.decision).toBe('deny');
      expect(result.reason).toContain('unreachable');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('assertMcpServerTrusted', () => {
  it('denies on origin alone, without ever attempting the manifest fetch', async () => {
    const key = makeEd25519Key('key-1');
    const fetchImpl = vi.fn();

    const result = await assertMcpServerTrusted(
      { origin: 'https://evil.io', manifest: 'https://evil.io/manifest.json' },
      {
        allowedOrigins: ['https://mcp.example.com'],
        pinnedKeys: [key.pinned],
        fetchImpl: fetchImpl as unknown as typeof fetch,
      },
    );

    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('allowlist');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('allows only when both the origin allowlist and the manifest signature check pass', async () => {
    const key = makeEd25519Key('key-1');
    const envelope = envelopeFor('{"name":"acme-mcp"}', key);

    const result = await assertMcpServerTrusted(
      { origin: 'https://mcp.example.com', manifest: envelope },
      { allowedOrigins: ['https://mcp.example.com'], pinnedKeys: [key.pinned] },
    );

    expect(result.decision).toBe('allow');
  });

  it('denies when the origin is allowed but the manifest signature does not verify', async () => {
    const signingKey = makeEd25519Key('untrusted');
    const pinnedKey = makeEd25519Key('trusted');
    const envelope = envelopeFor('{"name":"acme-mcp"}', signingKey);

    const result = await assertMcpServerTrusted(
      { origin: 'https://mcp.example.com', manifest: envelope },
      { allowedOrigins: ['https://mcp.example.com'], pinnedKeys: [pinnedKey.pinned] },
    );

    expect(result.decision).toBe('deny');
  });
});
