import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

const rootDir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      // Cross-package imports (the CLI and the OMA integration both `import ... from
      // 'toolgovern'`) resolve straight to source under test, instead of requiring `npm run
      // build` to have produced packages/toolgovern/dist first.
      toolgovern: resolve(rootDir, 'packages/toolgovern/src/index.ts'),
    },
  },
  test: {
    include: ['packages/*/test/**/*.test.ts', 'integrations/*/test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: ['packages/*/src/**/*.ts'],
      exclude: ['**/*.d.ts', '**/index.ts'],
      thresholds: {
        lines: 80,
        statements: 80,
        functions: 80,
        branches: 75,
      },
    },
  },
});
