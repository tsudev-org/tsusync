import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig(async () => {
  const migrations = await readD1Migrations('./migrations');
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.test.jsonc' },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            // Giá trị GIẢ chỉ dùng cho test (32 byte 0x01), không phải bí mật thật.
            SUB_ENC_KEY: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
          },
        },
      }),
    ],
    test: { setupFiles: ['./test/apply-migrations.ts'], testTimeout: 20_000 },
  };
});
