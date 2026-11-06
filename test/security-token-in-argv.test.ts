import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readToken } from '../src/mcp/server.ts';

// `claude mcp add -e BURSAR_TOKEN=<token>` put the agent token in argv, which
// every local user can read with ps while it runs. Setup now writes the token
// to a 0600 file and passes only its path; the MCP server reads it from there.
describe('audit: agent token in argv', () => {
  it('setup passes a token file, not the token, to claude mcp add', () => {
    const setup = readFileSync(
      fileURLToPath(new URL('../src/setup.ts', import.meta.url)),
      'utf8',
    );
    assert.doesNotMatch(setup, /`BURSAR_TOKEN=\$\{/);
    assert.match(setup, /`BURSAR_TOKEN_FILE=\$\{tokenFile\}`/);
  });

  it('the MCP server takes its token from BURSAR_TOKEN_FILE', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bursar-token-'));
    try {
      const file = join(dir, 'agent-token');
      writeFileSync(file, `${'a'.repeat(48)}\n`, { mode: 0o600 });
      assert.equal(readToken({ BURSAR_TOKEN_FILE: file }), 'a'.repeat(48));
      assert.equal(
        readToken({ BURSAR_TOKEN: 'b', BURSAR_TOKEN_FILE: file }),
        'b',
      );
      assert.throws(() =>
        readToken({ BURSAR_TOKEN_FILE: join(dir, 'missing') }),
      );
      assert.equal(readToken({}), undefined);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
