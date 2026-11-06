import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildPolicyYaml, PRESETS } from '../src/setup.ts';

const REPO = fileURLToPath(new URL('..', import.meta.url));

// Setup used to write the confirmed policy to a temp file the operator's user
// owns and hand its path to the root installer. An agent running as that user
// could rewrite the file while sudo asked for the password. The policy now
// goes to the installer on stdin, and the installer keeps it in a root-only
// temp file of its own.
describe('audit: setup hands the policy to the root installer on stdin', () => {
  it('setup no longer passes a POLICY_FILE path', () => {
    if (process.platform === 'win32') return;
    const out = execFileSync(
      process.execPath,
      [
        join(REPO, 'src', 'setup.ts'),
        '--dry-run',
        '--yes',
        '--no-claude',
        '--no-passkey',
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    assert.match(out, /install-(macos|linux)\.sh/);
    assert.match(out, /POLICY_STDIN=1/);
    assert.doesNotMatch(out, /POLICY_FILE=/);
  });

  for (const script of ['install-macos.sh', 'install-linux.sh']) {
    it(`${script} installs exactly the policy it read from stdin`, () => {
      if (process.platform === 'win32') return;
      const src = readFileSync(join(REPO, 'scripts', script), 'utf8');
      const start = src.indexOf('if [ "${POLICY_STDIN:-}" = 1 ]; then');
      const end = src.indexOf('elif [ ! -f "$STATE/policy.yaml" ]', start);
      assert.ok(start > 0 && end > start, 'installer layout changed');
      // The real branch, minus the root/group ownership an unprivileged test cannot set.
      const step = `set -eu\ndie() { echo "install: $*" >&2; exit 1; }\n${src
        .slice(start, end)
        .replace('install -o root -g $RUNAS -m 640', 'install -m 640')}fi\n`;
      const policy = buildPolicyYaml(
        { network: 'testnet', limits: PRESETS.careful },
        'a'.repeat(48),
      );
      const state = mkdtempSync(join(tmpdir(), 'bursar-stdin-'));
      try {
        const r = spawnSync('sh', ['-c', step], {
          input: policy,
          env: {
            PATH: process.env['PATH'] ?? '/usr/bin:/bin',
            STATE: state,
            NODE_TMP: mkdtempSync(join(state, 'node-')),
            RUNAS: 'nobody',
            POLICY_STDIN: '1',
            REPLACE_POLICY: '1',
          },
          encoding: 'utf8',
        });
        assert.equal(r.status, 0, r.stderr);
        assert.equal(readFileSync(join(state, 'policy.yaml'), 'utf8'), policy);
      } finally {
        rmSync(state, { recursive: true, force: true });
      }
    });
  }
});
