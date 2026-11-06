import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const script = (name: string) =>
  readFileSync(
    fileURLToPath(new URL(`../scripts/${name}`, import.meta.url)),
    'utf8',
  );

// The installers download the official Node build pinned by SHA-256 instead of
// copying the operator's node (a Homebrew build loads libraries from folders
// the operator's user can write, every time the daemon starts).
describe('pinned Node build', () => {
  const posix = script('node-release.sh');
  const windows = script('install-windows.ps1');

  it('macOS/Linux and Windows pin the same version', () => {
    const v = /^NODE_VERSION=(v\d+\.\d+\.\d+)$/m.exec(posix)?.[1];
    const w = /^\$NodeVersion = '(v\d+\.\d+\.\d+)'$/m.exec(windows)?.[1];
    assert.ok(v, 'NODE_VERSION missing');
    assert.equal(w, v);
    const [major, minor] = v.slice(1).split('.').map(Number);
    assert.ok(major! > 22 || (major === 22 && minor! >= 18), 'below engines');
  });

  it('every platform has a SHA-256', () => {
    for (const p of ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64'])
      assert.match(posix, new RegExp(`${p}\\) echo [0-9a-f]{64} ;;`), p);
    assert.match(windows, /^\$NodeSha256 = '[0-9a-f]{64}'$/m);
  });

  it('no installer runs or copies the operator node', () => {
    for (const name of ['install-macos.sh', 'install-linux.sh'])
      assert.doesNotMatch(script(name), /"\$NODE"|\$\{NODE/);
    assert.doesNotMatch(windows, /\[string\]\$Node\b/);
  });
});
