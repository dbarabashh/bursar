// Static check of scripts/install-windows.ps1 (no Windows or PowerShell here).
//
// %ProgramData% lets BUILTIN\Users create subfolders, and CREATOR OWNER gets
// full control of what it creates. icacls /inheritance:r removes only
// inherited ACEs and /grant:r replaces only the ACEs of the SIDs it names, so
// an explicit ACE an unprivileged user added to a pre-created
// %ProgramData%\bursar survives, and so does the ownership of any key or
// policy.yaml it planted there (the owner keeps WRITE_DAC). The installer must
// therefore refuse a state folder, key or policy it did not create: one whose
// owner is not Administrators/SYSTEM. This test asserts such a check runs
// before the key is generated or kept and before the policy is written.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const script = readFileSync(
  new URL('../scripts/install-windows.ps1', import.meta.url),
  'utf8',
);
const lines = script.split(/\r?\n/);
const firstLine = (re: RegExp) => lines.findIndex((l) => re.test(l));

describe('install-windows.ps1 with a pre-existing state folder', () => {
  const ownerCheck = firstLine(/GetOwner\(|\.Owner\b/);
  const keyDecision = firstLine(/Test-Path \$KeyPath/);
  const policyWrite = firstLine(/Write-Utf8 \$PolicyPath/);

  it('locates the key decision and policy write', () => {
    assert.ok(keyDecision > 0 && policyWrite > 0);
  });

  it('reads the owner of the state folder and its files before trusting them', () => {
    assert.ok(
      ownerCheck >= 0,
      'nothing in the installer checks who owns %ProgramData%\\bursar, an existing key or policy.yaml',
    );
    assert.ok(
      ownerCheck < keyDecision && ownerCheck < policyWrite,
      'owner check must run before the existing key is kept or the policy written',
    );
  });

  it('only accepts Administrators/SYSTEM as owner (not the installing user)', () => {
    const body = lines
      .slice(Math.max(ownerCheck - 5, 0), ownerCheck + 15)
      .join('\n');
    assert.match(body, /S-1-5-32-544/);
    assert.match(body, /S-1-5-18/);
  });
});
