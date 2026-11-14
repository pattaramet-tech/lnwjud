import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

const builderConfig = readFileSync(new URL('../electron-builder.yml', import.meta.url), 'utf8');
const installerScript = readFileSync(new URL('../build/installer.nsh', import.meta.url), 'utf8');

describe('Windows installer scope regression', () => {
  it('defaults to protected all-users installation while retaining per-user choice', () => {
    expect(builderConfig).toContain('oneClick: false');
    expect(builderConfig).toContain('perMachine: false');
    expect(builderConfig).toContain('selectPerMachineByDefault: true');
    expect(builderConfig).not.toContain('selectPerMachineByDefault: false');
  });

  it('refuses per-user installation instead of completing without the required service', () => {
    expect(installerScript).toContain('Current-user mode cannot install the protected Windows containment service');
    expect(installerScript).toContain('IfSilent unsupportedPerUserSilent 0');
    expect(installerScript).toContain('SetErrorLevel 125');
    expect(installerScript).toContain('Setup cannot continue');
    expect(installerScript).not.toContain('acknowledgedPerUserMode:');
  });

  it('rechecks interactive scope after selection and refuses before the install section', () => {
    const start = installerScript.indexOf('!macro customPageAfterChangeDir');
    const guard = installerScript.slice(start, installerScript.indexOf('!macroend', start));
    expect(start).toBeGreaterThanOrEqual(0);
    expect(guard).toContain('Page custom lnwjudVerifyInstallScope');
    expect(guard).toContain('${if} $installMode != "all"');
    expect(guard).toContain('explicitly select All Users');
    expect(guard).toContain('SetErrorLevel 125');
    expect(guard.indexOf('Quit')).toBeLessThan(guard.indexOf('${endif}'));
    expect(guard.indexOf('Abort')).toBeGreaterThan(guard.indexOf('${endif}'));
    expect(guard).not.toMatch(/Exec|UAC_RunElevated|service-install|Delete|RMDir/);
  });

  it('rejects silent per-user install in NSIS initialization before any files are extracted', () => {
    const init = installerScript.slice(installerScript.indexOf('!macro customInit'), installerScript.indexOf('!macroend'));
    expect(installerScript.indexOf('!macro customInit')).toBeGreaterThanOrEqual(0);
    expect(init).toContain('${if} $installMode == "CurrentUser"');
    expect(init).toContain('${if} ${Silent}');
    expect(init).toContain('SetErrorLevel 125');
    expect(init).toContain('Abort');
    expect(installerScript.indexOf('!macro customInit')).toBeLessThan(installerScript.indexOf('!macro customInstall'));
  });

  it('keeps silent update uninstall from waiting on the user-data prompt', () => {
    const silentGuard = installerScript.indexOf('IfSilent keepData 0');
    const prompt = installerScript.indexOf('MessageBox MB_YESNO|MB_ICONQUESTION');
    expect(silentGuard).toBeGreaterThanOrEqual(0);
    expect(prompt).toBeGreaterThan(silentGuard);
  });

  it('keeps service installation and removal failures non-interactive in silent updates', () => {
    const serviceInstall = installerScript.slice(
      installerScript.indexOf('nsExec::ExecToStack \'"$INSTDIR\\resources\\native-containment\\lnwjud-containment.exe" service-install\''),
      installerScript.indexOf('; Resolve the shortcut'),
    );
    const serviceUninstall = installerScript.slice(
      installerScript.indexOf('nsExec::ExecToStack \'"$INSTDIR\\resources\\native-containment\\lnwjud-containment.exe" service-uninstall\''),
      installerScript.indexOf('  Delete "$SMPROGRAMS\\lnwjud.lnk"'),
    );

    expect(serviceInstall).toContain('Pop $0');
    expect(serviceInstall).toContain('Pop $1');
    expect(serviceInstall).toContain('SERVICE_INSTALL_UNEXPECTED');
    expect(serviceInstall).toContain('reason $1');
    expect(serviceInstall).toContain('IfSilent silentInstallFailure 0');
    expect(serviceInstall).toContain('silentInstallFailure:');
    expect(serviceInstall).toContain('SetErrorLevel $0');
    expect(serviceUninstall).toContain('Pop $0');
    expect(serviceUninstall).toContain('Pop $1');
    expect(serviceUninstall).toContain('SERVICE_REMOVE_UNEXPECTED');
    expect(serviceUninstall).toContain('reason $1');
    expect(serviceUninstall).toContain('IfSilent silentUninstallFailure 0');
    expect(serviceUninstall).toContain('silentUninstallFailure:');
    expect(serviceUninstall).toContain('SetErrorLevel $0');
  });
});

describe('fresh-install safety entry points', () => {
  it('emits the guard after builder variable and UAC declarations through customHeader', () => {
    const header = installerScript.match(/!macro customHeader\r?\n([\s\S]*?)!macroend/)?.[1];
    expect(header).toContain('Function lnwjudVerifyFreshInstall');
    const desktopRequire = createRequire(new URL('../package.json', import.meta.url));
    const builderRequire = createRequire(desktopRequire.resolve('electron-builder/package.json'));
    const template = readFileSync(builderRequire.resolve('app-builder-lib/templates/nsis/installer.nsi'), 'utf8');
    expect(template.indexOf('!include "multiUser.nsh"')).toBeLessThan(template.indexOf('!insertmacro customHeader'));
  });

  it('checks registry and SCM in both early hooks, before install section', () => {
    const init = installerScript.slice(installerScript.indexOf('!macro customInit'), installerScript.indexOf('!macroend'));
    const pageStart = installerScript.indexOf('!macro customPageAfterChangeDir');
    const page = installerScript.slice(pageStart, installerScript.indexOf('!macroend', pageStart));
    expect(init).toContain('Call lnwjudVerifyFreshInstall');
    expect(page).toContain('Call lnwjudVerifyFreshInstall');
    expect(installerScript).toContain('Function lnwjudVerifyFreshInstall');
  });
});

interface ProbeFixture {
  keyErrors?: number[];
  serviceError?: number;
  managerAvailable?: boolean;
  closeManager?: boolean;
  innerUser?: boolean;
  installMode?: string;
  silent?: boolean;
}

interface GuardResult {
  exitCode: number;
  reason: string;
  probes: string[];
  closed: string[];
  messages: number;
  serviceProbes: number;
  registers: Record<string, string>;
  stack: string[];
}

// Execute the actual guard's small NSIS control-flow subset with synthetic API
// results. No registry, SCM, Setup process or production profile is accessed.
function exerciseFreshGuard(fixture: ProbeFixture = {}): GuardResult {
  const macro = installerScript.match(/!macro lnwjudRequireAbsentKey ROOT KEY ACCESS TAG\r?\n([\s\S]*?)!macroend/)?.[1];
  const body = installerScript.match(/Function lnwjudVerifyFreshInstall\r?\n([\s\S]*?)FunctionEnd/)?.[1];
  if (!macro || !body) throw new Error('Missing production fresh-install guard');
  const expanded = body.replace(/!insertmacro lnwjudRequireAbsentKey (\S+) (\S+) (\S+) (\S+)/g, (_, root, key, access, tag) =>
    macro.replaceAll('${ROOT}', root).replaceAll('${KEY}', key).replaceAll('${ACCESS}', access).replaceAll('${TAG}', tag));
  const lines = expanded.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith(';'));
  const labels = new Map(lines.map((line, index) => [line.endsWith(':') ? line.slice(0, -1) : '', index]));
  const registers: Record<string, string> = { '$0': 'saved0', '$1': 'saved1', '$2': 'saved2', '$3': 'saved3', '$installMode': fixture.installMode ?? 'all' };
  const stack: string[] = [];
  const probes: string[] = [];
  const closed: string[] = [];
  let messages = 0;
  let exitCode = 0;
  let serviceProbes = 0;
  const value = (token: string): string => token.startsWith('$') ? registers[token] : token.replace(/^"|"$/g, '');
  const jump = (label: string, pc: number): number => {
    if (label === '0' || label === undefined) return pc;
    const target = labels.get(label);
    if (target === undefined) throw new Error(`Unknown NSIS label ${label}`);
    return target;
  };
  for (let pc = 0, steps = 0; pc < lines.length; pc++) {
    if (++steps > 500) throw new Error('NSIS guard did not terminate');
    const line = lines[pc];
    if (line.endsWith(':') || line === '${endif}') continue;
    if (line === '${if} ${UAC_IsInnerInstance}') {
      if (!fixture.innerUser) pc = lines.indexOf('${endif}', pc);
      continue;
    }
    const tokens = line.match(/"[^"]*"|\S+/g)!;
    if (tokens[0] === 'Push') stack.push(value(tokens[1]));
    else if (tokens[0] === 'Pop') {
      const item = stack.pop();
      if (item === undefined) throw new Error('NSIS stack underflow');
      registers[tokens[1]] = item;
    } else if (tokens[0] === 'StrCpy') registers[tokens[1]] = value(tokens[2]);
    else if (tokens[0] === 'StrCmp') pc = jump(value(tokens[1]) === value(tokens[2]) ? tokens[3] : tokens[4] ?? '0', pc);
    else if (tokens[0] === 'Goto') pc = jump(tokens[1], pc);
    else if (tokens[0] === 'IfSilent') { if (fixture.silent) pc = jump(tokens[1], pc); }
    else if (tokens[0] === 'MessageBox') messages++;
    else if (tokens[0] === 'SetErrorLevel') exitCode = Number(value(tokens[1]));
    else if (tokens[0] === 'Quit') return { exitCode, reason: registers.$2, probes, closed, messages, serviceProbes, registers, stack };
    else if (line.startsWith('System::Call ')) {
      if (line.includes('RegOpenKeyExW(')) {
        const error = fixture.keyErrors?.[probes.length] ?? 2;
        probes.push(line);
        registers.$0 = error === 0 ? 'registry-handle' : '0';
        registers.$1 = String(error);
      } else if (line.includes('RegCloseKey(')) { closed.push('registry'); registers.$3 = '0'; }
      else if (line.includes('OpenSCManagerW(')) { registers.$0 = fixture.managerAvailable === false ? '0' : 'manager'; stack.push('0'); }
      else if (line.includes('OpenServiceW(')) {
        serviceProbes++;
        const error = fixture.serviceError ?? 1060;
        registers.$2 = error === 0 ? 'service' : '0';
        stack.push(String(error));
      } else if (line.includes('CloseServiceHandle(')) {
        const which = line.includes('p r2') ? registers.$2 : registers.$0;
        closed.push(which);
        registers.$3 = fixture.closeManager === false && which === 'manager' ? '0' : '1';
      } else throw new Error(`Unreviewed System API ${line}`);
    } else throw new Error(`Unreviewed NSIS instruction ${line}`);
  }
  return { exitCode, reason: '', probes, closed, messages, serviceProbes, registers, stack };
}

describe('fresh-install guard with synthetic registry and SCM observations', () => {
  it('requires both generated registry keys absent in HKCU/HKLM and 32/64-bit views', () => {
    const result = exerciseFreshGuard();
    expect(result.exitCode).toBe(0);
    expect(result.probes).toHaveLength(8);
    for (const hive of ['0x80000001', '0x80000002'])
      for (const view of ['0x20119', '0x20219'])
        for (const key of ['${INSTALL_REGISTRY_KEY}', '${UNINSTALL_REGISTRY_KEY}'])
          expect(result.probes.some((probe) => probe.includes(hive) && probe.includes(view) && probe.includes(key))).toBe(true);
    expect(result.closed).toEqual(['manager']);
    expect(result.stack).toEqual([]);
    expect(result.registers).toMatchObject({ '$0': 'saved0', '$1': 'saved1', '$2': 'saved2', '$3': 'saved3' });
  });

  it.each(Array.from({ length: 8 }, (_, index) => index))('refuses an existing install key at probe %i before reaching SCM', (index) => {
    const errors = Array<number>(8).fill(2); errors[index] = 0;
    const result = exerciseFreshGuard({ keyErrors: errors, silent: true });
    expect(result.exitCode).toBe(125);
    expect(result.reason).toBe('INSTALL_EXISTING_SCOPE_MIGRATION_UNSUPPORTED');
    expect(result.closed).toEqual(['registry']);
    expect(result.serviceProbes).toBe(0);
    expect(result.messages).toBe(0);
  });

  it.each([5, 6, -1])('rejects unverified registry result %i rather than treating it as absence', (error) => {
    expect(exerciseFreshGuard({ keyErrors: [error] })).toMatchObject({ exitCode: 125, reason: 'INSTALL_SCOPE_INSPECTION_UNAVAILABLE', serviceProbes: 0 });
  });

  it('refuses an existing service even if installation registry keys are absent', () => {
    const result = exerciseFreshGuard({ serviceError: 0 });
    expect(result.exitCode).toBe(125);
    expect(result.reason).toBe('SERVICE_INSTALL_EXISTING_SERVICE_UPDATE_UNSUPPORTED');
    expect(result.closed).toEqual(['service', 'manager']);
  });

  it.each([1072, 5, 6, 1062])('fails closed on SCM observation %i', (error) => {
    expect(exerciseFreshGuard({ serviceError: error })).toMatchObject({ exitCode: 125, reason: 'SERVICE_INSTALL_FRESH_PREFLIGHT_UNAVAILABLE' });
  });

  it('refuses unknown original HKCU after UAC handoff without inspecting another profile', () => {
    const result = exerciseFreshGuard({ innerUser: true });
    expect(result).toMatchObject({ exitCode: 125, reason: 'INSTALL_ORIGINAL_USER_CONTEXT_UNVERIFIED', probes: [], serviceProbes: 0 });
  });

  it('fails closed when the manager cannot be opened or its handle cannot be closed', () => {
    expect(exerciseFreshGuard({ managerAvailable: false }).exitCode).toBe(125);
    expect(exerciseFreshGuard({ closeManager: false }).exitCode).toBe(125);
  });

  it('does not invoke fresh-only probes for per-user mode handled by the existing refusal', () => {
    expect(exerciseFreshGuard({ installMode: 'CurrentUser' })).toMatchObject({ exitCode: 0, probes: [], serviceProbes: 0 });
  });

  it('uses read-only registry/SCM APIs; mutations stay behind native fresh-service validation', () => {
    const body = installerScript.match(/Function lnwjudVerifyFreshInstall\r?\n([\s\S]*?)FunctionEnd/)![1];
    expect(body).not.toMatch(/RegCreate|RegSet|DeleteService|CreateServiceW|ControlService|StartServiceW|Exec|RMDir/);
    expect(body).toContain('StrCmp $1 1060 lnwjudFreshInstallDone');
    const native = readFileSync(new URL('../../../native/windows-containment-helper/WindowsContainmentServiceInstaller.cs', import.meta.url), 'utf8');
    const install = native.slice(native.indexOf('internal static void Install()'), native.indexOf('internal static void Uninstall()'));
    expect(install.indexOf('RunFreshInstall(')).toBeLessThan(install.indexOf('SecureInstalledImage('));
    expect(install).not.toContain('ChangeServiceConfig(');
    expect(install).not.toContain('OpenService(manager, WindowsContainmentService.ServiceName, ServiceAllAccess)');
  });
});
