'use strict';
// Test only on an ephemeral GitHub-hosted Windows runner. No host data, no
// service/ledger edits, no forced release; use genuine packaged installer/RPCs.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
if (process.platform !== 'win32' || process.env.GITHUB_ACTIONS !== 'true' ||
    process.env.RUNNER_ENVIRONMENT !== 'github-hosted' ||
    process.env.GITHUB_REPOSITORY !== 'pattaramet-tech/lnwjud' ||
    process.env.GITHUB_REF !== 'refs/heads/test/fix08-r10-rollback') throw Error('HOSTED_RUNNER_REQUIRED');
const scenario = process.env.FIX08_R10_SCENARIO;
assert.ok(['settled','registered','active'].includes(scenario));
const root = path.join(process.env.RUNNER_TEMP, 'fix08-r10');
const install = path.join(process.env.ProgramFiles, 'lnwjud');
const helper = path.join(install, 'resources','native-containment','lnwjud-containment.exe');
const store = path.join(process.env.ProgramData, 'lnwjud-containment');
const ledger = path.join(store, 'attempts.json');
const report = { scenario, checks: [], result: 'FAIL' };
const reportPath = path.join(root, 'report.json');
const hash = f => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const exists = f => fs.existsSync(f);
const json = f => JSON.parse(fs.readFileSync(f,'utf8').replace(/^\uFEFF/,''));
const save = () => fs.writeFileSync(reportPath, JSON.stringify(report,null,2));
function record(name, value) { report.checks.push({name,value}); save(); console.log(name, JSON.stringify(value)); }
function ps(command) {
  const r = spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',command],
    {encoding:'utf8',timeout:30000,windowsHide:true});
  if(r.error || r.status!==0) throw Error('POWERSHELL_FAILED '+String(r.error || r.stderr));
  return r.stdout.trim();
}
function service() {
  const s = ps("$s=Get-CimInstance Win32_Service -Filter \"Name='LnwjudContainment'\"; if($null -eq $s){'null'}else{$s | Select-Object State,StartName,ProcessId,PathName | ConvertTo-Json -Compress}");
  return JSON.parse(s);
}
function snapshot() {
  return { service:service(), helper:exists(helper)?hash(helper):null,
    launcher:exists(path.join(install,'lnwjud.exe'))?hash(path.join(install,'lnwjud.exe')):null,
    ledger:exists(ledger)?hash(ledger):null,
    schema:exists(ledger)?json(ledger).schemaVersion:null,
    witnesses:exists(store)?Object.fromEntries(fs.readdirSync(store).filter(n=>/^managed-writer-witness-.*\.json$/.test(n)).sort().map(n=>[n,hash(path.join(store,n))])):{} };
}
function pkg(version) { return json(path.join(root,version,'PROVENANCE.json')); }
function setup(version) {
  const exe=path.join(root,version,'lnwjud-Setup-5.9.6.exe');
  const r=spawnSync(exe,['/S','/allusers'],{windowsHide:true,timeout:180000,encoding:'utf8'});
  if(r.error || r.signal || r.status===null) throw Error('INSTALLER_EXECUTION_FAILED '+String(r.error||r.signal));
  return r.status;
}
function requireInstalled(version) {
  const s=service(); assert.equal(s?.State,'Running'); assert.equal(s?.StartName,'LocalSystem');
  assert.equal(hash(helper),pkg(version).containment.helper.sha256);
}
function rpc(command, identity, extra={}) {
  const body=Buffer.from(JSON.stringify({protocol:3,command,identity,...extra}));
  const size=Buffer.alloc(4); size.writeUInt32LE(body.length);
  const r=spawnSync(helper,['service-rpc',hash(helper)],{input:Buffer.concat([size,body]),timeout:45000,windowsHide:true,encoding:'utf8'});
  if(r.error || r.status!==0) throw Error('RPC_TRANSPORT_FAILED '+command+' '+String(r.error||r.status));
  const response=JSON.parse(r.stdout);
  assert.equal(response.protocol,3); assert.equal(typeof response.ok,'boolean');
  return response;
}
function ok(command,identity,extra) { const r=rpc(command,identity,extra); assert.equal(r.ok,true,command+': '+r.error); return r.result; }
function missing(command,identity,extra) { const r=rpc(command,identity,extra); assert.equal(r.ok,false); assert.equal(r.error,'SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED'); }
function binding(managed=true) {
  const id=crypto.randomUUID();
  return { taskId:'r10-'+id,reservationId:(managed?'managed-writer-':'legacy-')+id,
    attemptId:id,generation:1,requestDigest:crypto.createHash('sha256').update(id).digest('hex'),
    ownerClientId:'r10-fixture-client',ownerSessionId:'r10-fixture-session',workspaceId:'r10-fixture-workspace' };
}
function abort(id) { return ok('abort',id,{reservationKey:store,operationDigest:id.requestDigest}); }
function assertSettled(r) { assert.equal(r.phase,2); assert.equal(r.reservationHeld,false); }
function witnessFile(id) { return path.join(store,'managed-writer-witness-'+crypto.createHash('sha256').update(id.attemptId).digest('hex')+'.json'); }
function operation() {
  const win=process.env.SystemRoot;
  return {kind:'run_process',executable:path.join(win,'System32','WindowsPowerShell','v1.0','powershell.exe'),
    args:['-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 180'],cwd:root,timeoutMs:200000,
    windowsVerbatimArguments:false,environment:{SystemRoot:win,WINDIR:win},maximumOutputBytes:1024};
}
try {
  assert.equal(service(),null,'runner service must be absent');
  assert.equal(exists(install),false,'runner install must be absent');
  assert.equal(exists(store),false,'runner native store must be absent');
  assert.equal(setup('fix07'),0); requireInstalled('fix07');
  const legacy=binding(false);
  assertSettled(abort(legacy));
  assert.equal(json(ledger).schemaVersion,2);
  const legacyBefore=ok('inspect',legacy);
  record('fix07_legacy_schema2',snapshot());
  assert.equal(setup('fix08'),0); requireInstalled('fix08');
  assert.deepEqual(ok('inspect',legacy),legacyBefore);
  record('fix07_to_fix08_legacy_preserved',snapshot());
  // Simulate exact old managed marker with no native attempt or witness.
  const lost=binding();
  const beforeMissing=snapshot();
  missing('inspect',lost);
  missing('abort',lost,{reservationKey:store,operationDigest:lost.requestDigest});
  missing('recover_after_reboot',lost,{recordedAt:'2000-01-01T00:00:00.000Z'});
  assert.deepEqual(snapshot(),beforeMissing);
  assert.equal(exists(witnessFile(lost)),false);
  record('legacy_missing_binding_refused_without_mutation',true);
  const reg=ok('register_managed_writer',binding());
  assert.equal(reg.phase,6); assert.equal(reg.reservationHeld,false);
  const id=reg.identity;
  assert.equal(json(ledger).schemaVersion,3);
  assert.ok(exists(witnessFile(id)));
  record('admission_registered_schema3',snapshot());
  if(scenario==='settled') {
    assertSettled(abort(id));
    assert.equal(json(ledger).schemaVersion,2);
    const before=snapshot();
    const expected=ok('inspect',id);
    assert.equal(setup('fix07'),0); requireInstalled('fix07');
    assert.deepEqual(ok('inspect',id),expected);
    assert.deepEqual(ok('inspect',legacy),legacyBefore);
    assert.deepEqual(snapshot().witnesses,before.witnesses);
    record('settled_fix08_to_fix07',snapshot());
    assert.equal(setup('fix08'),0); requireInstalled('fix08');
    assert.deepEqual(ok('inspect',id),expected);
    assert.deepEqual(snapshot().witnesses,before.witnesses);
    record('settled_reupgrade',snapshot());
  } else {
    if(scenario==='active') {
      const op=operation();
      assert.equal(ok('prepare',id,{operation:op}).phase,0);
      const run=ok('run',id,{operation:op});
      assert.equal(run.phase,3); assert.equal(run.reservationHeld,true);
      assert.equal(ok('inspect',id).phase,3);
      record('active_job_schema3',snapshot());
    }
    const before=snapshot();
    const result=setup('fix07');
    const after=snapshot();
    record('unsafe_rollback_observation',{exitCode:result,before,after});
    // Refusal after replacing the service/image or changing the ledger is a
    // FAIL, even when the installer exits nonzero. Never repair the fixture.
    assert.notEqual(result,0,'unsafe rollback was accepted');
    assert.deepEqual(after,before,'unsafe rollback changed system before refusal');
    assert.equal(ok('inspect',id).phase,scenario==='active'?3:6);
    record('unsafe_rollback_refused_before_mutation',true);
  }
  report.result='PASS'; save();
} catch(error) {
  report.failure=String(error); save(); console.error(error); process.exitCode=1;
}
