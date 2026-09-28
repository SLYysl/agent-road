import assert from 'node:assert/strict';
import test from 'node:test';
import {bindExistingTools, buildExistingTaskScript} from '../src/runtime/existing-task.mjs';
const c = (tool, path = `C:\\Tools\\${tool}.exe`) => ({tool,path,source:'path',status:'verified',version:'3.14.5',sha256:'A'.repeat(64),environmentModules:tool==='python',reason:null});
const report = candidates => JSON.stringify({schemaVersion:1,candidates});
test('binds only requested tools; missing ripgrep does not block a Python task', () => {
 const bound=bindExistingTools(report([c('python')]),['python']);
 assert.deepEqual(Object.keys(bound),['python']);
 assert.equal(bound.python.path,'C:\\Tools\\python.exe');
 assert.equal(Object.isFrozen(bound.python),true);
});
test('rejects missing, ambiguous, duplicate and unknown requirements before execution', () => {
 for(const [raw,requested] of [[report([]),['git']],[report([c('git'),c('git','D:\\git.exe')]),['git']],[report([c('git')]),['git','git']],[report([]),['curl']],[report([]),[]]]) {
  assert.throws(()=>bindExistingTools(raw,requested),{code:'EXISTING_TASK_BINDING_FAILED'});
 }
});
test('a Python without environment modules cannot satisfy the contract', () => {
 assert.throws(()=>bindExistingTools(report([{...c('python'),environmentModules:false}]),['python']),{code:'EXISTING_TASK_BINDING_FAILED'});
});
test('source and paths are encoded as data; all locks/checks precede user source', () => {
 const bindings=bindExistingTools(report([c('git',"C:\\It's a tool\\git.exe")]),['git']);
 const script=buildExistingTaskScript(bindings,'Write-Output "hello"');
 assert.ok(!script.includes("It's a tool"));
 assert.ok(script.indexOf('[IO.File]::Open')<script.indexOf('[ScriptBlock]::Create'));
 assert.ok(script.includes('[IO.FileShare]::Read'));
 assert.ok(script.includes('EXISTING_TASK_TOOL_CHANGED'));
 assert.ok(script.includes('$AgentRoadTools'));
 assert.ok(script.includes('[Console]::OutputEncoding=$OutputEncoding'));
 assert.ok(script.includes("$env:PYTHONIOENCODING='utf-8'"));
 assert.throws(()=>buildExistingTaskScript({git:c('git')},'exit 0'),{code:'EXISTING_TASK_BINDING_FAILED'});
 assert.throws(()=>buildExistingTaskScript(bindings,''),{code:'EXISTING_TASK_BINDING_FAILED'});
});
