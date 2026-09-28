import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const scriptUrl = new URL('../windows/bootstrap-stage-one.ps1', import.meta.url);

async function source() {
  return readFile(scriptUrl, 'utf8');
}

test('stage one exposes the exact entry boundary and required implementation functions', async () => {
  const text = await source();
  assert.match(text, /^\[CmdletBinding\(\)\]\nparam\(\n  \[Parameter\(Mandatory = \$true\)\]\n  \[pscustomobject\]\$Configuration\n\)\n\$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version 2\.0/m);
  for (const name of [
    'Assert-Administrator', 'Get-AgentRoadSystemFacts', 'Enter-AgentRoadBootstrapLock',
    'Read-AgentRoadJournal', 'Write-AgentRoadJournal', 'Complete-AgentRoadCheckpoint',
    'Backup-AgentRoadFile', 'Ensure-AgentRoadAccount', 'Ensure-AgentRoadAuthorizedKey',
    'Ensure-AgentRoadSshdConfiguration', 'Ensure-AgentRoadSshdService',
    'Ensure-AgentRoadFirewallRule', 'Get-AgentRoadHostKeys', 'Send-AgentRoadCompletion',
    'Restore-AgentRoadChanges',
  ]) {
    assert.equal((text.match(new RegExp(`function ${name}\\b`, 'g')) ?? []).length, 1, name);
  }
});

test('stage one uses isolated restricted persistent state and an atomic secret-free journal', async () => {
  const text = await source();
  assert.match(text, /C:\\ProgramData\\AgentRoad\\bootstrap/);
  assert.match(text, /bootstrap\.lock/);
  assert.match(text, /journal\.json/);
  assert.doesNotMatch(text, /stage-zero-(?:lock|journal)/);
  assert.match(text, /\[IO\.FileShare\]::None/);
  assert.match(text, /Assert-AgentRoadSafePath/);
  assert.match(text, /ReparsePoint/);
  assert.match(text, /icacls\.exe/);
  assert.match(text, /S-1-5-32-544.*S-1-5-18|S-1-5-18.*S-1-5-32-544/s);
  assert.match(text, /\.ExitCode\s+-ne\s+0/);
  assert.match(text, /Move-Item[^\n]+-Force/);
  assert.match(text, /\[IO\.File\]::Replace\(/);
  assert.match(text, /completionTicket\s*=\s*\$null/);
  assert.doesNotMatch(text, /journal[^\n]{0,80}completionTicket/i);
});

test('stage one installs only the dedicated account key and validates a bounded sshd block before activation', async () => {
  const text = await source();
  const configuration = text.match(/function Ensure-AgentRoadSshdConfiguration[\s\S]+?\n}/)?.[0];
  assert.ok(configuration);
  assert.doesNotMatch(text, /administrators_authorized_keys/i);
  assert.match(text, /C:\\ProgramData\\AgentRoad\\ssh\\authorized_keys/);
  assert.match(text, /# BEGIN AGENT ROAD/);
  assert.match(text, /# END AGENT ROAD/);
  assert.match(text, /Match User agentroad/);
  assert.match(text, /AuthorizedKeysFile C:\\/);
  assert.match(text, /PubkeyAuthentication yes/);
  assert.match(text, /AuthenticationMethods publickey/);
  assert.match(text, /PasswordAuthentication no/);
  assert.match(text, /KbdInteractiveAuthentication no/);
  assert.match(text, /ChallengeResponseAuthentication no/);
  assert.match(configuration, /\$blockLines\s*=\s*@\('# BEGIN AGENT ROAD'\)\s*\+\s*@\(\$listenLines\)\s*\+\s*@\(/);
  assert.match(configuration, /\$block\s*=\s*\$blockLines\s+-join\s+\$newline/);
  assert.match(configuration, /\$firstMatch\s*=\s*\[Text\.RegularExpressions\.Regex\]::Match\(\$text,'\(\?im\)\^\[ \\t\]\*Match\[ \\t\]\+'/);
  assert.match(configuration, /\.Insert\(\$firstMatch\.Index,\$block\)/);
  assert.doesNotMatch(configuration, /\$generic\b|Group\[ \\t\]\+administrators/);
  assert.match(text, /@\('-t','-f',\$ConfigPath\)/);
  assert.doesNotMatch(text, /@\('-T','-C'/);
  assert.match(text, /Test-AgentRoadSshPolicyCompatibility \$candidatePath/);
  assert.match(text, /OpenSSH\.Server~~~~0\.0\.1\.0/);
  assert.match(text, /\.State\s+-ne\s+'Installed'/);
  assert.match(text, /Membership\]::GeneratePassword\(32,8\)/);
  assert.match(text, /RandomNumberGenerator\]::Create\(\)/);
  assert.match(text, /ConvertTo-SecureString \$plain -AsPlainText -Force/);
  assert.doesNotMatch(text, /New-LocalUser[^\n]+-Password\s+['"]/);
});

test('stage one initializes ProgramData ssh and host keys before starting sshd', async () => {
  const text = await source();
  for (const name of ['Initialize-AgentRoadSshData', 'Ensure-AgentRoadHostKeys', 'Assert-AgentRoadSecureSshAcl', 'Assert-AgentRoadNoUnprivilegedWrite']) {
    assert.equal((text.match(new RegExp(`function ${name}\\b`, 'g')) ?? []).length, 1, name);
  }
  assert.match(text, /System32\\OpenSSH\\sshd_config_default/);
  assert.match(text, /Assert-AgentRoadNoUnprivilegedWrite \$defaultConfig/);
  assert.match(text, /ssh-keygen\.exe[\s\S]+@\('-A'\)/);
  assert.match(text, /ssh_host_(?:rsa|ecdsa|ed25519)_key/);
  assert.match(text, /removeFile[\s\S]+ssh_host_/);
  assert.match(text, /removeDirectory[\s\S]+C:\\ProgramData\\ssh/);
  assert.match(text, /AreAccessRulesProtected[\s\S]+GetOwner/);
  const secureAclFunction = text.match(/function Assert-AgentRoadSecureSshAcl[\s\S]+?\n}/)?.[0];
  assert.ok(secureAclFunction);
  assert.match(secureAclFunction, /Assert-AgentRoadNoUnprivilegedWrite/);
  assert.match(text, /FileSystemRights\]::Write[\s\S]+FileSystemRights\]::TakeOwnership/);
  assert.match(text, /Assert-AgentRoadSecureSshAcl[\s\S]+sshd_config/);
  assert.ok(text.indexOf('Initialize-AgentRoadSshData') < text.lastIndexOf('Ensure-AgentRoadSshdService'));
  assert.ok(text.indexOf('Ensure-AgentRoadHostKeys') < text.lastIndexOf('Ensure-AgentRoadSshdService'));
});

test('stage one detects writes with primitive rights without classifying read-only ACLs as writers', async () => {
  const text = await source();
  const mask = text.match(/function Get-AgentRoadWriteRightsMask[\s\S]+?\n}/)?.[0];
  assert.ok(mask);
  for (const right of [
    'WriteData',
    'AppendData',
    'WriteExtendedAttributes',
    'WriteAttributes',
    'DeleteSubdirectoriesAndFiles',
    'Delete',
    'ChangePermissions',
    'TakeOwnership',
  ]) {
    assert.match(mask, new RegExp(`FileSystemRights\\]::${right}`));
  }
  assert.doesNotMatch(mask, /FileSystemRights\]::(?:FullControl|Modify|Read|ReadAndExecute)/);
  assert.equal((text.match(/\$writeRights\s*=\s*Get-AgentRoadWriteRightsMask/g) ?? []).length, 2);
});

test('stage one resolves identities only for ACEs that can write', async () => {
  const text = await source();
  for (const name of ['Assert-AgentRoadSecureSshAcl', 'Assert-AgentRoadNoUnprivilegedWrite']) {
    const definition = text.match(new RegExp(`function ${name}\\b[\\s\\S]+?\\n}`))?.[0];
    assert.ok(definition, name);
    assert.match(
      definition,
      /if \(\$rule\.AccessControlType -eq \[Security\.AccessControl\.AccessControlType\]::Allow -and \(\$rule\.FileSystemRights -band \$writeRights\) -ne 0\) \{\s*\$sid = \$rule\.IdentityReference\.Translate\(\[Security\.Principal\.SecurityIdentifier\]\)\.Value/,
      name,
    );
  }
});

test('stage one removes nontrusted explicit ACEs before asserting an exact restricted ACL', async () => {
  const text = await source();
  const restrictedAcl = text.match(/function Set-AgentRoadRestrictedAcl[\s\S]+?\n}/)?.[0];
  assert.ok(restrictedAcl);
  assert.match(restrictedAcl, /GetAccessRules\(\$true,\$false,\[Security\.Principal\.SecurityIdentifier\]\)/);
  assert.match(restrictedAcl, /\$untrustedSids[\s\S]+Sort-Object -Unique/);
  assert.match(restrictedAcl, /untrustedSids\.Count\s+-gt\s+0[\s\S]+@\(\$Path,'\/remove'\)/);
  assert.match(restrictedAcl, /\^S-\\d\+\(\?:-\\d\+\)\+\$/);
  assert.match(restrictedAcl, /untrustedSids\.Count\s+-gt\s+64/);
  assert.ok(restrictedAcl.indexOf("'/remove'") < restrictedAcl.indexOf("'/setowner'"));
  assert.ok(restrictedAcl.indexOf("'/remove'") < restrictedAcl.indexOf("'/verify'"));
});

test('stage one activates changed config and restores service only after rollback files', async () => {
  const text = await source();
  assert.match(text, /\$script:ConfigChanged\s*=\s*\$false/);
  assert.match(text, /\$script:ConfigChanged\s*=\s*\$true/);
  assert.match(text, /ConfigChanged[\s\S]+Restart-Service/);
  assert.match(text, /WaitForStatus\([^,]+,[^)]+\)/);
  assert.match(text, /Test-AgentRoadSshPolicyCompatibility/);
  const serviceDefinition = text.match(/function Test-AgentRoadSshdServiceDefinition[\s\S]+?\n}/)?.[0];
  assert.ok(serviceDefinition);
  assert.match(serviceDefinition, /StartName[^\n]+LocalSystem/);
  assert.match(serviceDefinition, /PathName/);
  assert.match(serviceDefinition, /System32\\OpenSSH\\sshd\.exe/);
  assert.match(serviceDefinition, /ExpandEnvironmentVariables/);
  const serviceActivation = text.match(/function Ensure-AgentRoadSshdService[\s\S]+?\n}/)?.[0];
  assert.ok(serviceActivation);
  assert.match(serviceActivation, /Test-AgentRoadSshdServiceDefinition \$prior/);
  const servicePostcondition = text.match(/function Test-AgentRoadServicePostcondition[\s\S]+?\n}/)?.[0];
  assert.ok(servicePostcondition);
  assert.match(servicePostcondition, /Test-AgentRoadSshdServiceDefinition \$details/);
  assert.match(text, /\$serviceChanges[\s\S]+foreach \(\$change in \$serviceChanges\)/);
  assert.ok(text.indexOf("'restoreFile'") < text.lastIndexOf('foreach ($change in $serviceChanges)'));
});

test('stage one configures bounded sshd failure recovery before service activation', async () => {
  const text = await source();
  assert.match(text, /QueryServiceConfig2/);
  assert.match(text, /SERVICE_CONFIG_FAILURE_ACTIONS/);
  assert.match(text, /SERVICE_CONFIG_FAILURE_ACTIONS_FLAG/);
  assert.match(text, /SC_ACTION/);
  const desiredState = text.match(/function Test-AgentRoadSshdRecoveryStateDesired[\s\S]+?\n}/)?.[0];
  assert.ok(desiredState);
  assert.match(desiredState, /ResetPeriod[^\n]+86400/);
  assert.match(desiredState, /RebootMessage[^\n]+IsNullOrEmpty/);
  assert.match(desiredState, /Command[^\n]+IsNullOrEmpty/);
  assert.match(desiredState, /ActionTypes[^\n]+Count[^\n]+3/);
  assert.match(desiredState, /ActionTypes\[\$index\][^\n]+1/);
  assert.match(desiredState, /Delays\[\$index\][^\n]+\$expectedDelays\[\$index\]/);
  assert.match(desiredState, /FailureActionsOnNonCrashFailures/);
  const recovery = text.match(/function Ensure-AgentRoadSshdRecovery[\s\S]+?\n}/)?.[0];
  assert.ok(recovery);
  assert.match(recovery, /Test-AgentRoadSshdRecoveryDesired/);
  assert.match(recovery, /Test-AgentRoadSshdRecoveryUnset/);
  assert.match(recovery, /@\('failure','sshd','reset=','86400','actions=','restart\/5000\/restart\/15000\/restart\/30000'\)/);
  assert.match(recovery, /@\('failureflag','sshd','1'\)/);
  assert.match(recovery, /restoreServiceRecovery/);

  const main = text.slice(text.indexOf('$failureCode = $null'));
  assert.ok(main.indexOf('Ensure-AgentRoadSshdRecovery') < main.indexOf('Ensure-AgentRoadSshdService'));

  const postcondition = text.match(/function Test-AgentRoadServicePostcondition[\s\S]+?\n}/)?.[0];
  assert.ok(postcondition);
  assert.match(postcondition, /Test-AgentRoadSshdRecoveryDesired/);
});

test('stage one journals and restores only an initially empty sshd recovery policy', async () => {
  const text = await source();
  const changeValidator = text.match(/function Assert-AgentRoadChange[\s\S]+?\n}/)?.[0];
  assert.ok(changeValidator);
  assert.match(changeValidator, /'restoreServiceRecovery'/);
  assert.match(changeValidator, /path -cne 'sshd'/);
  assert.match(changeValidator, /backupPath -cne 'unset'/);

  const rollback = text.match(/function Restore-AgentRoadChanges[\s\S]+?\n}/)?.[0];
  assert.ok(rollback);
  assert.match(rollback, /\$serviceRecoveryChanges/);
  assert.match(rollback, /Clear-AgentRoadSshdRecovery/);
  assert.match(rollback, /Test-AgentRoadRollbackPostcondition/);

  const clear = text.match(/function Clear-AgentRoadSshdRecovery[\s\S]+?\n}/)?.[0];
  assert.ok(clear);
  assert.match(clear, /@\('failure','sshd','reset=','0','actions=',''\)/);
  assert.match(clear, /@\('failureflag','sshd','0'\)/);
  assert.match(clear, /Test-AgentRoadSshdRecoveryUnset/);
});

test('stage one anchors inbound ssh exposure to its owned rule and exact listeners', async () => {
  const text = await source();
  assert.doesNotMatch(text, /function Get-AgentRoadEnabledInboundSshAllowRules\b/);
  assert.doesNotMatch(text, /function Test-AgentRoadPortIncludes22\b/);
  assert.doesNotMatch(text, /function Test-AgentRoadExistingTailscaleAllowRule\b/);
  assert.match(text, /function Get-AgentRoadExplicitSshAllowRules\b/);
  assert.match(text, /OpenSSH-Server-In-TCP/);
  assert.match(text, /restoreFirewallEnabled/);
  assert.match(text, /Disable-NetFirewallRule/);
  const ownedCapability = text.match(/function Ensure-AgentRoadOpenSshCapability[\s\S]+?\n}/)?.[0];
  assert.ok(ownedCapability);
  assert.doesNotMatch(ownedCapability, /restoreFirewallEnabled|Enable-NetFirewallRule/);
  assert.match(text, /if \(\$script:CapabilityInstalledByAgentRoad\)[\s\S]+Disable-NetFirewallRule/);
  assert.match(text, /Direction[\s\S]+Inbound[\s\S]+Action[\s\S]+Allow[\s\S]+Enabled/);
  assert.match(text, /LocalPort[\s\S]+22/);
  const postcondition = text.match(/function Test-AgentRoadFirewallPostcondition[\s\S]+?\n}/)?.[0];
  assert.ok(postcondition);
  assert.match(postcondition, /Test-AgentRoadScopedFirewallRule/);
  assert.match(postcondition, /Test-AgentRoadMicrosoftOpenSshRule/);
  assert.match(postcondition, /Get-AgentRoadExplicitSshAllowRules/);
  assert.doesNotMatch(postcondition, /Get-AgentRoadEnabledInboundSshAllowRules/);
  const ownedCapabilityRollback = text.match(/function Remove-AgentRoadOwnedOpenSshCapability[\s\S]+?\n}/)?.[0];
  assert.ok(ownedCapabilityRollback);
  assert.match(ownedCapabilityRollback, /removeOpenSshCapability[\s\S]+Disable-NetFirewallRule[\s\S]+Remove-WindowsCapability/);
  assert.match(text, /removeOpenSshCapability[\s\S]+Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP'[\s\S]+Count\s+-eq\s+0/);
});

test('stage one preflights port 22 and installs the scoped rule before sshd activation', async () => {
  const text = await source();
  assert.equal((text.match(/function Assert-AgentRoadFirewallPreflight\b/g) ?? []).length, 1);
  const main = text.slice(text.indexOf('$failureCode = $null'));
  assert.ok(main.indexOf('Assert-AgentRoadFirewallPreflight') < main.indexOf('Ensure-AgentRoadOpenSshCapability'));
  const activation = main.match(/if \(@\(\$script:Journal\.checkpoints\) -cnotcontains 'firewall'\)[\s\S]+?Complete-AgentRoadCheckpoint 'firewall'/)?.[0];
  assert.ok(activation);
  assert.ok(activation.indexOf('Ensure-AgentRoadFirewallBoundary') < activation.indexOf('Ensure-AgentRoadSshdService'));
  assert.match(activation, /Test-AgentRoadFirewallPostcondition[\s\S]+Ensure-AgentRoadSshdService/);
  const preflight = text.match(/function Assert-AgentRoadFirewallPreflight[\s\S]+?\n}/)?.[0];
  assert.ok(preflight);
  assert.match(preflight, /Test-AgentRoadScopedFirewallRule/);
  assert.match(preflight, /Test-AgentRoadMicrosoftOpenSshRule/);
  assert.match(preflight, /Get-AgentRoadExplicitSshAllowRules/);
  assert.doesNotMatch(preflight, /Get-AgentRoadEnabledInboundSshAllowRules/);
  assert.match(preflight, /SupersedingHealthy/);
  assert.match(preflight, /Status[^\n]+Running|Test-AgentRoadPort22Unbound/);
});

test('stage one verifies effective firewall profiles before mutation and after scoped rule creation', async () => {
  const text = await source();
  const profileFunction = text.match(/function Assert-AgentRoadFirewallProfiles[\s\S]+?\n}/)?.[0];
  assert.ok(profileFunction);
  assert.match(profileFunction, /Get-NetFirewallProfile -PolicyStore ActiveStore/);
  assert.match(profileFunction, /@\('Domain','Private','Public'\)/);
  assert.match(profileFunction, /Count\s+-ne\s+3/);
  assert.match(profileFunction, /Enabled[\s\S]+True[\s\S]+DefaultInboundAction[\s\S]+Block[\s\S]+AllowInboundRules[\s\S]+True[\s\S]+AllowLocalFirewallRules[\s\S]+True/);
  assert.match(profileFunction, /DisabledInterfaceAliases[\s\S]+Count\s+-ne\s+0/);
  assert.doesNotMatch(text, /Set-NetFirewallProfile/);
  const main = text.slice(text.indexOf('$failureCode = $null'));
  assert.ok(main.indexOf('Assert-AgentRoadFirewallProfiles') < main.indexOf('Ensure-AgentRoadOpenSshCapability'));
  const activation = main.match(/if \(@\(\$script:Journal\.checkpoints\) -cnotcontains 'firewall'\)[\s\S]+?Complete-AgentRoadCheckpoint 'firewall'/)?.[0];
  assert.ok(activation);
  assert.match(activation, /Ensure-AgentRoadFirewallBoundary[\s\S]+Assert-AgentRoadFirewallProfiles[\s\S]+Ensure-AgentRoadSshdService/);
});

test('stage one removes an owned OpenSSH capability before rolling back generated artifacts', async () => {
  const text = await source();
  const rollbackFunction = text.match(/function Restore-AgentRoadChanges[\s\S]+?\n}/)?.[0];
  assert.ok(rollbackFunction);
  assert.match(text, /function Remove-AgentRoadOwnedOpenSshCapability\b[\s\S]+Disable-NetFirewallRule[\s\S]+Stop-Service[\s\S]+WaitForStatus\([^,]+,[^)]+\)[\s\S]+Remove-WindowsCapability[\s\S]+Remove-NetFirewallRule[\s\S]+Test-AgentRoadRollbackPostcondition/);
  assert.ok(rollbackFunction.indexOf('Remove-AgentRoadOwnedOpenSshCapability') < rollbackFunction.indexOf('foreach ($change in $changes)'));
  assert.match(rollbackFunction, /if \(\$ownedCapabilityRollbackSucceeded\)[\s\S]+foreach \(\$change in \$changes\)/);
  assert.match(rollbackFunction, /if \(\$change\.action -cin @\('restoreService','restoreServiceRecovery','restoreFirewallEnabled','removeOpenSshCapability'\)\) \{ continue \}/);
});

test('stage one safely removes only bounded known children from a fresh ssh data root', async () => {
  const text = await source();
  const capabilityFunction = text.match(/function Ensure-AgentRoadOpenSshCapability[\s\S]+?\n}/)?.[0];
  assert.ok(capabilityFunction);
  assert.ok(capabilityFunction.indexOf('Test-Path -LiteralPath $script:SshDataRoot') < capabilityFunction.indexOf('Add-WindowsCapability'));
  const cleanupFunction = text.match(/function Remove-AgentRoadOwnedSshDataRoot[\s\S]+?\n}/)?.[0];
  assert.ok(cleanupFunction);
  assert.match(cleanupFunction, /Assert-AgentRoadRestrictedAcl \$script:SshDataRoot/);
  assert.match(cleanupFunction, /Get-ChildItem -LiteralPath \$script:SshDataRoot -Force/);
  assert.match(cleanupFunction, /\.Count\s+-gt\s+(?:16|32)/);
  assert.match(cleanupFunction, /ReparsePoint/);
  assert.match(cleanupFunction, /Assert-AgentRoadSafeFile/);
  assert.match(cleanupFunction, /ssh_host_\(\?:rsa\|ecdsa\|ed25519\)_key/);
  assert.ok(cleanupFunction.includes('sshd\\.pid'));
  assert.ok(cleanupFunction.includes('sshd\\.log'));
  assert.match(cleanupFunction, /\[IO\.Directory\]::Delete\(\$script:SshDataRoot,\$false\)/);
  assert.match(cleanupFunction, /Test-Path -LiteralPath \$script:SshDataRoot[\s\S]+ROLLBACK_INCOMPLETE/);
  const rollbackFunction = text.match(/function Restore-AgentRoadChanges[\s\S]+?\n}/)?.[0];
  assert.ok(rollbackFunction);
  assert.match(rollbackFunction, /Remove-AgentRoadOwnedOpenSshCapability[\s\S]+Remove-AgentRoadOwnedSshDataRoot[\s\S]+foreach \(\$change in \$changes\)/);
  assert.doesNotMatch(cleanupFunction, /Remove-Item[^\n]+-Recurse/);
});

test('stage one accepts and preserves only a verified empty pre-existing ssh data root', async () => {
  const text = await source();
  const capabilityFunction = text.match(/function Ensure-AgentRoadOpenSshCapability[\s\S]+?\n}/)?.[0];
  assert.ok(capabilityFunction);
  assert.match(text, /function Assert-AgentRoadEmptySshDataRoot\b/);
  assert.match(capabilityFunction, /Assert-AgentRoadEmptySshDataRoot/);
  assert.match(capabilityFunction, /preserveEmptyDirectory/);
  assert.match(text, /preserveEmptyDirectory[\s\S]+expectedAclSha256/);
  const cleanupFunction = text.match(/function Remove-AgentRoadOwnedSshDataRoot[\s\S]+?\n}/)?.[0];
  assert.ok(cleanupFunction);
  assert.match(cleanupFunction, /PreserveRoot/);
  assert.match(cleanupFunction, /if \(-not \$PreserveRoot\)[\s\S]+Directory\]::Delete/);
  assert.match(text, /preserveEmptyDirectory[\s\S]+Get-AgentRoadAclSha256[\s\S]+Count\s+-eq\s+0/);
});

test('stage one safely supersedes a healthy uncertain completion with a new key transaction', async () => {
  const text = await source();
  const baseline = text.match(/function Test-AgentRoadSupersessionBaseline[\s\S]+?\n}/)?.[0];
  assert.ok(baseline);
  assert.match(baseline, /Get-LocalUser[\s\S]+Enabled[\s\S]+Get-LocalGroupMember/);
  assert.match(baseline, /AuthorizedKeyPath[\s\S]+Test-AgentRoadPriorAuthorizedKey/);
  const priorKey = text.match(/function Test-AgentRoadPriorAuthorizedKey[\s\S]+?\n}/)?.[0];
  assert.ok(priorKey);
  assert.match(priorKey, /ssh-ed25519[\s\S]+agent-road:[\s\S]+dev_/);
  assert.match(baseline, /Assert-AgentRoadRestrictedAcl|Assert-AgentRoadSafeFile/);
  assert.match(baseline, /Test-AgentRoadSshPolicyCompatibility[\s\S]+Test-AgentRoadServicePostcondition[\s\S]+Test-AgentRoadFirewallPostcondition[\s\S]+Get-AgentRoadHostKeys/);
  const supersede = text.match(/function Reset-AgentRoadSupersedingTransaction[\s\S]+?\n}/)?.[0];
  assert.ok(supersede);
  assert.match(supersede, /COMPLETION_UNCERTAIN/);
  assert.match(supersede, /Test-AgentRoadSupersessionBaseline/);
  assert.match(supersede, /\$script:SupersedingHealthy\s*=\s*\$true/);
  assert.match(supersede, /restoreFile[\s\S]+backups/);
  assert.match(supersede, /New-AgentRoadJournal[\s\S]+Write-AgentRoadJournal/);
  assert.doesNotMatch(supersede, /completionTicket/);
  const main = text.slice(text.indexOf('$failureCode = $null'));
  assert.ok(main.indexOf('Reset-AgentRoadSupersedingTransaction') < main.indexOf('foreach ($checkpoint'));
  assert.ok(main.indexOf('Reset-AgentRoadSupersedingTransaction') < main.lastIndexOf('Ensure-AgentRoadAuthorizedKey'));
  assert.match(text, /Backup-AgentRoadFile \$script:AuthorizedKeyPath[\s\S]+restoreFile/);
});

test('stage one replaces only the exact Microsoft SSH rule and restores it last on rollback', async () => {
  const text = await source();
  const microsoftRule = text.match(/function Test-AgentRoadMicrosoftOpenSshRule[\s\S]+?\n}/)?.[0];
  assert.ok(microsoftRule);
  assert.match(microsoftRule, /OpenSSH-Server-In-TCP/);
  assert.match(microsoftRule, /Direction[\s\S]+Inbound[\s\S]+Action[\s\S]+Allow/);
  assert.match(microsoftRule, /Profile[^\n]+@\('Any','Private'\)/);
  assert.match(microsoftRule, /System32\\OpenSSH\\sshd\.exe/);
  assert.match(microsoftRule, /%SystemRoot%\\system32\\OpenSSH\\sshd\.exe/);
  assert.match(microsoftRule, /\$program[^\n]+Any[^\n]+\$sshd/);
  assert.match(microsoftRule, /Protocol[\s\S]+TCP[\s\S]+LocalPort[\s\S]+22[\s\S]+RemoteAddress[\s\S]+Any/);
  const preflight = text.match(/function Assert-AgentRoadFirewallPreflight[\s\S]+?\n}/)?.[0];
  assert.ok(preflight);
  assert.match(preflight, /Test-AgentRoadMicrosoftOpenSshRule/);
  assert.match(text, /'restoreFirewallEnabled'[\s\S]+OpenSSH-Server-In-TCP/);
  const main = text.slice(text.indexOf('$failureCode = $null'));
  assert.ok(main.indexOf('Ensure-AgentRoadFirewallBoundary') < main.lastIndexOf('Ensure-AgentRoadAccount'));
  const boundary = text.match(/function Ensure-AgentRoadFirewallBoundary[\s\S]+?\n}/)?.[0];
  assert.ok(boundary);
  assert.match(boundary, /Ensure-AgentRoadFirewallRule[\s\S]+Disable-NetFirewallRule[\s\S]+Test-AgentRoadFirewallPostcondition/);
  const rollback = text.match(/function Restore-AgentRoadChanges[\s\S]+?\n}/)?.[0];
  assert.ok(rollback);
  assert.match(rollback, /\$firewallRestoreChanges[\s\S]+foreach \(\$change in \$firewallRestoreChanges\)/);
  assert.ok(rollback.indexOf('foreach ($change in $serviceChanges)') < rollback.indexOf('foreach ($change in $firewallRestoreChanges)'));
  assert.match(rollback, /if \(-not \$rollbackFailed\) \{[\s\S]+foreach \(\$change in \$firewallRestoreChanges\)[\s\S]+Enable-NetFirewallRule[\s\S]+Test-AgentRoadRollbackPostcondition/);
});

test('stage one durably retries one completion payload without rollback after pending', async () => {
  const text = await source();
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  assert.match(text, /completion-pending/);
  assert.match(text, /COMPLETION_UNCERTAIN/);
  assert.match(text, /for \(\$attempt = 1; \$attempt -le 3; \$attempt\+\+\)/);
  assert.match(text, /Invoke-AgentRoadCompletionRequest[\s\S]+StatusCode[\s\S]+200/);
  assert.doesNotMatch(text, /Invoke-WebRequest/);
  assert.match(text, /\$body\s*=\s*\$bodyObject \| ConvertTo-Json/);
  assert.ok(completionFunction.indexOf("status = 'completion-pending'") < completionFunction.indexOf('Invoke-AgentRoadCompletionRequest'));
  assert.match(completionFunction, /completion-pending[\s\S]+Write-AgentRoadJournal[\s\S]+Invoke-AgentRoadCompletionRequest/);
  assert.match(text, /status -eq 'completion-pending'[\s\S]+COMPLETION_UNCERTAIN/);
  assert.match(text, /COMPLETION_UNCERTAIN[\s\S]+throw \('AGENT_ROAD_BOOTSTRAP_FAILED:'/);
  const resumeValidation = text.match(/foreach \(\$checkpoint in @\(\$script:Journal\.checkpoints\)\)[\s\S]+?if \(@\(\$script:Journal\.checkpoints\) -cnotcontains 'preflight'\)/)?.[0];
  assert.ok(resumeValidation);
  assert.match(resumeValidation, /status -eq 'completion-pending'[\s\S]+throw 'COMPLETION_UNCERTAIN'/);
  assert.match(text, /Configuration\.completionTicket\s*=\s*\$null/);
});

test('stage one bounds completion transport and accepts only the exact canonical JSON acknowledgement', async () => {
  const text = await source();
  const requestFunction = text.match(/function Invoke-AgentRoadCompletionRequest[\s\S]+?\n}/)?.[0];
  assert.ok(requestFunction);
  assert.ok(requestFunction.includes('[Net.HttpWebRequest][Net.WebRequest]::Create'));
  assert.match(requestFunction, /Method\s*=\s*'POST'/);
  assert.match(requestFunction, /AllowAutoRedirect\s*=\s*\$false/);
  assert.match(requestFunction, /Timeout\s*=\s*30000/);
  assert.match(requestFunction, /ReadWriteTimeout\s*=\s*30000/);
  assert.match(requestFunction, /Stopwatch\]::StartNew\(\)[\s\S]+30000[\s\S]+ReadTimeout/);
  assert.match(requestFunction, /ContentLength\s*=\s*\$BodyBytes\.Length/);
  assert.match(requestFunction, /ContentLength\s+-gt\s+1024/);
  assert.match(requestFunction, /GetResponseStream/);
  assert.match(requestFunction, /New-Object byte\[\] 1025/);
  assert.match(requestFunction, /UTF8Encoding\(\$false,\$true\)/);
  assert.match(requestFunction, /ContentType[\s\S]+application\/json/);
  assert.match(requestFunction, /SequenceEqual|Compare-AgentRoadBytes/);
  assert.doesNotMatch(requestFunction, /ReadToEnd/);
  assert.match(text, /\{\"protocolVersion\":1,\"deviceId\":.*\"accepted\":true\}/);
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  assert.match(completionFunction, /StatusCode -eq 200[\s\S]+AckValid/);
  const invalidAckBranch = completionFunction.match(/elseif \(\$result\.StatusCode -eq 200 -and -not \$result\.AckValid\) \{[\s\S]+?\n      \}/)?.[0];
  assert.ok(invalidAckBranch);
  assert.match(invalidAckBranch, /\$sawUncertain\s*=\s*\$true/);
  assert.doesNotMatch(invalidAckBranch, /\$rejected\s*=\s*\$true/);
});

test('stage one keeps invalid 200 then 4xx uncertain without rollback', async () => {
  const text = await source();
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  const invalidAckBranch = completionFunction.match(/elseif \(\$result\.StatusCode -eq 200 -and -not \$result\.AckValid\) \{[\s\S]+?\n      \}/)?.[0];
  assert.ok(invalidAckBranch);
  assert.match(invalidAckBranch, /\$sawUncertain\s*=\s*\$true/);
  assert.match(completionFunction, /\$httpStatus -ge 400[\s\S]+if \(-not \$sawUncertain\)/);
  assert.match(completionFunction, /if \(-not \$confirmed -and -not \$rejected\)[\s\S]+COMPLETION_UNCERTAIN/);
});

test('stage one allows an exact valid 200 after an invalid 200', async () => {
  const text = await source();
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  assert.match(completionFunction, /StatusCode -eq 200 -and \$result\.AckValid[\s\S]+\$confirmed\s*=\s*\$true[\s\S]+break/);
  const invalidAckBranch = completionFunction.match(/elseif \(\$result\.StatusCode -eq 200 -and -not \$result\.AckValid\) \{[\s\S]+?\n      \}/)?.[0];
  assert.ok(invalidAckBranch);
  assert.match(invalidAckBranch, /\$sawUncertain\s*=\s*\$true/);
  assert.match(completionFunction, /if \(\$rejected\)[\s\S]+if \(-not \$confirmed[\s\S]+status = 'complete'/);
});

test('stage one keeps all invalid 200 acknowledgements uncertain', async () => {
  const text = await source();
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  const invalidAckBranch = completionFunction.match(/elseif \(\$result\.StatusCode -eq 200 -and -not \$result\.AckValid\) \{[\s\S]+?\n      \}/)?.[0];
  assert.ok(invalidAckBranch);
  assert.match(invalidAckBranch, /\$sawUncertain\s*=\s*\$true/);
  assert.match(completionFunction, /if \(\$attempt -lt 3\)[\s\S]+Start-Sleep/);
  assert.match(completionFunction, /if \(-not \$confirmed -and -not \$rejected\)[\s\S]+status = 'completion-pending'[\s\S]+COMPLETION_UNCERTAIN/);
});

test('stage one treats a first-attempt HTTP 400 as a definite completion rejection', async () => {
  const text = await source();
  const statusFunction = text.match(/function Get-AgentRoadCompletionHttpStatus[\s\S]+?\n}/)?.[0];
  assert.ok(statusFunction);
  assert.match(statusFunction, /WebException/);
  assert.match(statusFunction, /HttpWebResponse/);
  assert.match(statusFunction, /StatusCode/);
  assert.match(statusFunction, /\.Close\(\)/);
  assert.match(statusFunction, /finally[\s\S]+try[\s\S]+\.Close\(\)[\s\S]+catch/);
  assert.doesNotMatch(statusFunction, /GetResponseStream|ReadToEnd|\.Content/);
  assert.match(text, /\$httpStatus\s+-ge\s+400[\s\S]+\$httpStatus\s+-le\s+499[\s\S]+-not \$sawUncertain[\s\S]+\$rejected\s*=\s*\$true[\s\S]+break/);
  assert.match(text, /COMPLETION_REJECTED/);
});

test('stage one keeps network then HTTP 400 uncertain without rollback', async () => {
  const text = await source();
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  assert.match(completionFunction, /\$sawUncertain\s*=\s*\$false/);
  assert.match(completionFunction, /\$null -eq \$httpStatus[\s\S]+\$sawUncertain\s*=\s*\$true/);
  assert.match(completionFunction, /400[\s\S]+if \(-not \$sawUncertain\)[\s\S]+\$rejected\s*=\s*\$true/);
  assert.match(completionFunction, /if \(\$attempt -lt 3\)[\s\S]+Start-Sleep/);
});

test('stage one keeps 5xx then HTTP 400 uncertain', async () => {
  const text = await source();
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  assert.match(completionFunction, /\$httpStatus\s+-ge\s+500[\s\S]+\$httpStatus\s+-le\s+599[\s\S]+\$sawUncertain\s*=\s*\$true/);
  assert.match(completionFunction, /if \(-not \$confirmed -and -not \$rejected\)[\s\S]+COMPLETION_UNCERTAIN/);
});

test('stage one lets an exact 200 complete after transport uncertainty', async () => {
  const text = await source();
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  assert.match(completionFunction, /\$null -eq \$httpStatus[\s\S]+\$sawUncertain\s*=\s*\$true[\s\S]+\$result\.StatusCode -eq 200[\s\S]+\$result\.AckValid[\s\S]+\$confirmed\s*=\s*\$true[\s\S]+break/);
  assert.match(completionFunction, /if \(\$rejected\)[\s\S]+if \(-not \$confirmed[\s\S]+status = 'complete'/);
});

test('stage one keeps all no-response completion attempts uncertain without rollback', async () => {
  const text = await source();
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  assert.match(completionFunction, /\$httpStatus\s*=\s*\$result\.StatusCode/);
  assert.match(completionFunction, /if \(\$null -eq \$httpStatus\)[\s\S]+\$sawUncertain\s*=\s*\$true[\s\S]+if \(-not \$confirmed -and -not \$rejected\)[\s\S]+COMPLETION_UNCERTAIN/);
  assert.match(text, /status -eq 'completion-pending'[\s\S]+COMPLETION_UNCERTAIN/);
});

test('stage one rolls back and clears pending transaction state after definite rejection', async () => {
  const text = await source();
  const completionFunction = text.match(/function Send-AgentRoadCompletion[\s\S]+?\n}/)?.[0];
  assert.ok(completionFunction);
  assert.match(completionFunction, /if \(\$rejected\)[\s\S]+status = 'failed'[\s\S]+failureCode = 'COMPLETION_REJECTED'[\s\S]+rollbackStatus = 'pending'[\s\S]+Write-AgentRoadJournal[\s\S]+throw 'COMPLETION_REJECTED'/);
  assert.match(text, /Restore-AgentRoadChanges[\s\S]+Reset-AgentRoadTransaction/);
  assert.match(text, /rolledBack[\s\S]+return New-AgentRoadJournal/);
});

test('stage one validates compatible effective public-key-only policy', async () => {
  const text = await source();
  const effectivePolicy = text.match(/function Test-AgentRoadSshPolicyCompatibility[\s\S]+?\n}/)?.[0];
  assert.ok(effectivePolicy);
  assert.match(text, /pubkeyauthentication yes/i);
  assert.match(text, /authenticationmethods publickey/i);
  assert.match(text, /passwordauthentication no/i);
  assert.match(text, /kbdinteractiveauthentication no[\s\S]+challengeresponseauthentication no/i);
  assert.match(text, /allowusers\|denyusers\|allowgroups\|denygroups/i);
  assert.match(text, /foreach \(\$challengeDirective in @\('KbdInteractiveAuthentication no','ChallengeResponseAuthentication no'\)\)/);
  assert.match(effectivePolicy, /# BEGIN AGENT ROAD/);
  assert.match(effectivePolicy, /Match User agentroad/);
  assert.match(effectivePolicy, /AuthorizedKeysFile C:\\/);
  assert.match(effectivePolicy, /AuthenticationMethods publickey/);
  assert.match(effectivePolicy, /PasswordAuthentication no/);
  assert.match(effectivePolicy, /foreach \(\$challengeDirective in @\('KbdInteractiveAuthentication no','ChallengeResponseAuthentication no'\)\)/);
  assert.match(effectivePolicy, /AuthorizedKeysCommand/);
  assert.match(effectivePolicy, /TrustedUserCAKeys/);
  assert.match(effectivePolicy, /AuthorizedPrincipals/);
  assert.match(effectivePolicy, /Test-AgentRoadConfiguredListenAddresses/);
  assert.doesNotMatch(effectivePolicy, /Match User \*/);
  assert.doesNotMatch(effectivePolicy, /WindowsIdentity\]::GetCurrent\(\)\.Name/);
  assert.doesNotMatch(effectivePolicy, /Get-LocalUser|\$validationUser|\$validationPath/);
});

test('stage one never promotes an unowned pre-existing AgentRoad account', async () => {
  const text = await source();
  const account = text.match(/function Ensure-AgentRoadAccount[\s\S]+?\n}/)?.[0];
  assert.ok(account);
  assert.match(account, /removeUser/);
  assert.match(account, /SupersedingHealthy/);
  assert.match(account, /ACCOUNT_INVALID/);
  const ownershipCheck = account.search(/removeUser|SupersedingHealthy/);
  assert.ok(ownershipCheck >= 0 && ownershipCheck < account.indexOf('Add-LocalGroupMember'));
});

test('stage one scopes service, firewall, completion facts, rollback, and stable errors', async () => {
  const text = await source();
  assert.match(text, /AgentRoad-OpenSSH-Tailscale/);
  assert.match(text, /@\('100\.64\.0\.0\/10','fd7a:115c:a1e0::\/48'\)/);
  assert.match(text, /-LocalPort\s+22/);
  assert.match(text, /-Protocol\s+TCP/);
  assert.match(text, /ssh_host_\*_key\.pub/);
  assert.match(text, /ssh-keygen\.exe/);
  assert.match(text, /tailscale\.exe/);
  assert.match(text, /\/complete/);
  assert.match(text, /protocolVersion[\s\S]+deviceId[\s\S]+completionTicket[\s\S]+target[\s\S]+tailscaleAddresses[\s\S]+sshHostKeys[\s\S]+sshHostKeyFingerprints[\s\S]+checkpoints/);
  assert.match(text, /\[Array\]::Reverse/);
  for (const action of ['restoreFile', 'removeFile', 'removeDirectory', 'removeUser', 'removeAdminMember', 'restoreService', 'removeFirewall']) {
    assert.match(text, new RegExp(`'${action}'`));
  }
  assert.match(text, /AGENT_ROAD_BOOTSTRAP_FAILED:/);
  assert.doesNotMatch(text, /Write-(?:Host|Verbose|Debug|Information)/);
  assert.match(text, /WaitForExit\(timeoutMilliseconds\)/);
  assert.match(text, /65536/);
});

test('stage one preserves allowlisted failures and reports incomplete rollback', async () => {
  const text = await source();
  assert.match(text, /\$failureCode\s*=\s*\$null/);
  assert.match(text, /INTERNAL_ERROR/);
  assert.match(text, /ROLLBACK_INCOMPLETE/);
  assert.match(text, /failureCode/);
  assert.match(text, /rollbackStatus/);
  assert.ok(text.indexOf('$failureCode = $null') < text.indexOf("$failureCode = 'SSHD_CONFIG_INVALID'"));
});

test('stage one journals bounded SSH setup sites before each fallible step and preserves them through rollback', async () => {
  const text = await source();
  const recorder = text.match(/function Record-AgentRoadValidation[\s\S]+?\n}/)?.[0];
  assert.ok(recorder);
  assert.match(recorder, /Write-AgentRoadJournal/);
  assert.match(recorder, /BOOTSTRAP_STATE_INVALID/);

  const sites = [
    'account-entered',
    'authorized-key-entered',
    'ssh-data-entered',
    'host-keys-entered',
    'sshd-config-entered',
  ];
  for (const site of sites) assert.match(text, new RegExp(`'${site}'`));

  const main = text.slice(text.indexOf('$failureCode = $null'));
  const steps = [
    ['account-entered', 'Ensure-AgentRoadAccount'],
    ['authorized-key-entered', 'Ensure-AgentRoadAuthorizedKey'],
    ['ssh-data-entered', 'Initialize-AgentRoadSshData'],
    ['host-keys-entered', 'Ensure-AgentRoadHostKeys'],
    ['sshd-config-entered', 'Ensure-AgentRoadSshdConfiguration'],
  ];
  for (const [site, step] of steps) {
    assert.ok(main.indexOf(`Record-AgentRoadValidation '${site}'`) < main.indexOf(step));
  }

  const rollback = text.match(/function Restore-AgentRoadChanges[\s\S]+?\n}/)?.[0];
  assert.ok(rollback);
  assert.match(rollback, /Journal\.changes\s*=\s*@\(\);\s*\$script:Journal\.checkpoints\s*=\s*@\(\)/);
  assert.doesNotMatch(rollback, /Journal\.validations\s*=\s*@\(\)/);
  assert.doesNotMatch(text, /failureDetail|InvocationInfo|ScriptLineNumber/);
});

test('stage one journals bounded host-key generation and per-file validation sites', async () => {
  const text = await source();
  const hostKeys = text.match(/function Ensure-AgentRoadHostKeys[\s\S]+?\n}/)?.[0];
  assert.ok(hostKeys);
  assert.match(hostKeys, /Record-AgentRoadValidation 'host-keys-inputs-valid'/);
  assert.match(hostKeys, /Invoke-AgentRoadNative \$keygen @\('-A'\) 60[\s\S]+Record-AgentRoadValidation 'host-keys-generation-valid'/);
  for (let index = 1; index <= 6; index += 1) {
    assert.match(hostKeys, new RegExp(`'host-key-${index}-valid'`));
  }
  for (const site of ['present', 'safe', 'sized', 'acl-set']) {
    assert.match(hostKeys, new RegExp(`'host-key-1-${site}'`));
  }
  const restrictedAcl = text.match(/function Set-AgentRoadRestrictedAcl[\s\S]+?\n}/)?.[0];
  assert.ok(restrictedAcl);
  assert.match(restrictedAcl, /\[string\]\$ValidationPrefix/);
  for (const site of ['acl-granted', 'owner-set', 'acl-verified']) {
    assert.match(restrictedAcl, new RegExp(`'host-key-1-${site}'`));
  }
  assert.match(hostKeys, /Set-AgentRoadRestrictedAcl \$path 'host-key-1'/);
  assert.match(hostKeys, /Record-AgentRoadValidation \$hostKeyValidationNames\[\$index\]/);
  assert.match(text, /validations\.Count\s+-gt\s+32/);
  assert.match(text, /validations\.Count\s+-ge\s+32/);
});

test('stage one journals bounded sshd candidate and publication validation sites', async () => {
  const text = await source();
  const compatibility = text.match(/function Test-AgentRoadSshPolicyCompatibility[\s\S]+?\n}/)?.[0];
  const configuration = text.match(/function Ensure-AgentRoadSshdConfiguration[\s\S]+?\n}/)?.[0];
  assert.ok(compatibility);
  assert.ok(configuration);
  assert.match(compatibility, /\[bool\]\$RecordDiagnostics\s*=\s*\$false/);
  assert.ok(compatibility.includes('# END AGENT ROAD[ \\t]*\\r?$'));
  assert.match(compatibility, /ownedBlock\.Value\.TrimEnd\("`r"\)\s+-split/);
  for (const site of ['syntax-valid', 'listeners-valid', 'block-valid']) {
    assert.match(compatibility, new RegExp(`'sshd-config-${site}'`));
  }
  for (const site of ['input-valid', 'candidate-written', 'candidate-acl-set', 'candidate-selected', 'published', 'postconditions-valid']) {
    assert.match(configuration, new RegExp(`'sshd-config-${site}'`));
  }
  assert.match(configuration, /Test-AgentRoadSshPolicyCompatibility \$candidatePath \$true/);
  assert.ok(configuration.indexOf("'sshd-config-input-valid'") < configuration.indexOf("'sshd-config-candidate-written'"));
  assert.ok(configuration.indexOf("'sshd-config-candidate-written'") < configuration.indexOf("'sshd-config-candidate-acl-set'"));
  assert.ok(configuration.indexOf("'sshd-config-candidate-selected'") < configuration.indexOf("'sshd-config-published'"));
  assert.ok(configuration.indexOf("'sshd-config-published'") < configuration.indexOf("'sshd-config-postconditions-valid'"));
});

test('stage one validates hostile journals before replay and resumes only verified checkpoints', async () => {
  const text = await source();
  for (const name of ['Assert-AgentRoadJournal', 'Assert-AgentRoadChange', 'Test-AgentRoadCheckpointPostcondition', 'Reset-AgentRoadTransaction']) {
    assert.equal((text.match(new RegExp(`function ${name}\\b`, 'g')) ?? []).length, 1, name);
  }
  assert.match(text, /checkpoints\.Count\s+-gt\s+5/);
  assert.match(text, /changes\.Count\s+-gt\s+32/);
  assert.match(text, /restoreFile[\s\S]+removeOpenSshCapability/);
  assert.match(text, /HasDuplicateJsonKeys/);
  assert.match(text, /switch -CaseSensitive/);
  assert.match(text, /failureCode[\s\S]+rollbackStatus[\s\S]+updatedAt/);
  assert.doesNotMatch(text, /aclSddl/);
  assert.match(text, /GetFileInformationByHandle|fsutil\.exe/);
  assert.match(text, /Test-AgentRoadCheckpointPostcondition[^\n]+/);
  assert.match(text, /if \(-not \(Test-AgentRoadCheckpointPostcondition/);
  for (const checkpoint of ['preflight', 'tailscale', 'openssh', 'account', 'firewall']) {
    assert.match(text, new RegExp(`checkpoints\\) -cnotcontains '${checkpoint}'`));
  }
});

test('stage one verifies exact firewall state and bounds timeout cleanup', async () => {
  const text = await source();
  assert.match(text, /-RemoteAddress\s+@\('100\.64\.0\.0\/10','fd7a:115c:a1e0::\/48'\)/);
  const remoteAddresses = text.match(/function Test-AgentRoadTailnetRemoteAddresses[\s\S]+?\n}/)?.[0];
  const scopedRule = text.match(/function Test-AgentRoadScopedFirewallRule[\s\S]+?\n}/)?.[0];
  assert.ok(remoteAddresses);
  assert.ok(scopedRule);
  assert.match(remoteAddresses, /100\.64\.0\.0\/10/);
  assert.match(remoteAddresses, /100\.64\.0\.0\/255\.192\.0\.0/);
  assert.match(remoteAddresses, /fd7a:115c:a1e0::\/48/);
  assert.match(remoteAddresses, /Count\s+-ne\s+2/);
  assert.match(scopedRule, /Test-AgentRoadTailnetRemoteAddresses/);
  assert.match(scopedRule, /Test-AgentRoadCurrentLocalAddresses[\s\S]+LocalAddress/);
  const localAddresses = text.match(/function Test-AgentRoadCurrentLocalAddresses[\s\S]+?\n}/)?.[0];
  assert.ok(localAddresses);
  assert.match(localAddresses, /TailscaleAddresses/);
  assert.match(scopedRule, /\.Program/);
  assert.match(scopedRule, /System32\\OpenSSH\\sshd\.exe/);
  assert.match(scopedRule, /\.Service[^\n]+sshd/);
  assert.match(scopedRule, /EdgeTraversalPolicy[\s\S]+Block/);
  assert.match(text, /function Test-AgentRoadFirewallPostcondition\b/);
  assert.match(text, /\.Profile[\s\S]+RemotePort[\s\S]+RemoteAddress/);
  assert.match(text, /Get-NetFirewallApplicationFilter/);
  assert.match(text, /Get-NetFirewallServiceFilter/);
  assert.match(text, /Get-NetFirewallInterfaceTypeFilter/);
  assert.doesNotMatch(text, /process\.WaitForExit\(\);/);
  assert.match(text, /KillTree/);
  assert.match(text, /WaitForExit\(5000\)/);
});

test('stage one does not classify unrelated app rules and binds sshd only to current Tailscale addresses', async () => {
  const text = await source();
  assert.doesNotMatch(text, /Get-AgentRoadEnabledInboundSshAllowRules/);
  const explicitRules = text.match(/function Get-AgentRoadExplicitSshAllowRules[\s\S]+?\n}/)?.[0];
  assert.ok(explicitRules);
  assert.match(explicitRules, /Get-NetFirewallRule[^\n]+PolicyStore ActiveStore/);
  assert.match(explicitRules, /explicitProgram/);
  assert.match(explicitRules, /explicitService/);
  assert.match(explicitRules, /explicitPort/);
  assert.match(explicitRules, /LocalPort[^\n]+-cne 'Any'/);
  assert.doesNotMatch(explicitRules, /\.Package/);

  assert.match(text, /function Get-AgentRoadTailscaleAddresses\b/);
  assert.match(text, /\$script:TailscaleAddresses/);
  assert.match(text, /ListenAddress ' \+ \$address/);
  assert.match(text, /activeListenAddresses[\s\S]+SSHD_CONFIG_INVALID/);
  assert.match(text, /function Test-AgentRoadListenerPostcondition\b/);
  assert.match(text, /Get-NetTCPConnection[^\n]+LocalPort 22/);
  assert.match(text, /LocalAddress[\s\S]+TailscaleAddresses/);
  assert.match(text, /OwningProcess/);
  assert.match(text, /Win32_Service[^\n]+Name='sshd'/);
  assert.match(text, /Test-AgentRoadListenerPostcondition[\s\S]+SSHD_START_FAILED/);
});

test('stage one rejects forwarding exposure and stops sshd immediately on a bad listener', async () => {
  const text = await source();
  const isolation = text.match(/function Assert-AgentRoadSshTransportIsolation[\s\S]+?\n}/)?.[0];
  assert.ok(isolation);
  assert.match(isolation, /Get-NetIPAddress/);
  assert.match(isolation, /Get-NetIPInterface/);
  assert.match(isolation, /WeakHostReceive[\s\S]+Enabled/);
  assert.match(isolation, /Forwarding[\s\S]+Enabled/);
  assert.doesNotMatch(isolation, /ConnectionState/);
  assert.match(isolation, /Services\\PortProxy/);
  assert.match(isolation, /Get-NetNatStaticMapping/);
  assert.match(isolation, /ExternalPort[\s\S]+InternalPort/);
  const service = text.match(/function Ensure-AgentRoadSshdService[\s\S]+?\n}/)?.[0];
  assert.ok(service);
  assert.match(service, /Test-AgentRoadListenerPostcondition[\s\S]+Stop-Service[^\n]+sshd[\s\S]+Test-AgentRoadPort22Unbound/);
  const main = text.slice(text.indexOf('$failureCode = $null'));
  assert.ok(main.indexOf('Assert-AgentRoadSshTransportIsolation') < main.indexOf('Ensure-AgentRoadOpenSshCapability'));
});

test('stage one treats only a missing NetNat CIM class as no static mappings', async () => {
  const text = await source();
  const helper = text.match(/function Get-AgentRoadNetNatStaticMappings[\s\S]+?\n}/)?.[0];
  assert.ok(helper);
  assert.match(helper, /Get-NetNatStaticMapping -ErrorAction Stop/);
  assert.match(helper, /Microsoft\.Management\.Infrastructure\.CimException/);
  assert.match(helper, /FullyQualifiedErrorId/);
  assert.match(helper, /0x80041010/);
  assert.match(helper, /return @\(\)/);
  assert.match(helper, /throw/);

  const isolation = text.match(/function Assert-AgentRoadSshTransportIsolation[\s\S]+?\n}/)?.[0];
  assert.ok(isolation);
  assert.match(isolation, /Get-AgentRoadNetNatStaticMappings/);
  assert.doesNotMatch(isolation, /Get-NetNatStaticMapping -ErrorAction Stop/);
});

test('stage one permits preinstalled OpenSSH past broad rules only while sshd is stopped and port 22 is unbound', async () => {
  const text = await source();
  const preflight = text.match(/function Assert-AgentRoadFirewallPreflight[\s\S]+?\n}/)?.[0];
  const portCheck = text.match(/function Test-AgentRoadPort22Unbound[\s\S]+?\n}/)?.[0];
  assert.ok(preflight);
  assert.ok(portCheck);
  assert.match(portCheck, /Get-NetTCPConnection[^\n]+State Listen[^\n]+ErrorAction Stop/);
  assert.match(portCheck, /Where-Object[^\n]+LocalPort[^\n]+22/);
  assert.doesNotMatch(portCheck, /-LocalPort 22/);
  assert.match(preflight, /Installed/);
  assert.match(preflight, /Status[^\n]+Stopped/);
  assert.match(preflight, /StartMode[^\n]+@\('Manual','Disabled'\)/);
  assert.match(preflight, /Test-AgentRoadPort22Unbound/);
});

test('stage one verifies every reverse mutation before rollback success', async () => {
  const text = await source();
  for (const name of ['Get-AgentRoadFileSha256', 'Get-AgentRoadAclSha256', 'Test-AgentRoadRollbackPostcondition']) {
    assert.equal((text.match(new RegExp(`function ${name}\\b`, 'g')) ?? []).length, 1, name);
  }
  assert.match(text, /expectedSha256/);
  assert.match(text, /expectedAclSha256/);
  assert.match(text, /Get-LocalUser[^\n]+AgentRoad[\s\S]+Get-LocalGroupMember/);
  assert.match(text, /Get-NetFirewallRule -Name/);
  assert.match(text, /Get-NetFirewallRule -DisplayName/);
  assert.match(text, /StartMode[\s\S]+Status/);
  assert.match(text, /Test-Path[^\n]+removeFile|removeFile[\s\S]+Test-Path/);
  assert.match(text, /foreach \(\$change in \$changes\)[\s\S]+Test-AgentRoadRollbackPostcondition/);
  assert.match(text, /\$rollbackFailed\s*=\s*\$true/);
});

test('stage one is syntactically valid when PowerShell is available', async (t) => {
  const pwsh = spawnSync('sh', ['-c', 'command -v pwsh'], { encoding: 'utf8' }).stdout.trim();
  if (!pwsh) return t.skip('pwsh unavailable');
  await access(scriptUrl);
  const result = spawnSync(pwsh, [
    '-NoProfile', '-Command',
    '$t=$null;$e=$null; [System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$t,[ref]$e)>$null; if($e.Count){$e|Out-String|Write-Error;exit 1}',
    scriptUrl.pathname,
  ], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
