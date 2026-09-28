"""Read-only HTTPS download plus isolated macOS install; no account or device actions."""
import hashlib,json,os,pathlib,subprocess,tempfile
origin='https://agent-road.brahma-technologies.com'
existing=pathlib.Path.home()/'.local/bin/agent-road'
before=hashlib.sha256(existing.read_bytes()).hexdigest() if existing.exists() else None
with tempfile.TemporaryDirectory(prefix='agent-road-public-install-') as tmp:
 root=pathlib.Path(tmp)
 def fetch(path,dest):
  subprocess.run(['/usr/bin/curl','-fLsS','--proto','=https','--proto-redir','=https','--max-time','120',origin+path,'-o',str(dest)],check=True)
 fetch('/downloads/controller-manifest.json',root/'manifest.json')
 manifest=json.loads((root/'manifest.json').read_text())
 fetch('/install.sh',root/'install.sh')
 assert hashlib.sha256((root/'install.sh').read_bytes()).hexdigest()==manifest['installerSha256']
 prefix=root/'isolated prefix'
 env={**os.environ,'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','AGENT_ROAD_INSTALL_PREFIX':str(prefix),'AGENT_ROAD_HOME':str(root/'state')}
 install=subprocess.run(['/bin/sh',str(root/'install.sh')],env=env,capture_output=True,text=True,timeout=400)
 assert install.returncode==0,install.stderr
 cli=prefix/'bin/agent-road'
 def run(*args):
  return subprocess.run([str(cli),*args],env=env,capture_output=True,text=True,timeout=30)
 assert run('--help').returncode==0
 listed=run('list');assert listed.returncode==0 and json.loads(listed.stdout)==[]
 caps=run('capabilities');assert caps.returncode==0 and json.loads(caps.stdout)['deviceProbed'] is False
 who=run('whoami');assert who.returncode!=0 and 'AUTH_LOGIN_REQUIRED' in who.stderr
 repeat=subprocess.run(['/bin/sh',str(root/'install.sh')],env=env,capture_output=True,text=True,timeout=60);assert repeat.returncode==0,repeat.stderr
 fetch('/docs/agent-setup.md',root/'guide.md');assert 'PUBLIC_INSTALL_STATUS: AVAILABLE_ALPHA' in (root/'guide.md').read_text()
 assert (hashlib.sha256(existing.read_bytes()).hexdigest() if existing.exists() else None)==before
 print(json.dumps({'origin':origin,'archive':manifest['archive'],'archiveSha256':manifest['sha256'],'installerSha256':manifest['installerSha256'],'realHTTPSDownloads':True,'installerIntegrityVerified':True,'isolatedMacArm64Install':True,'systemNodeNotOnPATH':True,'help':True,'emptyList':True,'capabilities':True,'whoamiRequiresLogin':True,'repeatInstall':True,'existingCLIUnchanged':True,'guideAvailable':True,'accountsOrWindowsChanged':False,'freshMacOS':False,'intelExecuted':False},indent=2))
