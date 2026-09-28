"""macOS application-install acceptance; cached official Node archive required."""
import hashlib,json,os,pathlib,subprocess,tempfile,sys
bundle=pathlib.Path(sys.argv[1]).resolve()
manifest=json.loads((bundle/'manifest.json').read_text())
node=bundle/'node-arm64.tar.gz'
assert hashlib.sha256(node.read_bytes()).hexdigest()=='61130f394c1630d211dd50aecc4353d379480f36d3ac913cd85dbba1aed585c6'
with tempfile.TemporaryDirectory(prefix='agent-road-install-') as tmp:
 root=pathlib.Path(tmp); fake=root/'bin';fake.mkdir()
 curl=fake/'curl'
 curl.write_text('#!'+sys.executable+'\nimport sys,shutil,pathlib\na=sys.argv[1:];url=next(x for x in a if x.startswith("https://"));src='+repr(str(bundle))+'\np=pathlib.Path(src)/('+repr(manifest['archive'])+' if "/downloads/" in url else "node-arm64.tar.gz")\nshutil.copyfile(p,a[a.index("-o")+1])\n')
 curl.chmod(0o700)
 prefix=root/'prefix with spaces'
 env={**os.environ,'PATH':str(fake)+':/usr/bin:/bin:/usr/sbin:/sbin','AGENT_ROAD_INSTALL_PREFIX':str(prefix),'AGENT_ROAD_HOME':str(root/'state')}
 def install(script=bundle/'install.sh'):
  return subprocess.run(['/bin/sh',str(script)],env=env,capture_output=True,text=True)
 truncated=root/'truncated.sh';truncated.write_text((bundle/'install.sh').read_text().rsplit('}\nmain',1)[0])
 result=install(truncated);assert result.returncode!=0 and not prefix.exists()
 first=install();assert first.returncode==0,first.stderr
 cli=prefix/'bin/agent-road'
 result=subprocess.run([str(cli),'list'],env=env,capture_output=True,text=True)
 assert result.returncode==0 and json.loads(result.stdout)==[],result.stderr
 capabilities=subprocess.run([str(cli),'capabilities'],env=env,capture_output=True,text=True);assert capabilities.returncode==0,capabilities.stderr
 old=cli.read_bytes();assert install().returncode==0 and cli.read_bytes()==old
 cli.write_text('existing-user-tool');assert install().returncode!=0 and cli.read_text()=='existing-user-tool'
 cli.unlink();cli.symlink_to(root/'do-not-touch');assert install().returncode!=0;cli.unlink()
 bad=root/'bad.sh';bad.write_text((bundle/'install.sh').read_text().replace(manifest['sha256'],'0'*64));result=install(bad);assert result.returncode!=0 and 'checksum mismatch' in result.stderr and not cli.exists(),result.stderr
 assert not (prefix/'share/agent-road/install.lock').exists()
 candidate=root/'candidate-prefix';env['AGENT_ROAD_INSTALL_PREFIX']=str(candidate);env['AGENT_ROAD_ARCHIVE_FILE']=str(bundle/manifest['archive'])
 result=install();assert result.returncode==0,result.stderr
 candidate_cli=candidate/'bin/agent-road';help_result=subprocess.run([str(candidate_cli),'--help'],env=env,capture_output=True,text=True)
 assert help_result.returncode==0 and 'runtime-readiness' in help_result.stdout and 'runtime-retain-empty-stage' in help_result.stdout
 assert (candidate/'share/agent-road/releases'/manifest['sha256']/'docs/agent-setup.md').is_file()
 assert (candidate/'share/agent-road/releases'/manifest['sha256']/'docs/agent-interface.md').is_file()
 missing=subprocess.run([str(candidate_cli),'runtime-readiness','dev_nonexistent'],env=env,capture_output=True,text=True)
 assert missing.returncode==2 and missing.stderr=='DEVICE_NOT_FOUND\n',missing.stderr
 env['AGENT_ROAD_INSTALL_PREFIX']=str(root/'bad-candidate-prefix');bad_archive=root/'bad-archive.tgz';bad_archive.write_bytes(b'corrupted')
 env['AGENT_ROAD_ARCHIVE_FILE']=str(bad_archive);result=install();assert result.returncode!=0 and 'checksum mismatch' in result.stderr
 link=root/'linked-archive';link.symlink_to(bundle/manifest['archive']);env['AGENT_ROAD_ARCHIVE_FILE']=str(link)
 result=install();assert result.returncode!=0 and 'Unsafe candidate archive' in result.stderr
 env['AGENT_ROAD_ARCHIVE_FILE']='relative.tgz';result=install();assert result.returncode!=0 and 'absolute path' in result.stderr
 report={'platform':sys.platform,'freshApplicationPrefix':True,'prefixWithSpaces':True,'privateOfficialNodeChecksumVerified':True,'noSystemNodeOnPath':True,'emptyDeviceList':True,'capabilities':True,'repeatInstall':True,'unmanagedLauncherPreserved':True,'symlinkLauncherRefused':True,'corruptDownloadRejected':True,'lockCleaned':True,'truncatedInstallerDoesNotExecute':True,'publicDownloadTested':False,'freshMacOS':False,'windowsPaired':False}
 report.update(candidateArchiveChecksumVerified=True,corruptCandidateRefused=True,symlinkCandidateRefused=True,relativeCandidateRefused=True,packagedReadinessAndRecoveryHelp=True,packagedGuide=True)
 print(json.dumps(report,indent=2))
