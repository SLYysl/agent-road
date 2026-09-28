#!/usr/bin/env python3
"""Build a whitelisted, credential-free private tester handoff. No network calls."""
import argparse, hashlib, html, json, shutil, zipfile
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--artifacts',type=Path,required=True); p.add_argument('--output',type=Path,required=True); a=p.parse_args()
root=a.output.resolve(); root.mkdir(parents=True,exist_ok=False)
source=Path(__file__).resolve().parent
names=['01-安装包','02-素材与反馈包','03-Agent中文提示词包']
for n in names: (root/n).mkdir()
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
payloads={
 'agent-road-controller.tar.gz':(a.artifacts/'distribution-59e025e/agent-road-67d2832d6e02f4f4.tar.gz','67d2832d6e02f4f4e79638729db95094cb714352c29810056df82c71dc4d0666'),
 'install.sh':(a.artifacts/'distribution-59e025e/install.sh','0b24d5127af44630e4b1e492b7217c24689f878c03622f8bb493effc4e78875b'),
 'AgentRoadNativeSetup.exe':(a.artifacts/'AgentRoadNativeSetup-build11.exe','4ad217c8357cf37e9010b221c0ad77e39d6fdbcde9e95d7a7b283a31c2de7dfb')}
for name,(src,sha) in payloads.items():
 if digest(src)!=sha: raise SystemExit('Payload hash mismatch: '+name)
 shutil.copyfile(src,root/names[0]/name)
for i in range(3):
 text=(source/f'{i+1:02}.md').read_text()
 (root/names[i]/'先读我.md').write_text(text)
 page='<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>'+names[i]+'</title><style>body{max-width:960px;margin:40px auto;padding:0 24px;font:17px/1.75 system-ui;background:#f6f7f9;color:#182033}pre{white-space:pre-wrap;overflow-wrap:anywhere}button{padding:10px 18px;cursor:pointer}</style><h1>'+names[i]+'</h1><button onclick="Promise.resolve().then(()=>navigator.clipboard.writeText(document.querySelector(\'pre\').textContent)).then(()=>this.textContent=\'已复制\').catch(()=>this.textContent=\'请手动全选复制\')">复制全文</button><pre>'+html.escape(text)+'</pre>'
 (root/names[i]/'打开阅读.html').write_text(page)
for f in ['inspect-mac.sh','inspect-windows.ps1']: shutil.copyfile(source/f,root/names[0]/f)
for f in ['smoke.ps1','feedback.md']: shutil.copyfile(source/f,root/names[1]/f)
(root/names[1]/'中文素材-hello.txt').write_text('Hello Windows — by Mac Astra\n中文与表情测试 ✅🚀\nAgent Road 私人内测样例；不含真实用户资料。\n')
manifest={'schemaVersion':1,'date':'2026-09-23','channel':'private-real-hardware-trial-candidate','codeRevision':'59e025e','unsignedWindows':True,'publicWindowsRelease':False,'realHardwareNativeOnboardingAccepted':False,'scope':'Mac controller to Windows 11 x64; other directions inspection only','requirements':'Own account, own Tailscale network, internet and device-owner consent','evidence':'One fresh VM paired and core ready; graceful reboot recovery not accepted; this kit is not fresh third-party onboarding evidence','payloadSha256':{n:s for n,(_,s) in payloads.items()}}
(root/names[0]/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
for n in names:
 folder=root/n
 files=sorted(x for x in folder.iterdir() if x.is_file())
 (folder/'SHA256SUMS.txt').write_text(''.join(digest(x)+'  '+x.name+'\n' for x in files))
 with zipfile.ZipFile(root/(n+'.zip'),'w',zipfile.ZIP_DEFLATED) as z:
  for f in sorted(folder.iterdir()): z.write(f,n+'/'+f.name)
(root/'从这里开始.txt').write_text('三个 ZIP 一起发给测试者，分别解压到同一目录。先读 01 的 打开阅读.html，再把 03 的中文提示词交给 Agent。02 用于验收和反馈。\n这是私人 Alpha 测试候选，非三种平台均已支持。Mac→Windows 11 x64 可尝试接入；Mac→Mac、Windows→Windows 只做只读检查。保留浏览器账号授权，仍需互联网和测试者自己的 Tailscale 网络。\n尚不能承诺真实新设备一次接入成功；如系统安全机制拦截，不绕过。\n')
print(root)
