import importlib.util
from pathlib import Path
import unittest
import tempfile,json,time
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('watch',Path(__file__).resolve().parents[1]/'tools/acceptance/stability_watch.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class WatchTest(unittest.TestCase):
    def test_pending_is_not_accepted(self):
        self.assertEqual(m.summarize([{'started':0,'status':'OK'}],0,86400,100)['status'],'OBSERVING')
    def test_complete_coverage(self):
        samples=[{'started':x,'status':'OK'} for x in range(0,86400,900)]
        self.assertEqual(m.summarize(samples,0,86400,86401)['status'],'PASSED')
    def test_sleep_gap_or_failure_is_not_accepted(self):
        samples=[{'started':x,'status':'OK'} for x in range(0,86400,900)]
        self.assertEqual(m.summarize(samples[2:],0,86400,86401)['status'],'NOT_ACCEPTED')
        samples[2]['status']='INCOMPLETE'
        self.assertEqual(m.summarize(samples,0,86400,86401)['status'],'NOT_ACCEPTED')
    def test_boot_change_is_visible_and_not_accepted(self):
        samples=[{'started':x,'status':'OK','observation':{'boot':'a' if x<900 else 'b'}} for x in range(0,86400,900)]
        result=m.summarize(samples,0,86400,86401)
        self.assertEqual(result['status'],'NOT_ACCEPTED')
        self.assertEqual(result['distinctBoots'],2)
    def test_event_identity_reconciles_timestamp_drift_but_not_real_boot_change(self):
        samples=[{'started':x,'status':'OK','observation':{'boot':'old' if x<900 else 'drift', 'bootRecord':2627,'bootEventUtc':'2026-09-26T11:50:21Z'}} for x in range(0,86400,900)]
        result=m.summarize(samples,0,86400,86401)
        self.assertEqual(result['status'],'PASSED')
        self.assertEqual(result['distinctBoots'],2)
        self.assertEqual(result['distinctBootIdentities'],1)
        samples[-1]['observation']['bootRecord']=2628
        self.assertEqual(m.summarize(samples,0,86400,86401)['status'],'NOT_ACCEPTED')
    def test_partial_event_identity_is_not_accepted(self):
        samples=[{'started':x,'status':'OK','observation':{'boot':'same','bootRecord':2627,'bootEventUtc':'same-event'}} for x in range(0,86400,900)]
        del samples[-1]['observation']['bootEventUtc']
        self.assertEqual(m.summarize(samples,0,86400,86401)['status'],'NOT_ACCEPTED')
    def test_service_restart_is_not_hidden(self):
        samples=[{'started':x,'status':'OK','observation':{'sshdPid':1 if x<900 else 2}} for x in range(0,86400,900)]
        result=m.summarize(samples,0,86400,86401)
        self.assertEqual(result['status'],'NOT_ACCEPTED')
        self.assertEqual(result['distinctSshdPids'],2)
    def test_no_samples_cannot_pass(self):
        self.assertEqual(m.summarize([],0,86400,86401)['status'],'NOT_ACCEPTED')
    def test_deadline_and_pause_never_dispatch(self):
        for paused, expired in [(True,False),(False,True)]:
            with tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp); now=time.time()
                (p/'watch.json').write_text(json.dumps({'start':now-90000 if expired else now,'deadline':now-1 if expired else now+86400}))
                if paused:(p/'PAUSE').touch()
                with patch.object(m.subprocess,'run',side_effect=AssertionError('must not dispatch')):
                    m.main(p)
                result=json.loads((p/'summary.json').read_text())
                self.assertEqual(result['samples'],0)
    def test_connection_failure_collects_only_configured_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);now=time.time()
            config={'start':now,'deadline':now+86400,'home':'/isolated','node':'node','cli':'cli.mjs','device':'dev_vm','expectedHost':'ROAD-CLEAN','fallback':{'device':'dev_host','script':'diagnostic.ps1','home':'/other'}}
            (p/'watch.json').write_text(json.dumps(config))
            calls=[]
            def run(args,**kwargs):
                calls.append(args)
                if len(calls)==1:kwargs['stderr'].write('REMOTE_CONNECTION_FAILED\n');kwargs['stderr'].flush()
                return type('Result',(),{'returncode':2 if len(calls)==1 else 0})()
            with patch.object(m.subprocess,'run',side_effect=run):m.main(p)
            self.assertEqual(len(calls),2)
            self.assertEqual(calls[1][2:4],['exec','dev_host'])
            self.assertEqual(json.loads((p/'summary.json').read_text())['failedOrIncomplete'],1)
            with patch.object(m.subprocess,'run',side_effect=AssertionError('cadence must prevent another dispatch')):m.main(p)
if __name__=='__main__':unittest.main()
