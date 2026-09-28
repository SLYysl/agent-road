import csv,json,sys,unittest
from pathlib import Path

def summarize(rows):
    totals={}
    for row in rows:
        minutes=int(row['minutes'])
        if minutes<0: raise ValueError('negative duration')
        totals[row['category']]=totals.get(row['category'],0)+minutes
    return {'records':len(rows),'minutes':sum(totals.values()),'categories':totals,'dataKind':'synthetic demo data'}

class Checks(unittest.TestCase):
    def test_empty(self): self.assertEqual(summarize([])['minutes'],0)
    def test_aggregation(self):
        self.assertEqual(summarize([{'category':'code','minutes':'4'},{'category':'code','minutes':'7'}])['categories'],{'code':11})
    def test_reject_negative(self):
        with self.assertRaises(ValueError): summarize([{'category':'code','minutes':'-1'}])

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='test':
        result=unittest.TextTestRunner(stream=sys.stdout,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
        sys.exit(0 if result.wasSuccessful() else 1)
    else:
        rows=list(csv.DictReader(Path('sessions.csv').open(encoding='utf-8-sig',newline='')))
        Path('summary.json').write_text(json.dumps(summarize(rows),indent=2),encoding='utf8')
