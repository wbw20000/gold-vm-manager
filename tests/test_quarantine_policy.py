import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import quarantine_policy as q


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='quarantine-policy-test-')
        self.root=Path(self.tmp.name).resolve();self.addCleanup(self.cleanup)
        self.path=self.root/'new-download';self.path.write_bytes(b'fixture')
        self.calls=[]

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(),self.root)
        self.assertTrue(self.root.name.startswith('quarantine-policy-test-'))
        self.tmp.cleanup()

    def runner(self,existing=None,fail=False):
        current=existing
        def run(argv,**kwargs):
            nonlocal current
            self.calls.append(argv)
            self.assertEqual(argv[0],'/usr/bin/xattr')
            self.assertFalse(any(arg in ('-d','-c','-r') for arg in argv))
            self.assertEqual(argv[-1],str(self.path))
            if fail:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'fixture error')
            if argv[1]=='-w':
                self.assertIsNone(current);current=argv[3].encode();out=b''
            elif argv[1]=='-p':out=(current or b'')+b'\n'
            else:out=(q.NAME+'\n').encode() if current is not None else b'other.attribute\n'
            return SimpleNamespace(returncode=0,stdout=out,stderr=b'')
        return run

    def test_add_missing_with_fixed_native_tool(self):
        result=q.ensure(self.path,run=self.runner())
        self.assertTrue(result.startswith(b'0083;'))
        self.assertEqual(len(self.calls),3)
        self.assertEqual(self.calls[1][1:3],['-w',q.NAME])

    def test_existing_quarantine_is_never_overwritten(self):
        self.assertEqual(q.ensure(self.path,run=self.runner(b'0083;existing')),b'0083;existing')
        self.assertEqual(len(self.calls),2)
        self.assertTrue(all('-w' not in args for args in self.calls))

    def test_native_failure_cannot_be_assumed_attribute_missing(self):
        with self.assertRaises(q.QuarantineError):q.ensure(self.path,run=self.runner(fail=True))
        self.assertEqual(len(self.calls),1)

    def test_empty_attribute_not_accepted_or_cleared(self):
        with self.assertRaises(q.QuarantineError):q.ensure(self.path,run=self.runner(b''))
        self.assertTrue(all('-w' not in args for args in self.calls))


class PropagateTests(unittest.TestCase):
    VALUE=b'0083;65abcdef;Origin Agent;ABCDEF01-2345-6789-ABCD-EF0123456789'

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='quarantine-propagate-test-')
        self.root=Path(self.tmp.name).resolve();self.addCleanup(self.cleanup)
        self.source=self.root/'source';self.target=self.root/'claimed-target'
        self.source.mkdir();self.target.mkdir()
        for path in (self.source,self.target):
            (path/'payload').write_bytes(b'fixture bytes must not change')
        self.calls=[]

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(),self.root)
        self.assertTrue(self.root.name.startswith('quarantine-propagate-test-'))
        self.assertEqual(self.root.stat().st_uid,os.getuid())
        self.tmp.cleanup()

    def runner(self,source_value=VALUE,target_value=None,fail_at=None,failure=None,
               ignore_write=False,stored_value=None):
        self.attrs={self.source:{'fixture.other':b'keep source'},
                    self.target:{'fixture.other':b'keep target'}}
        for path,value in ((self.source,source_value),(self.target,target_value)):
            if value is not None:self.attrs[path][q.NAME]=value
        self.before={path:dict(attrs) for path,attrs in self.attrs.items()}
        def run(argv,**kwargs):
            self.calls.append(list(argv))
            self.assertEqual(argv[0],'/usr/bin/xattr')
            self.assertFalse(any(arg in ('-c','-d','-r') for arg in argv))
            self.assertEqual(kwargs['stdin'],subprocess.DEVNULL)
            self.assertTrue(kwargs['capture_output'])
            self.assertEqual(kwargs['timeout'],30)
            path=Path(argv[-1]);self.assertIn(path,self.attrs)
            attrs=self.attrs[path]
            if len(argv)==2:
                self.assertEqual(path,self.target)
            elif argv[1]=='-p':
                self.assertEqual(argv,['/usr/bin/xattr','-p',q.NAME,str(path)])
            else:
                self.assertEqual(argv[:3],['/usr/bin/xattr','-w',q.NAME])
                self.assertEqual(len(argv),5)
                self.assertEqual(path,self.target)
                self.assertNotIn(q.NAME,attrs)
                self.assertEqual(argv[3].encode('utf-8'),self.before[self.source][q.NAME])
            if len(self.calls)==fail_at:
                if isinstance(failure,BaseException):raise failure
                return failure or SimpleNamespace(returncode=1,stdout=b'',stderr=b'fixture failure')
            if len(argv)==2:out=('\n'.join(attrs)+'\n').encode()
            elif argv[1]=='-p':
                if q.NAME not in attrs:
                    return SimpleNamespace(returncode=1,stdout=b'',stderr=b'No such xattr: com.apple.quarantine')
                out=attrs[q.NAME]+b'\n'
            else:
                if not ignore_write:
                    attrs[q.NAME]=stored_value if stored_value is not None else argv[3].encode('utf-8')
                out=b''
            return SimpleNamespace(returncode=0,stdout=out,stderr=b'')
        return run

    def assert_unchanged(self):
        self.assertEqual(self.attrs,self.before)
        self.assertTrue(all('-w' not in args for args in self.calls))

    def assert_other_data_preserved(self):
        self.assertEqual(self.attrs[self.source],self.before[self.source])
        self.assertEqual(self.attrs[self.target]['fixture.other'],b'keep target')
        for path in (self.source,self.target):
            self.assertEqual((path/'payload').read_bytes(),b'fixture bytes must not change')

    def test_exact_source_value_added_only_when_target_missing(self):
        self.assertEqual(q.propagate(self.source,self.target,run=self.runner()),self.VALUE)
        self.assertEqual(self.calls,[
            ['/usr/bin/xattr','-p',q.NAME,str(self.source)],
            ['/usr/bin/xattr',str(self.target)],
            ['/usr/bin/xattr','-w',q.NAME,self.VALUE.decode(),str(self.target)],
            ['/usr/bin/xattr','-p',q.NAME,str(self.target)]])
        self.assertEqual(self.attrs[self.target][q.NAME],self.VALUE)
        self.assert_other_data_preserved()

    def test_existing_identical_target_is_unmodified(self):
        self.assertEqual(q.propagate(self.source,self.target,
                                    run=self.runner(target_value=self.VALUE)),self.VALUE)
        self.assertEqual(len(self.calls),3)
        self.assert_unchanged();self.assert_other_data_preserved()

    def test_different_existing_target_refused_without_writes(self):
        with self.assertRaisesRegex(q.QuarantineError,'differs; never overwrite'):
            q.propagate(self.source,self.target,run=self.runner(target_value=b'0083;different origin'))
        self.assertEqual(len(self.calls),3)
        self.assert_unchanged();self.assert_other_data_preserved()

    def test_absent_source_fails_before_target_inspection_or_write(self):
        with self.assertRaises(q.QuarantineError):
            q.propagate(self.source,self.target,run=self.runner(source_value=None))
        self.assertEqual(len(self.calls),1)
        self.assert_unchanged()

    def test_malformed_source_is_not_replaced_with_generated_quarantine(self):
        for value in (b'',b'0083;bad\x00origin',b'x'*4097):
            with self.subTest(value_length=len(value)):
                self.calls=[]
                with self.assertRaises(q.QuarantineError):
                    q.propagate(self.source,self.target,run=self.runner(source_value=value))
                self.assertEqual(len(self.calls),1)
                self.assert_unchanged()

    def test_empty_existing_target_refused_without_clearing_or_writing(self):
        with self.assertRaises(q.QuarantineError):
            q.propagate(self.source,self.target,run=self.runner(target_value=b''))
        self.assertEqual(len(self.calls),3)
        self.assert_unchanged()

    def test_nonzero_tool_results_fail_closed_at_every_step(self):
        for step in range(1,5):
            with self.subTest(step=step):
                self.calls=[]
                with self.assertRaises(q.QuarantineError):
                    q.propagate(self.source,self.target,run=self.runner(fail_at=step))
                self.assertEqual(len(self.calls),step)
                if step<3:self.assert_unchanged()
                elif step==3:self.assertEqual(self.attrs,self.before)
                else:self.assertEqual(self.attrs[self.target][q.NAME],self.VALUE)
                self.assert_other_data_preserved()

    def test_tool_exceptions_fail_closed_at_every_step(self):
        for step in range(1,5):
            for error in (OSError('fixture launch failure'),subprocess.TimeoutExpired('/usr/bin/xattr',30)):
                with self.subTest(step=step,error=type(error).__name__):
                    self.calls=[]
                    with self.assertRaises(type(error)):
                        q.propagate(self.source,self.target,run=self.runner(fail_at=step,failure=error))
                    self.assertEqual(len(self.calls),step)
                    if step<3:self.assert_unchanged()
                    elif step==3:self.assertEqual(self.attrs,self.before)
                    self.assert_other_data_preserved()

    def test_oversized_native_output_fails_closed(self):
        for step in range(1,5):
            for stream in ('stdout','stderr'):
                with self.subTest(step=step,stream=stream):
                    self.calls=[]
                    failure=SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
                    setattr(failure,stream,b'x'*65537)
                    with self.assertRaises(q.QuarantineError):
                        q.propagate(self.source,self.target,run=self.runner(fail_at=step,failure=failure))
                    self.assertEqual(len(self.calls),step)
                    if step<3:self.assert_unchanged()
                    self.assert_other_data_preserved()

    def test_successful_write_exit_requires_present_exact_readback(self):
        for options in ({'ignore_write':True},{'stored_value':b'0083;wrong value'}):
            with self.subTest(options=options):
                self.calls=[]
                with self.assertRaises(q.QuarantineError):
                    q.propagate(self.source,self.target,run=self.runner(**options))
                self.assertEqual(len(self.calls),4)
                self.assertEqual(sum('-w' in args for args in self.calls),1)
                self.assert_other_data_preserved()


if __name__=='__main__':unittest.main()
