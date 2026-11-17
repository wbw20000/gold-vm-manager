import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import discard_state


class DiscardStateTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(tempfile.mkdtemp(prefix='gold-discard-test-',dir='/private/tmp')).resolve(strict=True)
        self.expected=self.root
        self.vm=self.root/'gold'
        self.vm.mkdir(mode=0o700)
        (self.vm/'config.json').write_text('{"test":true}')
        (self.vm/'disk.img').write_bytes(b'original-guest-disk-do-not-edit')
        (self.vm/'state.vzvmsave').write_bytes(b'private-fake-saved-ram')
        self.change=patch.object(discard_state,'VM_ROOT',self.root)
        self.change.start()

    def tearDown(self):
        self.change.stop()
        self.assertEqual(self.root.resolve(strict=True),self.expected)
        self.assertEqual(self.root.parent,Path('/private/tmp').resolve(strict=True))
        self.assertTrue(self.root.name.startswith('gold-discard-test-'))
        self.assertFalse(self.root.is_symlink())
        shutil.rmtree(str(self.root))

    def test_removes_only_saved_ram(self):
        result=discard_state.discard('gold')
        self.assertTrue(result['saved_ram_discarded'])
        self.assertFalse((self.vm/'state.vzvmsave').exists())
        self.assertEqual((self.vm/'config.json').read_text(),'{"test":true}')
        self.assertEqual((self.vm/'disk.img').read_bytes(),b'original-guest-disk-do-not-edit')

    def test_unknown_vm_rejected(self):
        with self.assertRaises(ValueError):discard_state.discard('../gold')
        self.assertTrue((self.vm/'state.vzvmsave').exists())

    def test_symlink_saved_state_rejected(self):
        p=self.vm/'state.vzvmsave'
        self.assertEqual(p.resolve(strict=True),self.vm/'state.vzvmsave')
        p.unlink()
        p.symlink_to(self.vm/'disk.img')
        with self.assertRaises(RuntimeError):discard_state.discard('gold')
        self.assertEqual((self.vm/'disk.img').read_bytes(),b'original-guest-disk-do-not-edit')

    def test_missing_state_never_deletes_disk(self):
        p=self.vm/'state.vzvmsave'
        self.assertEqual(p.resolve(strict=True),p)
        p.unlink()
        with self.assertRaises(OSError):discard_state.discard('gold')
        self.assertTrue((self.vm/'disk.img').exists())

    def test_running_posix_lock_prevents_discard(self):
        # Independent process emulates Tart PIDLock, using ONLY this private fixture.
        code='import fcntl,sys; f=open(sys.argv[1],"r+"); fcntl.lockf(f,fcntl.LOCK_EX); print("ready",flush=True); sys.stdin.read(1)'
        child=subprocess.Popen([sys.executable,'-c',code,str(self.vm/'config.json')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'ready')
            with self.assertRaises(OSError):discard_state.discard('gold')
            self.assertTrue((self.vm/'state.vzvmsave').exists())
            self.assertTrue((self.vm/'disk.img').exists())
        finally:
            child.stdin.write('x');child.stdin.flush()
            child.wait(timeout=5)
            child.stdin.close();child.stdout.close()

if __name__=='__main__':unittest.main()
