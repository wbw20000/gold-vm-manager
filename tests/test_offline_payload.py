"""Archive-only fixtures; no real commands, apps, DMG mounts, network or VMs."""
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import offline_payload as p


class ZipInspectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='offline-zip-test-')
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.cleanup)
        self.path = self.root/'sample.zip'

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(), self.root)
        self.assertTrue(self.root.name.startswith('offline-zip-test-'))
        self.tmp.cleanup()

    def archive(self, entries):
        with zipfile.ZipFile(self.path,'w') as z:
            for name, payload, kind in entries:
                e=zipfile.ZipInfo(name);e.create_system=3
                e.external_attr=(kind|0o755)<<16
                z.writestr(e,payload)
        return self.path

    def base(self):
        return [('Claude.app/',b'',stat.S_IFDIR),('Claude.app/Contents/',b'',stat.S_IFDIR),
                ('Claude.app/Contents/file',b'fixture',stat.S_IFREG)]

    def reject(self, extra):
        self.archive(self.base()+extra)
        with self.assertRaises(p.PayloadError):p.inspect_zip(self.path)

    def test_regular_complete_root_and_internal_symlinks(self):
        self.archive(self.base()+[('Claude.app/Contents/Versions/',b'',stat.S_IFDIR),
            ('Claude.app/Contents/Versions/A/',b'',stat.S_IFDIR),
            ('Claude.app/Contents/Versions/A/executable',b'not executed',stat.S_IFREG),
            ('Claude.app/Contents/Versions/Current',b'A',stat.S_IFLNK),
            ('Claude.app/Contents/executable',b'Versions/Current/executable',stat.S_IFLNK)])
        result=p.inspect_zip(self.path)
        self.assertEqual(result['symlink_count'],2)
        self.assertFalse(result['extraction_performed'])
        self.assertEqual(set(self.root.iterdir()),{self.path})

    def test_traversal_absolute_backslash_and_unrelated_root(self):
        for name in ('/tmp/escape','Claude.app/../escape','Claude.app/a/../../escape','Claude.app/./x',
                     'Claude.app//x','Claude.app/a\\b','Other.app/file'):
            with self.subTest(name=name):self.reject([(name,b'x',stat.S_IFREG)])

    def test_case_and_unicode_collisions(self):
        for names in (('FILE','file'),('\u00e9','e\u0301')):
            with self.subTest(names=names):
                self.reject([('Claude.app/Contents/'+n,b'x',stat.S_IFREG) for n in names])

    def test_descendants_never_traverse_archive_links(self):
        self.reject([('Claude.app/Contents/link',b'other',stat.S_IFLNK),
                     ('Claude.app/Contents/link/child',b'x',stat.S_IFREG)])

    def test_absolute_escaping_cyclic_and_broken_links(self):
        for link in ('/etc/passwd','../../escape','link','missing'):
            with self.subTest(link=link):self.reject([('Claude.app/Contents/link',link.encode(),stat.S_IFLNK)])

    def test_case_alias_cannot_hide_symlink_parent_or_escape(self):
        self.reject([('Claude.app/outside/',b'',stat.S_IFDIR),
                     ('Claude.app/Contents/Up',b'..',stat.S_IFLNK),
                     ('Claude.app/Contents/link',b'up/../../outside',stat.S_IFLNK),
                     ('Claude.app/Contents/LINK/payload',b'never extracted',stat.S_IFREG)])

    def test_implicit_parent_case_and_unicode_aliases_rejected(self):
        for first, second in (('Frameworks','frameworks'),('\u00e9','e\u0301')):
            with self.subTest(names=(first,second)):
                self.reject([('Claude.app/Contents/'+first+'/file',b'x',stat.S_IFREG),
                             ('Claude.app/Contents/'+second+'/',b'',stat.S_IFDIR)])

    def test_symlink_targets_must_use_canonical_archive_spelling(self):
        self.reject([('Claude.app/Contents/Target/',b'',stat.S_IFDIR),
                     ('Claude.app/Contents/link',b'target',stat.S_IFLNK)])

    def test_link_to_application_root_rejected(self):
        self.reject([('Claude.app/Contents/up',b'..',stat.S_IFLNK)])

    def test_escaping_and_returning_link_is_still_refused(self):
        self.reject([('Claude.app/Contents/link',b'../../Claude.app/Contents/file',stat.S_IFLNK)])

    def test_special_setid_and_appledouble_links_rejected(self):
        for name,mode in (('Claude.app/Contents/socket',stat.S_IFSOCK),
                          ('Claude.app/Contents/suid',stat.S_IFREG|stat.S_ISUID),
                          ('__MACOSX/link',stat.S_IFLNK)):
            with self.subTest(name=name):self.reject([(name,b'file',mode)])

    def test_size_and_entry_limits_before_extraction(self):
        self.archive(self.base())
        for kwargs in ({'maximum_bytes':1},{'maximum_entries':1}):
            with self.subTest(kwargs=kwargs),self.assertRaises(p.PayloadError):p.inspect_zip(self.path,**kwargs)

    def test_unreviewed_product_rejected(self):
        self.archive(self.base())
        with self.assertRaises(p.PayloadError):p.inspect_zip(self.path,'Other.app')

    def test_missing_app_root_rejected(self):
        self.archive(self.base()[1:])
        with self.assertRaises(p.PayloadError):p.inspect_zip(self.path)

    def test_local_header_cannot_disagree_with_safe_central_name(self):
        self.archive(self.base())
        with zipfile.ZipFile(self.path) as z:entry=z.getinfo('Claude.app/Contents/file')
        raw=bytearray(self.path.read_bytes());start=entry.header_offset+30
        name=entry.filename.encode();raw[start:start+len(name)]=b'../'+b'x'*(len(name)-3)
        self.path.write_bytes(raw)
        with self.assertRaises(p.PayloadError):p.inspect_zip(self.path)

    def test_regular_stream_crc_checked_before_any_extraction(self):
        self.archive(self.base())
        with zipfile.ZipFile(self.path) as z:entry=z.getinfo('Claude.app/Contents/file')
        raw=bytearray(self.path.read_bytes());start=entry.header_offset+30+len(entry.filename.encode())
        raw[start]^=1;self.path.write_bytes(raw)
        with self.assertRaises(p.PayloadError):p.inspect_zip(self.path)

    def test_same_parser_extraction_preserves_relative_links_without_tools(self):
        import hashlib
        import guest_app_artifacts as a
        self.archive(self.base()+[('Claude.app/Contents/link',b'file',stat.S_IFLNK)])
        digest=hashlib.sha256(self.path.read_bytes()).hexdigest()
        manifest=a.freeze_manifest(product='claudeDesktop',version='1.2.3',
            artifact_url='https://downloads.claude.ai/releases/darwin/universal/1.2.3/Claude-'+('a'*40)+'.zip',known_sha256=digest)
        receipt=a.DownloadReceipt(manifest.artifact_key,str(self.path),digest,self.path.stat().st_size,True,'fixture')
        def forbidden(*args,**kwargs):raise AssertionError('No external ZIP extraction tool permitted')
        with patch.object(p,'_quarantine',return_value=b'fixture'):
            result=p.extract_zip(manifest,receipt,self.root/'extracted',self.root/'evidence',run=forbidden)
        self.assertEqual((result[0]/'Contents/file').read_bytes(),b'fixture')
        self.assertEqual(os.readlink(result[0]/'Contents/link'),'file')
        self.assertEqual((result[0]/'Contents/file').stat().st_mode&0o777,0o755)

    def test_existing_extraction_directory_never_reused(self):
        with self.assertRaises(FileExistsError):p._new_directory(self.root)
        self.assertEqual(list(self.root.iterdir()),[])


if __name__=='__main__':unittest.main()
