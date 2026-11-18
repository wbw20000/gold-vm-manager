import struct
import subprocess
import unittest
from unittest.mock import patch

import manager
import process_identity as p


class ProcessIdentityTests(unittest.TestCase):
    def test_decode_keeps_spaces_as_one_argument(self):
        args=['/app/tart','run','中文 VM','--net-fd=12']
        data=struct.pack('=i',len(args))+b'/app/tart\0\0\0'+b'\0'.join(x.encode() for x in args)+b'\0HOME=/unused\0'
        self.assertEqual(p.decode_arguments(data),args)

    def test_malformed_process_metadata_rejected(self):
        for data in [b'',b'x'*7,struct.pack('=i',0)+b'x\0\0\0',struct.pack('=i',99999)+b'x\0\0\0',struct.pack('=i',1)+b'x\0\0\xff\0']:
            self.assertEqual(p.decode_arguments(data),[])

    def controller(self):
        c=object.__new__(manager.Controller)
        c._runtime=lambda _: {'tart_pid':12345}
        c._environment=lambda _: {}
        c._run=lambda _:subprocess.CompletedProcess([],0,str(manager.TART)+' run gold other --net-fd=12','')
        return c

    def test_prefix_collision_never_controls_other_vm(self):
        with patch.object(p,'arguments',return_value=[str(manager.TART),'run','gold other','--net-fd=12']):
            with self.assertRaises(manager.AppError):self.controller()._pid('gold')

    def test_exact_name_with_spaces_is_supported(self):
        with patch.object(p,'arguments',return_value=[str(manager.TART),'run','gold other','--net-fd=12']):
            self.assertEqual(self.controller()._pid('gold other')[0],12345)

    def test_unknown_process_arguments_fail_closed(self):
        with patch.object(p,'arguments',return_value=[]):
            with self.assertRaises(manager.AppError):self.controller()._pid('gold')

if __name__=='__main__':unittest.main()
