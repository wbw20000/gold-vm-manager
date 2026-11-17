"""Read an owned macOS process argv without ambiguous ps whitespace splitting."""
import ctypes
import struct
import sys


def arguments(pid):
    if sys.platform != 'darwin' or type(pid) is not int or pid <= 1:
        return []
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.sysctl
    call.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                     ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    call.restype = ctypes.c_int
    mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
    size = ctypes.c_size_t()
    if call(mib, 3, None, ctypes.byref(size), None, 0) or not 8 <= size.value <= 1024 * 1024:
        return []
    buf = ctypes.create_string_buffer(size.value)
    if call(mib, 3, buf, ctypes.byref(size), None, 0):
        return []
    return decode_arguments(buf.raw[:size.value])


def decode_arguments(data):
    if len(data) < 8: return []
    argc = struct.unpack_from('=i', data)[0]
    if not 1 <= argc <= 4096: return []
    end = data.find(b'\0', 4)
    if end < 0: return []
    pos = end + 1
    while pos < len(data) and data[pos] == 0: pos += 1
    items = data[pos:].split(b'\0', argc)
    if len(items) < argc + 1: return []
    try: return [x.decode('utf-8', errors='strict') for x in items[:argc]]
    except UnicodeError: return []
