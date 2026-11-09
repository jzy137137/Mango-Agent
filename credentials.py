"""User-scoped Windows DPAPI storage; no plaintext API key is written to disk."""
import ctypes
import os
from ctypes import wintypes
from pathlib import Path

KEY_FILE = Path(__file__).resolve().parent / 'secrets' / 'api-key.dpapi'

class Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]

def _crypt(data, decrypt=False):
    if os.name != 'nt':
        raise RuntimeError('Local encrypted key storage requires Windows; use environment variable')
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    library = ctypes.WinDLL('crypt32', use_last_error=True)
    function = library.CryptUnprotectData if decrypt else library.CryptProtectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
        raise RuntimeError('Windows could not access the encrypted key for this user')
    free = ctypes.WinDLL('kernel32', use_last_error=True).LocalFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_void_p
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        free(ctypes.cast(output.data, ctypes.c_void_p))

def save_key(key):
    key = key.strip()
    if not key or any(c.isspace() for c in key):
        raise ValueError('API Key must be nonempty and contain no whitespace')
    encrypted = _crypt(key.encode('utf-8'))
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_bytes(encrypted)

def load_key(env_name):
    key = os.environ.get(env_name, '')
    if key:
        return key
    if KEY_FILE.exists():
        return _crypt(KEY_FILE.read_bytes(), decrypt=True).decode('utf-8')
    return ''
