"""Correct PDF Standard security handler (R=2..4) tools.

For R=4 + /CFM /AESV2 the U entry is still verified with RC4
(ISO 32000-1 Algorithm 5); only stream/string data uses AES-128-CBC.
"""
import hashlib
import struct

from Crypto.Cipher import AES, ARC4

PAD = bytes([
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56,
    0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A])


def rc4(key, data):
    return ARC4.new(key).encrypt(data)


def pad_password(pw):
    if isinstance(pw, str):
        pw = pw.encode('latin-1')
    return (pw + PAD)[:32]


class PdfCrypt:
    def __init__(self, o, u, p, r, v, file_id, length=128):
        self.O = o
        self.U = u
        self.P = p
        self.R = r
        self.V = v
        self.ID = file_id
        self.n = length // 8

    def compute_key(self, pw):
        h = hashlib.md5()
        h.update(pad_password(pw))
        h.update(self.O)
        h.update(struct.pack('<i', self.P))
        h.update(self.ID)
        key = h.digest()
        if self.R >= 3:
            for _ in range(50):
                key = hashlib.md5(key[:self.n]).digest()
        return key[:self.n]

    def compute_U(self, key, r):
        x = rc4(key, hashlib.md5(PAD + self.ID).digest())
        if r >= 3:
            for i in range(1, 20):
                x = rc4(bytes(b ^ i for b in key), x)
        return x

    def check_user(self, pw):
        key = self.compute_key(pw)
        u = self.compute_U(key, self.R)
        return u == self.U[:16 if self.R >= 3 else 32]

    def check_owner(self, pw):
        """Algorithm 7: derive user password from owner password."""
        h = hashlib.md5(pad_password(pw)).digest()
        if self.R >= 3:
            for _ in range(50):
                h = hashlib.md5(h).digest()
        okey = h[:self.n]
        if self.R == 2:
            user_pw = rc4(okey, self.O)
        else:
            user_pw = self.O
            for i in range(19, -1, -1):
                user_pw = rc4(bytes(b ^ i for b in okey), user_pw)
        return self.check_user(user_pw)

    def obj_key(self, num, gen=0, aes=True):
        ext = struct.pack('<i', num)[:3] + struct.pack('<i', gen)[:2]
        if aes:
            ext += b'sAlT'
        return hashlib.md5(self.key + ext).digest()[:min(self.n + 5, 16)]

    def decrypt_stream(self, num, gen, data, aes=True):
        key = self.obj_key(num, gen, aes)
        if aes:
            if len(data) < 16:
                return b''
            iv, body = data[:16], data[16:]
            body = body[:len(body) - (len(body) % 16)]
            return AES.new(key, AES.MODE_CBC, iv).decrypt(body)
        return rc4(key, data)
