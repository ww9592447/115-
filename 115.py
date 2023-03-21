import base64
import zlib
import struct
import time
import random
from Crypto.PublicKey import ECC
from urllib.parse import urlencode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import hashlib
import lz4.block as lb
from os.path import getsize, basename
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric import ec


def md5(data) -> str:
    return hashlib.md5(data.encode('utf-8')).hexdigest()


def sha1(data) -> str:
    s = hashlib.sha1()
    s.update(data)
    return s.hexdigest()


def file_sha1(path) -> str:
    with open(path, 'rb') as f:
        sha = hashlib.sha1()
        while True:
            data = f.read(1024 * 128)
            if not data:
                break
            sha.update(data)
        return sha.hexdigest().upper()


class _ECC:
    def __init__(self):
        serverKey = [0x04, 0x57, 0xa2, 0x92, 0x57, 0xcd, 0x23, 0x20,
               0xe5, 0xd6, 0xd1, 0x43, 0x32, 0x2f, 0xa4, 0xbb,
               0x8a, 0x3c, 0xf9, 0xd3, 0xcc, 0x62, 0x3e, 0xf5,
               0xed, 0xac, 0x62, 0xb7, 0x67, 0x8a, 0x89, 0xc9,
               0x1a, 0x83, 0xba, 0x80, 0x0d, 0x61, 0x29, 0xf5,
               0x22, 0xd0, 0x34, 0xc8, 0x95, 0xdd, 0x24, 0x65,
               0x24, 0x3a, 0xdd, 0xc2, 0x50, 0x95, 0x3b, 0xee,
               0xba, ]
        ecckey = ECC.generate(curve='NIST P-224')
        pubkey = list(ecckey.public_key().export_key(format='SEC1', compress=True))
        public_key = EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), bytes(serverKey))
        serverx = public_key.public_numbers().x
        servery = public_key.public_numbers().y

        # ?不知道接下來如何交換金鑰

        self.key = {
            'pubKey': [len(pubkey)] + pubkey,
            # 'aesKey': aesKey,
            # 'aesIv': aesIv,
        }

    def encodetime(self, timestamp: int) -> str:
        buf = [0] * 44
        buf[0:15] = self.key['pubKey'][:15]
        buf[24:39] = self.key['pubKey'][15:]
        buf[16] = 115
        buf[40] = 1
        buf[20:24] = list(struct.pack('I', timestamp))
        r1, r2 = random.randint(0, 255), random.randint(0, 255)
        for i in range(len(buf)):
            buf[i] ^= r1 if i < 24 else r2
        data = bytes(buf)
        crcSalt = b'^j>WD3Kr?J2gLFjD4W2y@'
        crc32 = zlib.crc32(crcSalt + data)
        data += struct.pack('I', crc32)
        return base64.b64encode(data).decode()

    def encode(self, data: dict) -> bytes:
        data = bytearray(urlencode(data).encode('utf-8'))
        for _ in range(4):
            data.append(0)
        cipher = AES.new(bytes(self.key['aesKey']), AES.MODE_CBC, bytes(self.key['aesIv']))
        return cipher.encrypt(pad(data, AES.block_size))

    def decode(self, data: bytes) -> None:
        data = list(data)
        cryptoSize = len(data) - 12
        cryptotext = data[:cryptoSize]
        tail = data[cryptoSize:]
        for index in range(4):
            tail[index] ^= tail[7]
        hex_str = ''.join(['{:x}'.format(b) for b in reversed(tail[0:4])])
        outputSize = int(hex_str.lstrip('0'), 16)
        cipher = AES.new(bytes(self.key['aesKey']), AES.MODE_CBC, bytes(self.key['aesIv']))
        plaintext = list(cipher.decrypt(bytes(cryptotext)))
        hex_str = ''.join(['{:x}'.format(b) for b in reversed(plaintext[0:2])])
        srcSize = int(hex_str.lstrip('0'), 16)
        dec = lb.decompress(bytes(plaintext[2:srcSize + 2]), uncompressed_size=(outputSize))
        print(dec.decode())


class Client:
    def __init__(self):
        self.headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'cookie': '',
        }
        self._ecc = _ECC()
        self.app_version = '2.0.3.6'
        self.userid = ''
        self.userkey = ''
        self.salt = 'Qclm8MGWUv59TnrR0XPg'

    def getuploadinfo(self) -> None:
        result = requests.get("http://proapi.115.com/app/uploadinfo", headers=headers)
        result = result.json()
        self.userid = str(result['user_id'])
        self.userkey = str(result['userkey']).upper()

    def getsig(self, fileid: str, target: str) -> str:
        sz_text = self.userid + fileid + target + "0"
        result = sha1(sz_text.encode())
        sz_text = self.userkey + result + "000000"
        return sha1(sz_text.encode()).upper()

    def upload_file(self, path: str, cid: str) -> None:
        fileid = file_sha1(path)
        target = f'U_1_{cid}'
        filesize = str(getsize(path))
        data = {
            'appid': cid,
            'appversion': self.app_version,
            'filename': basename(path),
            'filesize': filesize,
            'fileid': fileid,
            'target': target,
            'userid': self.userid,
            'sig': self.getsig(fileid, target),
        }
        now = int(time.time())
        token = md5(self.salt + fileid + filesize + self.userid + str(now) + md5(self.userid) + self.app_version)
        data.update({
                't': str(now),
                'token': token,
            })

        url = f'https://uplb.115.com/4.0/initupload.php?k_ec={self._ecc.encodetime(now)}'
        result = requests.post(url, data=self._ecc.encode(data), headers=self.headers)
        result = self._ecc.decode(result.content)
        print(result)


if __name__ == '__main__':
    client = Client()
    client.upload_file('path', 'cid')
