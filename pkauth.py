__author__ = "Benjamin Mickler"
__copyright__ = "Copyright 2022, Benjamin Mickler"
__credits__ = ["Benjamin Mickler"]
__license__ = "GPLv3 or later"
__version__ = "18082022"
__maintainer__ = "Benjamin Mickler"
__email__ = "ben@benmickler.com"

"""
pkauth is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

pkauth is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
pkauth. If not, see <https://www.gnu.org/licenses/>.
"""

"""
Registration:
Client to server (action = 4): [action]?[uuid]?[public_key]
if UUID already registered:
Server to client (action = 5): [action]?[challege]
Client to server (action = 6): [action]?[decrypted challenge]

Authentication:
Client to server (action = 0): [action]?[uuid]?[request]
Server to client (action = 1): [action]?[challenge]
Client to server (action = 2): [action]?[decrypted challenge]
Server to client (action = 3): [action]?[request result]
"""


import asyncio
import os
import sqlite3
import secrets
import sys
import uuid
import string
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Key:
    def __init__(self, data=None, filename=None, public_key_filename=None, private_key_filename=None):
        self.public_key_filename = public_key_filename
        self.private_key_filename = private_key_filename
        self.filename = filename
        self.exists = False
        self.data = data
        self.key = Fernet.generate_key()
        if filename != None or public_key_filename != None and private_key_filename != None:
            self.load()
    def load(self):
        if not self.filename:
            if os.path.isfile(self.private_key_filename) and os.path.isfile(self.public_key_filename):
                self.exists = True
                with open(self.private_key_filename, "rb") as key_file:
                    self.private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend()
                    )
                with open(self.public_key_filename, "rb") as key_file:
                    self.public_key = serialization.load_pem_public_key(
                        key_file.read(),
                        backend=default_backend()
                    )
        elif self.filename != None:
            if os.path.isfile(self.filename):
                self.exists = True
                with open(self.filename, "rb") as key_file:
                    file_data = key_file.read()
                self.private_key = serialization.load_pem_private_key(
                    file_data.split(b"\r\n")[0],
                    password=None,
                    backend=default_backend()
                )
                self.public_key = serialization.load_pem_public_key(
                    file_data.split(b"\r\n")[1],
                    backend=default_backend()
                )
        elif self.data != None:
            self.exists = True
            self.private_key = serialization.load_pem_private_key(
                self.data.split(b"\r\n")[0],
                password=None,
                backend=default_backend()
            )
            self.public_key = serialization.load_pem_public_key(
                self.data.split(b"\r\n")[1],
                backend=default_backend()
            )
    def private_bytes(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    def public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    def create(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        if self.public_key_filename and self.private_key_filename:
            self.exists = True
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.private_key_filename, 'wb') as f:
                f.write(private_pem)
            with open(self.public_key_filename, 'wb') as f:
                f.write(public_pem)
        elif self.filename:
            self.exists = True
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.filename, 'wb') as f:
                f.write(private_pem+b"\r\n"+public_pem)

class Challenge:
    def __init__(self, public_key):
        self.public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )
    def generate(self):
        letters = string.ascii_lowercase+string.ascii_uppercase+string.digits
        self.original_data = ''.join(secrets.choice(letters) for i in range(50)).encode()
        self.encrypted_data = self.public_key.encrypt(self.original_data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self.encrypted_data_base64 = base64.b64encode(self.encrypted_data)
        return self.encrypted_data_base64
    def verify(self, data: bytes):
        return data == self.original_data

class Server:
    def __init__(self, db: str):
        self.db = db
        self.conn = sqlite3.connect(self.db)
        self.cursor = self.conn.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS clients (uuid TEXT, public_key BLOB)")
    def add_client(self, uuid: str, public_key: bytes):
        self.cursor.execute("INSERT INTO clients (uuid, public_key) VALUES (?, ?)", (uuid, memoryview(public_key)))
        self.conn.commit()
    def get_client(self, uuid: str):
        self.cursor.execute("SELECT public_key FROM clients WHERE uuid = ?", (uuid,))
        return self.cursor.fetchone()[0]
    def check_client(self, uuid: str):
        self.cursor.execute("SELECT uuid FROM clients WHERE uuid = ?", (uuid,))
        return self.cursor.fetchone() != None
    async def handle_client(self, reader: asyncio.StreamReader, writer):
        buff = b""
        challenge_completed = False
        challenge_sent = False
        request = None
        while True:
            while b'\r\n' not in buff:
                data = await reader.read(100)
                if not data or data == b"DIS\r\n":
                    break
                elif data == b"EXIT\r\n":
                    sys.exit(0)
                buff += data
            if not data or data == b"DIS\r\n":
                break
            data,sep,buff = buff.partition(b'\r\n')
            data = data.split(b"?")
            if data[0] == b"4":
                if not self.check_client(data[1].decode()):
                    self.add_client(data[1].decode(), data[2])
                    writer.write("OK\r\n".encode())
                else:
                    print("Client with UUID '{}' already exists, sending challenge".format(data[1].decode()))
                    challenged_UUID = data[1].decode()
                    challenged_public_key = data[2]
                    register_challenge = Challenge(self.get_client(data[1].decode()))
                    register_challenge_data = register_challenge.generate()
                    writer.write(register_challenge_data)
                    writer.write(b"\r\n")
            elif data[0] == b"5":
                if register_challenge.verify(data[1]):
                    print("Challenge accepted, registered user with UUID '{}'".format(challenged_UUID))
                    self.add_client(challenged_UUID, challenged_public_key)
                else:
                    print("Challenge rejected, user with UUID '{}' not registered".format(challenged_UUID))
            elif data[0] == b"0":
                request = data[2]
                if not challenge_completed and not challenge_sent:
                    challenge = Challenge(self.get_client(data[1].decode()))
                    challenge_data = challenge.generate()
                    writer.write(challenge_data)
                    writer.write(b"\r\n")
                    challenge_sent = True
                    await writer.drain()
            elif data[0] == b"2":
                if not challenge_completed and challenge_sent:
                    if challenge.verify(data[1]):
                        challenge_completed = True
                        print("Client successfully authenticated")
                
    async def listen(self, port: int):
        server = await asyncio.start_server(
            self.handle_client, '0.0.0.0', port)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f'Serving on {addrs}')
        async with server:
            await server.serve_forever()

class Client:
    def __init__(self, uuid: str, key: Key=None):
        self.key = key
        self.uuid = uuid
        self.connected = False
    async def connect(self, host: str, port: int):
        self.reader, self.writer = await asyncio.open_connection(host, port)
        self.connected = True
    async def register(self, old_key, new_key=True):
        if not self.connected:
            return False
        if self.key == None or new_key:
            print("Generating new key")
            self.key = Key(filename="test.key")
            self.key.create()
        if not self.key.exists:
            print("Generating new key")
            self.key.create()
        self.writer.write(b"4?"+self.uuid.encode()+b"?"+self.key.public_bytes()+b"\r\n")
        buff = b""
        while b'\r\n' not in buff:
            data = await self.reader.read(100)
            if not data or data == b"END\r\n":
                break
            buff += data
        data,sep,buff = buff.partition(b'\r\n')
        if data == b"OK":
            print("Registered")
            return True
        else:
            data = base64.b64decode(data)
            data = old_key.private_key.decrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            self.writer.write(b"5?"+data+b"\r\n")
    async def auth(self):
        if not self.connected:
            return False
        request = "test request"
        self.writer.write(b"0?"+self.uuid.encode()+b"?"+request.encode()+b"\r\n")
        buff = b""
        while b'\r\n' not in buff:
            data = await self.reader.read(100)
            if not data or data == b"END\r\n":
                break
            buff += data
        data,sep,buff = buff.partition(b'\r\n')
        data = base64.b64decode(data)
        try:
            data = self.key.private_key.decrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        except:
            data = b"0"
        self.writer.write(b"2?"+data+b"\r\n")

if __name__ == "__main__":
    def server_main():
        server = Server("server.db")
        asyncio.run(server.listen(8356))
    import multiprocessing
    multiprocessing.Process(target=server_main).start()
    import time
    time.sleep(1)
    async def client_main():
        k = Key(filename="test.key")
        a = Client(str(uuid.uuid4()), key=k)
        await a.connect("127.0.0.1", 8356)
        print("Client connected")
        await a.register(Key(filename="test.key"), new_key=False)
        await a.auth()
        a.writer.write(b"EXIT\r\n")
        sys.exit(0)
    asyncio.run(client_main())