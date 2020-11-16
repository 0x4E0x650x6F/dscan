import hmac
import os
import io
import unittest
from argparse import Namespace
from configparser import ConfigParser, ExtendedInterpolation
from unittest.mock import patch, MagicMock

import dscan
from scanner import Config
from server import AgentHandler
from structures import Auth


class BufMock:

    def __init__(self, *commands):
        self.reads = []
        for cmd in commands:
            if hasattr(cmd, 'pack'):
                self.reads.append(io.BytesIO(cmd.pack()))
            else:
                if isinstance(cmd, bytes):
                    self.reads.append(io.BytesIO(cmd))
                else:
                    self.reads.append(cmd)
        self.cur_cmd = None
        self.count = 0

    def read(self, size):
        if self.count >= len(self.reads):
            return ''
        if not self.cur_cmd:
            self.cur_cmd = self.reads[self.count]

        if isinstance(self.cur_cmd, io.BytesIO):
            data = self.cur_cmd.read1(size)
        else:
            data = self.cur_cmd.read(size)

        if len(data) == 0 and (self.count + 1) < len(self.reads) \
                and len(self.reads):
            self.count += 1
            self.cur_cmd = self.reads[self.count]
            if isinstance(self.cur_cmd, io.BytesIO):
                data = self.cur_cmd.read1(size)
            else:
                data = self.cur_cmd.read(size)
        return data


class TestAgentHandler(unittest.TestCase):
    def setUp(self):
        self.data_path = os.path.join(os.path.dirname(__file__), "data")
        options = Namespace(name='test', b='127.0.0.1', p=9011,
                            cmd='srv', targets='foofile')
        self.cfg = ConfigParser(interpolation=ExtendedInterpolation())
        self.data = open(os.path.join(self.data_path, 'dscan.conf'))
        self.cfg.read_file(self.data)
        self.patcher = patch('os.makedirs')
        self.mock_makedirs = self.patcher.start()
        self.settings = Config(self.cfg, options)

    def tearDown(self) -> None:
        self.data.close()
        self.addCleanup(self.patcher.stop)

    @patch('socket.socket')
    @patch('os.urandom')
    def test_authentication(self, mock_urandom, mock_socket):
        challenge = b"hello"
        mock_urandom.return_value = challenge
        # emulate the client!

        hmac_hash = hmac.new(self.settings.secret_key, challenge, 'sha512')
        digest = hmac_hash.hexdigest().encode("utf-8")
        buffer = BufMock(Auth(digest))
        mock_socket.recv = buffer.read
        mock = MagicMock()
        mock.secret_key = self.settings.secret_key
        handler = AgentHandler(mock_socket, '127.0.0.1', mock, mock)
        self.assertTrue(handler.authenticated)


if __name__ == '__main__':
    unittest.main()