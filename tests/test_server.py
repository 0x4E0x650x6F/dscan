import hmac
import os
import io
import struct
import unittest
from argparse import Namespace
from configparser import ConfigParser, ExtendedInterpolation
from unittest.mock import patch, MagicMock, mock_open
from dscan.server import AgentHandler
from dscan.models.structures import Auth
from dscan.models.structures import Ready
from dscan.models.structures import Report
from dscan.models.scanner import Config
from dscan.server import DScanServer


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

    @staticmethod
    def build_mock(data):
        handle = MagicMock(spect=open)
        handle.__enter__.return_value = handle
        handle.__exit__.return_value = False
        handle.__iter__.side_effect = data.__iter__
        handle.__next__.side_effect = data.__next__
        handle.readline = data.readline
        handle.read = data.read
        handle.seek = data.seek
        handle.tell = data.tell
        handle.write = data.write
        handle.writelines = data.writelines
        return handle

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
        self.mock_server = MagicMock(spect=DScanServer)
        self.mock_server.secret_key = self.settings.secret_key

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
        handler = AgentHandler(mock_socket, '127.0.0.1', mock,
                               terminate_event=mock)
        self.assertTrue(handler.authenticated)

    @patch.object(hmac, 'compare_digest', return_value=True)
    @patch('socket.socket')
    def test_ready(self, mock_socket, handler):
        buffer = BufMock(Auth("fu"), Ready(0, "bub"), struct.pack("<B", 0))
        mock = MagicMock()
        mock_socket.recv = buffer.read

        AgentHandler(mock_socket, '127.0.0.1', self.mock_server,
                     terminate_event=mock)
        mock_socket.sendall.assert_called_with(
            b'\x03\t\x10127.0.0.1-sV -Pn -p1-1000')

    @patch.object(hmac, 'compare_digest', return_value=True)
    @patch('socket.socket')
    def test_report_send(self, mock_socket, handler):
        expected_hash = "055a61499ea7c0d96332cf850f69ecb7295" \
               "0c3666dee9912ca5b175dd8c5e592a6ea66" \
               "b90d47f40f84834fc50fa18c0984a9264a2" \
               "de5b74f3a195316ebb26b04"

        file = open(os.path.join(self.data_path, 'discovery-nonstandar.xml'),
                    'rb')
        file.seek(0, os.SEEK_END)
        report_msg = Report(file.tell(), "foobar.xml", expected_hash)
        file.seek(0)
        buffer = BufMock(Auth("fu").pack(), report_msg.pack(), file)
        mock = MagicMock()
        mock_socket.recv = buffer.read
        report_mock = mock_open()
        with patch('builtins.open', report_mock) as m:
            self.mock_server.ctx.get_report = report_mock
            AgentHandler(mock_socket, '127.0.0.1', self.mock_server,
                         terminate_event=mock)
            handle = m.return_value
            offset = file.tell() - 996
            file.seek(offset)
            self.assertEqual(handle.write.call_count, 3)
            handle.write.assert_called_with(file.read())
        file.close()


if __name__ == '__main__':
    unittest.main()
