import hmac
import os
import io
import struct
import threading
import logging
import unittest
from argparse import Namespace
from configparser import ConfigParser, ExtendedInterpolation
import ssl
from socket import socket
from socket import AF_INET
from socket import SOCK_STREAM
from unittest.mock import patch, MagicMock, mock_open
from dscan.server import AgentHandler
from dscan.models.structures import Auth
from dscan.models.structures import Ready
from dscan.models.structures import Report
from dscan.models.structures import Structure
from dscan.models.scanner import Config, Context
from dscan.server import DScanServer


log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


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
        # ctx = Context(self.settings)
        self.ctx = MagicMock(spect=Context)
        self.ctx.pop.return_value = ("127.0.0.1", "-sV -Pn -p1-1000")
        self.ctx.secret_key = self.settings.secret_key
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
        handler = AgentHandler(mock_socket, ('127.0.0.1', '1234'),
                               self.mock_server, terminate_event=mock,
                               context=self.ctx)
        self.assertTrue(handler.authenticated)

    @patch.object(hmac, 'compare_digest', return_value=True)
    @patch('socket.socket')
    def test_ready(self, mock_socket, handler):
        buffer = BufMock(Auth("fu"), Ready(0, "bub"), struct.pack("<B", 0))
        mock = MagicMock()
        mock_socket.recv = buffer.read

        AgentHandler(mock_socket, ('127.0.0.1', '1234'), self.mock_server,
                     terminate_event=mock, context=self.ctx)
        mock_socket.sendall.assert_called_with(
            b'\x03\t\x10127.0.0.1-sV -Pn -p1-1000')
        self.ctx.running.assert_called_once()
        self.ctx.running.assert_called_with("127.0.0.1:1234")

    @patch.object(hmac, 'compare_digest', return_value=True)
    @patch('socket.socket')
    def test_ready_failed(self, mock_socket, handler):
        buffer = BufMock(Auth("fu"), Ready(0, "bub"), struct.pack("<B", 1))
        mock = MagicMock()
        mock_socket.recv = buffer.read

        AgentHandler(mock_socket, ('127.0.0.1', '1234'), self.mock_server,
                     terminate_event=mock, context=self.ctx)
        mock_socket.sendall.assert_called_with(
            b'\x03\t\x10127.0.0.1-sV -Pn -p1-1000')
        self.ctx.running.assert_not_called()
        self.ctx.interrupted.assert_called_once()

    @patch.object(hmac, 'compare_digest', return_value=True)
    @patch('socket.socket')
    def test_ready_disconnected(self, mock_socket, handler):
        buffer = BufMock(Auth("fu"), Ready(0, "bub"))
        mock = MagicMock()
        mock_socket.recv = buffer.read

        AgentHandler(mock_socket, ('127.0.0.1', '1234'), self.mock_server,
                     terminate_event=mock, context=self.ctx)
        mock_socket.sendall.assert_called_with(
            b'\x03\t\x10127.0.0.1-sV -Pn -p1-1000')
        self.ctx.running.assert_not_called()
        self.ctx.interrupted.assert_called_once()

    @patch.object(hmac, 'compare_digest', return_value=True)
    @patch('socket.socket')
    def test_report_send(self, mock_socket, handler):
        expected_hash = "055a61499ea7c0d96332cf850f69ecb7295"

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
            self.ctx.get_report = report_mock
            AgentHandler(mock_socket, ('127.0.0.1', '1234'), self.mock_server,
                         terminate_event=mock, context=self.ctx)
            handle = m.return_value
            offset = file.tell() - 996
            file.seek(offset)
            self.assertEqual(handle.write.call_count, 3)
            handle.write.assert_called_with(file.read())
            self.ctx.downloading.assert_called_with("127.0.0.1:1234")
            self.ctx.completed.assert_called_with("127.0.0.1:1234")
        file.close()

    def test_server(self):

        server = DScanServer((self.settings.host, self.settings.port),
                             AgentHandler, options=self.settings)

        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        log.info(f"Server loop running in thread:{server_thread.name}")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.load_verify_locations(self.settings.sslcert)
        s = context.wrap_socket(socket(AF_INET, SOCK_STREAM),
                                server_side=False, server_hostname="dscan")
        s.connect(('127.0.0.1', 9011))

        #struct_size = struct.calcsize("<B128s")
        #op, data = struct.unpack("<B128s", s.recv(struct_size))
        s.recv(1)
        opr = Structure.create(1, s)
        hmac_hash = hmac.new(self.settings.secret_key, opr.data,
                             'sha512')
        digest = hmac_hash.hexdigest().encode("utf-8")

        s.sendall(Auth(digest).pack())
        s.close()
        server.shutdown()


if __name__ == '__main__':

    unittest.main()
