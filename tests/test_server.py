import hmac
import os
import ssl
import struct
import threading
import unittest
from argparse import Namespace
from socket import AF_INET, SOCK_STREAM, socket
from unittest.mock import MagicMock, mock_open, patch

from dscan.models.scanner import Config, Context
from dscan.models.structures import (Auth, ExitStatus, Ready, Report, Status,
                                     Structure)
from dscan.server import AgentHandler, DScanServer
from tests import BufMock, create_config, data_path, log


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
        options = Namespace(name='data', b='127.0.0.1', p=9011,
                            cmd='srv', targets='foofile')
        self.cfg = create_config()
        self.patcher = patch('os.makedirs')
        mos_isfile = patch('os.path.isfile')
        mos_isfile.return_value = True
        mos_isfile.start()
        self.mock_makedirs = self.patcher.start()
        self.settings = Config(self.cfg, options)
        # ctx = Context(self.settings)
        self.ctx = MagicMock(spect=Context)
        self.ctx.pop.return_value = ("127.0.0.1", "-sV -Pn -p1-1000")
        self.ctx.secret_key = self.settings.secret_key
        self.ctx.is_finished = False
        self.mock_server = MagicMock(spect=DScanServer)
        self.mock_server.secret_key = self.settings.secret_key
        self.mock_terminate = MagicMock()
        self.mock_terminate.is_set.return_value = False
        self.hmac_patch = patch.object(hmac, 'compare_digest',
                                       return_value=True)
        self.challenge = b'4%x8p\x8d\xda\x04\xe5r\xfb\xc1Si8[' \
                         b'\xcb\x1a\x1c\x84\xf5\xb5%\x15[' \
                         b'\xea\x10\x96)!n\xe3\xadit\x0f\x15e\xc2\x06\xd1' \
                         b'\xd8\xb0' \
                         b'\xc5\x81\x87\xf2s\xe3\xd8\x95\xd1\x9c\xbdM\x8f' \
                         b'\x9c\xd5' \
                         b'\x14\xb3\x8e\xdd\x8eQ\xffw\x10Y8\xa5\xa5\x83\xf3' \
                         b'\xeeQ' \
                         b'\xa1\xfcOP\x9d\xd6\x80x\x80\x9eh\x11\xa7\xd7\xce' \
                         b'\xcf' \
                         b'.\xec\x01\x94S\xd4\x1d\x7f\xef\x83e\xe8\xfa\xf9' \
                         b'`\xfb' \
                         b'\xc6:SB\xeff\x15\r\xcb\xe9\xa4\xefO\x03i\xe9' \
                         b'\xefoMz\x8b'
        self.hmac_patch.start()
        self.addCleanup(self.patcher.stop)
        self.addCleanup(self.hmac_patch.stop)
        self.addCleanup(mos_isfile.stop)

    def tearDown(self):
        self.patcher.stop()
        self.hmac_patch.stop()

    @patch('socket.socket')
    @patch('os.urandom')
    def test_authentication(self, mock_urandom, mock_socket):

        mock_urandom.return_value = self.challenge
        # emulate the client!

        hmac_hash = hmac.new(self.settings.secret_key, self.challenge,
                             'sha512')
        digest = hmac_hash.hexdigest().encode("utf-8")
        buffer = BufMock(Auth(digest))
        mock_socket.recv = buffer.read
        mock = MagicMock()
        handler = AgentHandler(mock_socket, ('127.0.0.1', '1234'),
                               self.mock_server, terminate_event=self.mock_terminate,
                               context=self.ctx)
        self.assertTrue(handler.authenticated)

    @patch('socket.socket')
    def test_ready(self, mock_socket):
        buffer = BufMock(Auth(self.challenge), Ready(0, "bub"),
                         struct.pack("<B", 0))
        mock_socket.recv = buffer.read

        AgentHandler(mock_socket, ('127.0.0.1', '1234'), self.mock_server,
                     terminate_event=self.mock_terminate, context=self.ctx)
        mock_socket.sendall.assert_called_with(
            b'\x03\t\x10127.0.0.1-sV -Pn -p1-1000')
        self.ctx.running.assert_called_once()
        self.ctx.running.assert_called_with("127.0.0.1:1234")

    @patch('socket.socket')
    def test_wait(self, mock_socket):
        buffer = BufMock(Auth(self.challenge), Ready(0, "bub"),
                         Ready(0, "bub"), struct.pack("<B", 0))
        mock_socket.recv = buffer.read
        mock_data = MagicMock()
        mock_data.side_effect = [None, ("127.0.0.1", "-sV -Pn -p1-1000")]
        self.ctx.pop = mock_data

        AgentHandler(mock_socket, ('127.0.0.1', '1234'), self.mock_server,
                     terminate_event=self.mock_terminate, context=self.ctx)

        mock_socket.sendall.assert_called_with(
            b'\x03\t\x10127.0.0.1-sV -Pn -p1-1000')
        self.ctx.running.assert_called_once()
        self.ctx.running.assert_called_with("127.0.0.1:1234")

    @patch('socket.socket')
    def test_ready_failed(self, mock_socket):
        buffer = BufMock(Auth(self.challenge), Ready(0, "bub"),
                         struct.pack("<B", 1))
        mock_socket.recv = buffer.read

        AgentHandler(mock_socket, ('127.0.0.1', '1234'), self.mock_server,
                     terminate_event=self.mock_terminate, context=self.ctx)
        mock_socket.sendall.assert_called_with(
            b'\x03\t\x10127.0.0.1-sV -Pn -p1-1000')
        self.ctx.running.assert_not_called()
        self.ctx.interrupted.assert_called_once()

    @patch('socket.socket')
    def test_ready_disconnected(self, mock_socket):
        buffer = BufMock(Auth(self.challenge), Ready(0, "bub"))
        mock_socket.recv = buffer.read

        AgentHandler(mock_socket, ('127.0.0.1', '1234'), self.mock_server,
                     terminate_event=self.mock_terminate, context=self.ctx)
        mock_socket.sendall.assert_called_with(
            b'\x03\t\x10127.0.0.1-sV -Pn -p1-1000')
        self.ctx.running.assert_not_called()
        self.ctx.interrupted.assert_called_once()

    @patch('socket.socket')
    def test_report_send(self, mock_socket):
        expected_hash = "055a61499ea7c0d96332cf850f69ecb7295"

        file = open(os.path.join(data_path, 'discovery-nonstandar.xml'),
                    'rb')
        file.seek(0, os.SEEK_END)
        report_msg = Report(file.tell(), "foobar.xml", expected_hash)
        file.seek(0)
        buffer = BufMock(Auth("fu").pack(), report_msg.pack(), file)
        mock_socket.recv = buffer.read
        report_mock = mock_open()
        with patch('builtins.open', report_mock) as m:
            self.ctx.get_report = report_mock
            AgentHandler(mock_socket, ('127.0.0.1', '1234'), self.mock_server,
                         terminate_event=self.mock_terminate, context=self.ctx)
            handle = m.return_value
            offset = file.tell() - 996
            file.seek(offset)
            self.assertEqual(handle.write.call_count, 3)
            handle.write.assert_called_with(file.read())
            self.ctx.downloading.assert_called_with("127.0.0.1:1234")
            self.ctx.completed.assert_called_with("127.0.0.1:1234")
        file.close()

    @patch("builtins.open")
    def test_server(self, mock_open):
        with patch('os.path.isfile') as misfile:
            misfile.return_value = False
            server = DScanServer((self.settings.host, self.settings.port),
                                 AgentHandler, options=self.settings)

            server_thread = threading.Thread(target=server.serve_forever)
            # Exit the server thread when the main thread terminates
            server_thread.daemon = True
            server_thread.start()
            log.info(f"Server loop running in thread: {server_thread.name}")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.load_verify_locations(self.settings.sslcert)
            s = context.wrap_socket(socket(AF_INET, SOCK_STREAM),
                                    server_side=False, server_hostname="dscan")
            s.connect(('127.0.0.1', 9011))

            opr = Structure.create(s)
            hmac_hash = hmac.new(self.settings.secret_key, opr.data,
                                 'sha512')
            digest = hmac_hash.hexdigest().encode("utf-8")

            s.sendall(Auth(digest).pack())
            s.close()
            server.shutdown()


if __name__ == '__main__':
    unittest.main()
