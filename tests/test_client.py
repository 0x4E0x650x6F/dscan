import hashlib
import hmac
import os
import struct
import unittest
from argparse import Namespace
from socket import timeout
from unittest.mock import MagicMock, call, mock_open, patch

import tests
from dscan.client import Agent
from dscan.models.scanner import Config, ScanProcess
from dscan.models.structures import (Auth, Command, ExitStatus, Ready, Report,
                                     Status)


class TestAgentHandler(unittest.TestCase):
    def setUp(self):
        options = Namespace(name='data', s='127.0.0.1', p=2040,
                            cmd='agent')
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
        self.cfg = tests.create_config()
        self.patcher_makedirs = patch('os.makedirs')
        mos_isfile = patch('os.path.isfile')
        mos_isfile.return_value = True
        mos_isfile.start()
        self.mock_makedirs = self.patcher_makedirs.start()
        self.settings = Config(self.cfg, options)
        self.hmac_patch = patch.object(hmac, 'compare_digest',
                                       return_value=True)
        self.hmac_patch.start()
        self.patcher_defContext = patch('ssl.create_default_context')
        self.patcher_sslContext = patch('ssl.SSLContext', name="sslContext")
        self.patcher_socket = patch('socket.socket', name="socket")
        self.patcher_urandom = patch('os.urandom', name="urandom")
        self.mock_urandom = self.patcher_urandom.start()
        self.mock_urandom.return_value = self.challenge
        self.mock_create_ctx = self.patcher_defContext.start()
        self.mock_context = self.patcher_sslContext.start()
        self.mock_socket = self.patcher_socket.start()
        self.mock_create_ctx.return_value = self.mock_context
        self.mock_context.wrap_socket.return_value = self.mock_socket
        hmac_hash = hmac.new(self.settings.secret_key, self.challenge,
                             'sha512')
        self.digest_auth = hmac_hash.hexdigest().encode("utf-8")
        self.expected_calls_timeout = [
            call.connect(('127.0.0.1', 2040)),
            call.recv(1),
            call.__bool__(),
            call.recv(128),
            call.sendall(Auth(self.digest_auth).pack()),
            call.recv(1),
            call.sendall(Ready(os.getuid(), "AAAAAA").pack()),
            call.recv(1),
            call.close(),
            call.close(),
            call.connect(('127.0.0.1', 2040)),
            call.recv(1),
            call.__bool__(),
            call.recv(128),
            call.sendall(Auth(self.digest_auth).pack()),
            call.recv(1),
            call.sendall(Ready(os.getuid(), "AAAAAA").pack()),
            call.recv(1),
            call.close(),
            call.close(),
            call.connect(('127.0.0.1', 2040)),
            call.recv(1),
            call.close(),
            call.close(),
            call.connect(('127.0.0.1', 2040)),
            call.recv(1),
            call.close(),
            call.close(),
        ]
        self.addCleanup(self.patcher_makedirs.stop)
        self.addCleanup(self.hmac_patch.stop)
        self.addCleanup(self.patcher_defContext.stop)
        self.addCleanup(self.patcher_sslContext.stop)
        self.addCleanup(self.patcher_socket.stop)
        self.addCleanup(self.patcher_urandom.stop)
        self.addCleanup(mos_isfile.stop)

    def tearDown(self):
        self.patcher_makedirs.stop()
        self.hmac_patch.stop()
        self.patcher_defContext.stop()
        self.patcher_sslContext.stop()
        self.patcher_socket.stop()
        self.patcher_urandom.stop()

    def check_mock_calls_connect_disconnect(self):
        self.mock_context.wrap_socket.assert_called_once()
        self.mock_context.load_verify_locations.assert_called_once()
        self.mock_socket.connect.assert_called()
        self.mock_socket.close.assert_called()
        # Check call args
        self.mock_context.load_verify_locations.assert_called_once_with(
            'data/certfile.crt')
        self.mock_socket.connect.assert_called_with(
            ('127.0.0.1', 2040))

    def mock_server_responses(self, *args):
        buffer = tests.BufMock(*args)
        self.mock_socket.recv = buffer.read

    def test_connect(self):
        agent = Agent(self.settings)
        agent.start()
        self.check_mock_calls_connect_disconnect()

    def test_timeout_after_auth(self):
        mock_ex = MagicMock()
        mock_ex.side_effect = [struct.pack("<B", 1),
                               struct.pack("<128s", self.challenge),
                               struct.pack("<B", 0),
                               timeout(),
                               timeout(),
                               timeout(),
                               timeout()
                               ]
        expected = [
            call.connect(('127.0.0.1', 2040)),
            call.recv(1),
            call.__bool__(),
            call.recv(128),
            call.sendall(Auth(self.digest_auth).pack()),
            call.recv(1),
            call.sendall(Ready(os.getuid(), "AAAAAA").pack()),
            call.recv(1),
            call.close(),
            call.close(),
            call.connect(('127.0.0.1', 2040)),
            call.recv(1),
            call.close(),
            call.close(),
            call.connect(('127.0.0.1', 2040)),
            call.recv(1),
            call.close(),
            call.close(),
        ]
        self.mock_socket.recv = mock_ex
        with patch('random.choice') as mock_choice:
            mock_choice.return_value = "A"
            agent = Agent(self.settings)
            agent.start()
            self.mock_socket.assert_has_calls(expected)

    def test_reset_retry_count_timeout(self):
        mock_ex = MagicMock()
        mock_ex.side_effect = [struct.pack("<B", 1),
                               struct.pack("<128s", self.challenge),
                               struct.pack("<B", 0),
                               timeout(),
                               struct.pack("<B", 1),
                               struct.pack("<128s", self.challenge),
                               struct.pack("<B", 0),
                               timeout(),
                               timeout(),
                               timeout(),
                               ]
        self.mock_socket.recv = mock_ex
        with patch('random.choice') as mock_choice:
            mock_choice.return_value = "A"
            agent = Agent(self.settings)
            agent.start()
            self.mock_socket.assert_has_calls(self.expected_calls_timeout)

    @patch('os.getuid')
    def test_full(self, mgetuid):
        mgetuid.return_value = 0

        digest = hashlib.sha512(b"pickabu").hexdigest()
        data = "hello hello report mock\n"
        expected = Report(len(data), "fu.xml", digest)

        expected_calls = [
            call.connect(('127.0.0.1', 2040)),
            call.sendall(Auth(self.digest_auth).pack()),
            call.sendall(Ready(0, "AAAAAA").pack()),
            call.sendall(expected.pack()),
            call.sendall(data),
            call.sendall(data),
            call.sendall(Ready(0, "AAAAAA").pack()),
            call.close()
        ]

        self.mock_server_responses(Auth(self.challenge), struct.pack("<B", 0),
                                   Command("127.0.0.1", "-sV -Pn -p1-1000"),
                                   struct.pack("<B", 1), struct.pack("<B", 0))

        report_mock = mock_open(read_data=data)
        with patch('random.choice') as mock_choice:
            mock_choice.return_value = "A"
            with patch('builtins.open', report_mock):
                patcher = patch.object(ScanProcess, 'run',
                                       return_value=expected)
                patcher.start()
                agent = Agent(self.settings)
                agent.start()
                self.check_mock_calls_connect_disconnect()
                self.mock_socket.assert_has_calls(expected_calls,
                                                  any_order=True)
                patcher.stop()

    @patch('os.getuid')
    def test_wait(self, mgetuid):
        mgetuid.return_value = 0

        digest = hashlib.sha512(b"pickabu").hexdigest()
        data = "hello hello report mock\n"
        expected = Report(len(data), "fu.xml", digest)

        expected_calls = [
            call.connect(('127.0.0.1', 2040)),
            call.sendall(Auth(self.digest_auth).pack()),
            call.sendall(Ready(0, "AAAAAA").pack()),
            call.sendall(expected.pack()),
            call.sendall(data),
            call.sendall(data),
            call.sendall(Ready(0, "AAAAAA").pack()),
            call.close()
        ]

        self.mock_server_responses(Auth(self.challenge),
                                   struct.pack("<B", 0),
                                   ExitStatus(Status.UNFINISHED),
                                   Command("127.0.0.1", "-sV -Pn -p1-1000"),
                                   struct.pack("<B", 1), struct.pack("<B", 0))

        report_mock = mock_open(read_data=data)
        with patch('random.choice') as mock_choice:
            mock_choice.return_value = "A"
            with patch('builtins.open', report_mock):
                patcher = patch.object(ScanProcess, 'run',
                                       return_value=expected)
                patcher.start()
                agent = Agent(self.settings)
                agent.start()
                self.check_mock_calls_connect_disconnect()
                self.mock_socket.assert_has_calls(expected_calls,
                                                  any_order=True)
                patcher.stop()

    @patch('os.getuid')
    def test_full_unsuccessful_report(self, mgetuid):
        mgetuid.return_value = 0

        hmac_hash = hmac.new(self.settings.secret_key, self.challenge,
                             'sha512')
        digest_auth = hmac_hash.hexdigest().encode("utf-8")
        digest = hashlib.sha512(b"pickabu").hexdigest()
        data = "hello hello report mock\n"
        expected = Report(len(data), "fu.xml", digest)

        expected_calls = [
            call.connect(('127.0.0.1', 2040)),
            call.sendall(Auth(digest_auth).pack()),
            call.sendall(Ready(0, "AAAAAA").pack()),
            call.sendall(expected.pack()),
            call.sendall(data),
            call.sendall(data),
            call.sendall(data),
            call.close()
        ]

        self.mock_server_responses(Auth(self.challenge), struct.pack("<B", 0),
                                   Command("127.0.0.1", "-sV -Pn -p1-1000"),
                                   struct.pack("<B", 1), struct.pack("<B", 1),
                                   struct.pack("<B", 1))

        report_mock = mock_open(read_data=data)
        with patch('random.choice') as mock_choice:
            mock_choice.return_value = "A"
            with patch('builtins.open', report_mock):
                patcher = patch.object(ScanProcess, 'run',
                                       return_value=expected)
                patcher.start()
                agent = Agent(self.settings)
                agent.start()
                self.check_mock_calls_connect_disconnect()
                self.mock_socket.assert_has_calls(expected_calls,
                                                  any_order=True)
                patcher.stop()


if __name__ == '__main__':
    unittest.main()
