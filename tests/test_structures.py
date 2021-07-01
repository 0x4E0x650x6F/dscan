import hashlib
import io
import struct
import unittest
from socket import socket
from unittest.mock import MagicMock, patch

from dscan.models.structures import (Auth, Command, ExitStatus, Operations,
                                     Ready, Report, Status, Structure)


class TestStructure(unittest.TestCase):

    @staticmethod
    def build_mock(data):
        data = io.BytesIO(data.pack())
        handle = MagicMock(spect=socket)
        handle.recv = data.read1
        return handle

    @staticmethod
    def getSize():
        with open(__file__, 'r') as fileobject:
            fileobject.seek(0, 2)  # move the cursor to the end of the file
            size = fileobject.tell()
        return size

    def test_auth_pack_unpack(self):
        digest = hashlib.sha512(b"pickabu").hexdigest()
        expected = Auth(digest)

        mock_sock = self.build_mock(expected)
        with patch('socket.socket', new=mock_sock) as mock_socket:
            struct_size: int = struct.calcsize("<B")
            result = Structure.create(sock=mock_socket)
            self.assertEqual(expected.data, result.data)
            self.assertEqual(digest.encode("ascii"), result.data)
            self.assertEqual(Operations.AUTH, result.op_code)

    def test_ready_pack_unpack(self):
        expected = Ready(0, 'agentx')
        mock_sock = self.build_mock(expected)
        with patch('socket.socket', new=mock_sock) as mock_socket:
            result = Structure.create(sock=mock_socket)
            self.assertEqual(expected.uid, result.uid)
            self.assertEqual(expected.alias, result.alias)

    def test_result_status_pack_unpack(self):
        expected = ExitStatus(Status.FINISHED)
        mock_sock = self.build_mock(expected)
        with patch('socket.socket', new=mock_sock) as mock_socket:
            result = Structure.create(sock=mock_socket)
            self.assertEqual(expected.op_code, result.op_code)
            self.assertEqual(expected.status, result.status)

    def test_command_pack_unpack(self):
        expected = Command("127.0.0.1", "-sV -Pn -p1-1000")
        mock_sock = self.build_mock(expected)
        with patch('socket.socket', new=mock_sock) as mock_socket:
            result = Structure.create(sock=mock_socket)
            self.assertEqual(expected.target, result.target)

    def test_report_pack_unpack(self):
        digest = hashlib.sha512(b"pickabu").hexdigest()
        expected = Report(self.getSize(), "fu.xml", digest)
        mock_sock = self.build_mock(expected)
        with patch('socket.socket', new=mock_sock) as mock_socket:
            result = Structure.create(sock=mock_socket)
            self.assertEqual(expected.filesize, result.filesize)
            self.assertEqual(expected.filename, result.filename)
            self.assertEqual(expected.filehash, result.filehash)

    def test_status(self):
        self.assertTrue((0 == Status.SUCCESS.value))


if __name__ == '__main__':
    unittest.main()
