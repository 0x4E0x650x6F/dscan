import hashlib
import io
import unittest
import struct
from unittest.mock import patch, MagicMock
from socket import socket
from dscan.models.structures import Operations
from dscan.models.structures import Auth
from dscan.models.structures import Ready
from dscan.models.structures import Command
from dscan.models.structures import Report
from dscan.models.structures import Structure
from  dscan.models.structures import Status


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
            op = mock_socket.recv(struct_size)
            self.assertEqual(ord(op), Operations.AUTH)
            result = Structure.create(1, sock=mock_socket)
            self.assertEqual(expected.data, result.data)
            self.assertEqual(digest.encode("ascii"), result.data)
            self.assertEqual(Operations.AUTH, result.op_code)

    def test_ready_pack_unpack(self):
        expected = Ready(0, 'agentx')
        mock_sock = self.build_mock(expected)
        with patch('socket.socket', new=mock_sock) as mock_socket:
            struct_size = struct.calcsize("<B")
            op = mock_socket.recv(struct_size)
            self.assertEqual(ord(op), Operations.READY)
            result = Structure.create(2, sock=mock_socket)
            self.assertEqual(expected.uid, result.uid)
            self.assertEqual(expected.alias, result.alias)

    def test_command_pack_unpack(self):
        expected = Command("127.0.0.1", "-sV -Pn -p1-1000")
        mock_sock = self.build_mock(expected)
        with patch('socket.socket', new=mock_sock) as mock_socket:
            struct_size = struct.calcsize("<B")
            op = mock_socket.recv(struct_size)
            self.assertEqual(ord(op), Operations.COMMAND)
            result = Structure.create(3, sock=mock_socket)
            self.assertEqual(expected.target, result.target)

    def test_report_pack_unpack(self):
        digest = hashlib.sha512(b"pickabu").hexdigest()
        expected = Report(self.getSize(), "fu.xml", digest)
        mock_sock = self.build_mock(expected)
        with patch('socket.socket', new=mock_sock) as mock_socket:
            struct_size = struct.calcsize("<B")
            op = mock_socket.recv(struct_size)
            self.assertEqual(ord(op), Operations.REPORT)
            result = Structure.create(6, sock=mock_socket)
            self.assertEqual(expected.filesize, result.filesize)
            self.assertEqual(expected.filename, result.filename)
            self.assertEqual(expected.filehash, result.filehash)

    def test_status(self):
        self.assertTrue((0 == Status.SUCCESS.value))


if __name__ == '__main__':
    unittest.main()
