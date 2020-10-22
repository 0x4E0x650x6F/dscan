import unittest
import os
import pickle
from io import TextIOWrapper
from io import BytesIO
from unittest.mock import patch
from unittest.mock import mock_open
from unittest.mock import MagicMock
from unittest.mock import Mock
from dscan.models.scanner import File


class TestStateFullFile(unittest.TestCase):
    def mopen(self, filename, mode):
        if filename == 'fake/targets.work':
            content = "192.168.10.0/24\n192.168.12.0/24\n10.100.1.0/24\n"
            self.targets_mock = mock_open()
            targets_data = MagicMock(spect=TextIOWrapper)
            memory_file = TextIOWrapper(BytesIO(content.encode("utf-8")))
            targets_data.__iter__.return_value = iter(content.split("\n"))
            targets_data.readline = memory_file.readline
            targets_data.read = memory_file.read
            targets_data.seek = memory_file.seek
            targets_data.tell = memory_file.tell
            self.targets_mock.return_value = targets_data
            return self.targets_mock.return_value
        elif filename == 'fake/current.trace':
            content = b""
            if mode == 'wb':
                return mock_open().return_value
            else:
                return mock_open(read_data=content).return_value
        else:
            raise FileNotFoundError(filename)

    def setUp(self) -> None:
        self.data_path = os.path.join(os.path.dirname(__file__), "data")
        patcher = patch('builtins.open', new=self.mopen)
        os_isfile = patch('os.path.isfile')
        os_access = patch('os.access')
        os_access.return_value = True
        os_isfile.return_value = True
        self.targets_mock = patcher.start()
        os_isfile.start()
        os_access.start()
        self.obj_file = File('fake/targets.work')
        self.addCleanup(patcher.stop)
        self.addCleanup(os_isfile.stop)
        self.addCleanup(os_access.stop)

    @patch("os.stat")
    def test_open(self, os_stat):
        os_stat.return_value = Mock(st_size=35)
        self.obj_file.open()
        self.assertTrue(True, self.obj_file.exists())
        self.assertTrue(True, self.obj_file.readable())
        self.assertEqual(3, self.obj_file.nlines)
        self.assertEqual(3, len(self.obj_file))
        _, line = self.obj_file.readline()
        self.assertEqual('192.168.10.0/24', line)
        self.assertEqual(1, self.obj_file.lineno)
        self.assertEqual(len('192.168.10.0/24\n'), self.obj_file.loc)
        self.obj_file.close()

    @patch("os.stat")
    def test_serialize(self, os_stat):
        os_stat.return_value = Mock(st_size=35)
        self.obj_file.open()
        _, line = self.obj_file.readline()
        self.assertEqual('192.168.10.0/24', line)
        self.assertEqual(1, self.obj_file.lineno)
        nobj_file = pickle.loads(pickle.dumps(self.obj_file))
        _, line = nobj_file.readline()
        self.assertEqual("192.168.12.0/24", line)
        self.assertEqual(2, nobj_file.lineno)


if __name__ == '__main__':
    unittest.main()
