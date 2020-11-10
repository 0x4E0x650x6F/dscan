import unittest
from io import StringIO
from unittest.mock import patch, Mock, MagicMock, mock_open

from scanner import File


class TestReportsParsers(unittest.TestCase):

    def setUp(self):
        os_isfile = patch('os.path.isfile')
        os_stat = patch("os.stat")
        os_access = patch('os.access')
        os_access.return_value = True
        os_isfile.return_value = True
        os_isfile.start()
        os_access.start()
        os_stat = os_stat.start()
        os_stat.return_value = Mock(st_size=35)
        self.addCleanup(os_isfile.stop)
        self.addCleanup(os_access.stop)
        self.addCleanup(os_stat.stop)
        self.shared = StringIO()
        self.mocks = {
            "ppp": StringIO('192.168.10.0/24\n192.168.10.0/24\n'),
            "live": self.shared,
            "live": self.shared
        }

    def build_mock(self, data):
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

    def side_effect(self, name):
        if name == "live":
            self.shared.seek(0)
        return self.build_mock(self.mocks[name])

    def test_io(self):
        with patch('builtins.open', spec=open) as mock_open:
            mock_open.side_effect = self.side_effect

            with open("ppp") as f:
                for line in f:
                    print(line.strip())
                    #self.assertListEqual(["aa", "bb"], [x for x in f])

            f = open("live")
            f.write("fu\n")
            f.writelines(["fa\n", "fb\b"])

            f = open("live")
            print("last")
            print(f.read())

    def test_open(self):
        self.obj_file = File('fake/run/targets.work')
        self.obj_file.open()
        self.assertTrue(True, self.obj_file.exists())
        self.assertTrue(True, self.obj_file.readable())
        self.assertEqual(3, self.obj_file.nlines)
        self.assertEqual(3, len(self.obj_file))
        line = self.obj_file.readline()
        self.assertEqual('192.168.10.0/24', line)
        self.assertEqual(1, self.obj_file.lineno)
        self.assertEqual(len('192.168.10.0/24\n'), self.obj_file.loc)
        self.obj_file.close()

if __name__ == '__main__':
    unittest.main()
