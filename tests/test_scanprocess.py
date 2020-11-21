import unittest
from unittest.mock import patch, call, Mock, MagicMock, PropertyMock
from dscan.models.scanner import ScanProcess, Status
import tests


class TestScanProcess(unittest.TestCase):
    def setUp(self):
        self.callback = Mock()
        self.patch_nmap_proc = patch('dscan.models.scanner.NmapProcess')
        # patching sleep to speed the test execution
        self.patch_sleep = patch('dscan.models.scanner.sleep')
        running_mock = MagicMock(side_effect=[True, True, True, False])
        progress_mock = PropertyMock(side_effect=[10, 50, 100])
        self.mock_nmap_proc = self.patch_nmap_proc.start()
        self.patch_sleep.start()
        self.mock_nmap_proc().is_running = running_mock
        type(self.mock_nmap_proc()).progress = progress_mock
        self.mock_nmap_proc().stdout = "Hello Mock output"
        self.addCleanup(self.patch_nmap_proc.stop)
        self.addCleanup(self.patch_sleep.stop)

    def tearDown(self):
        self.patch_nmap_proc.stop()
        self.patch_sleep.stop()

    @patch('os.path.isfile')
    def test_report_name_single_host(self, mock_isfile):
        mock_isfile.side_effect = [True, False, False]
        expected_calls = [
            call('fake/path/127.0.0.1.nmap'),
            call('fake/path/0-127.0.0.1.nmap'),
            call('fake/path/127.0.0.1.xml')
        ]
        sprocess = ScanProcess("fake/path")
        report = sprocess.run("127.0.0.1", "-p1-20", self.callback)
        self.assertEqual(b"fake/path/127.0.0.1.xml", report.filename)
        mock_isfile.assert_has_calls(expected_calls)
        self.callback.assert_called_once_with(Status.SUCCESS)

    @patch('os.path.isfile')
    def test_report_name_network(self, mock_isfile):
        mock_isfile.return_value = False
        expected_call = [
            call('fake/path/127.0.0.1-24.xml')
        ]
        sprocess = ScanProcess("fake/path")
        report = sprocess.run("127.0.0.1/24", "-p1-20", self.callback)
        self.assertEqual(b"fake/path/127.0.0.1-24.xml", report.filename)
        mock_isfile.assert_has_calls(expected_call)
        self.callback.assert_called_once_with(Status.SUCCESS)

    @patch('os.path.isfile')
    def test_report_name_network_existing(self, mock_isfile):
        mock_isfile.side_effect = [True, False, False]
        expected_calls = [
            call('fake/path/127.0.0.1-24.nmap'),
            call('fake/path/0-127.0.0.1-24.nmap'),
            call('fake/path/127.0.0.1-24.xml')
        ]
        sprocess = ScanProcess("fake/path")
        report = sprocess.run("127.0.0.1/24", "-p1-20", self.callback)
        self.assertIsNotNone(report)
        self.assertEqual(b"fake/path/127.0.0.1-24.xml", report.filename)
        mock_isfile.assert_has_calls(expected_calls)
        self.callback.assert_called_once_with(Status.SUCCESS)


if __name__ == '__main__':
    unittest.main()
