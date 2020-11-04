import unittest
import pickle
from io import TextIOWrapper
from io import BytesIO
from unittest.mock import patch
from unittest.mock import mock_open
from unittest.mock import MagicMock
from unittest.mock import Mock
from dscan.models.scanner import ServerConfig
from dscan.models.scanner import File
from dscan.models.scanner import Task, STATUS, DiscoveryStage, Stage, Context


class FileSystemMockTestCase(unittest.TestCase):

    def mopen(self, filename, mode):
        if filename == 'fake/run/targets.work':
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
        elif filename == 'fake/run/current.trace':
            content = b""
            if mode == 'wb':
                return mock_open().return_value
            else:
                return mock_open(read_data=content).return_value
        else:
            raise FileNotFoundError(filename)

    def setUp(self) -> None:
        patcher = patch('builtins.open', new=self.mopen)
        os_isfile = patch('os.path.isfile')
        os_access = patch('os.access')
        os_access.return_value = True
        os_isfile.return_value = True
        self.targets_mock = patcher.start()
        os_isfile.start()
        os_access.start()
        self.obj_file = File('fake/run/targets.work')
        self.addCleanup(patcher.stop)
        self.addCleanup(os_isfile.stop)
        self.addCleanup(os_access.stop)


class TestStateFullFile(FileSystemMockTestCase):

    @patch("os.stat")
    def test_open(self, os_stat):
        os_stat.return_value = Mock(st_size=35)
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

    @patch("os.stat")
    def test_serialize(self, os_stat):
        os_stat.return_value = Mock(st_size=35)
        self.obj_file.open()
        line = self.obj_file.readline()
        self.assertEqual('192.168.10.0/24', line)
        self.assertEqual(1, self.obj_file.lineno)
        nobj_file = pickle.loads(pickle.dumps(self.obj_file))
        line = nobj_file.readline()
        self.assertEqual("192.168.12.0/24", line)
        self.assertEqual(2, nobj_file.lineno)


class TestTasks(unittest.TestCase):

    def test_curd(self):
        stage_name = "discovery"
        options = "-sS -n -p22"
        target = "192.168.0.0/24"
        task = Task(stage_name, options, target)

        self.assertEqual(stage_name, task.stage_name)
        self.assertEqual(options, task.options)
        self.assertEqual(target, task.target)
        self.assertEqual(STATUS.SCHEDULED, task.status)
        task.update(STATUS.RUNNING)
        self.assertEqual(STATUS.RUNNING, task.status)

    def test_invalid_status(self):
        stage_name = "discovery"
        options = "-sS -n -p22"
        target = "192.168.0.0/24"
        task = Task(stage_name, options, target)
        with self.assertRaises(AssertionError):
            task.update("FU")


class TestRuntimeContext(FileSystemMockTestCase):

    def setUp(self) -> None:
        super(TestRuntimeContext, self).setUp()
        targets_path = "fake/run/targets.work"
        options = "-sS -n -p22"
        outdir = "fake/reports"
        ltargets_path = "fake/run/targets.work"
        resume_path = "fake/run/current.trace"
        
        self.mock_server_config = MagicMock(spect=ServerConfig)
        self.mock_server_config.rundir = "fake/run"
        self.mock_server_config.queue_path = targets_path
        self.mock_server_config.ltargets_path = ltargets_path
        self.mock_server_config.resume_path = resume_path
        self.mock_server_config.stage_list = [
            DiscoveryStage(targets_path, options, outdir, ltargets_path),
            Stage("stage1", ltargets_path, options),
            Stage("stage2", ltargets_path, options)
        ]
        self.mock_server_config.outdir = outdir

    @patch("os.stat")
    def test_context(self, os_stat):
        os_stat.return_value = Mock(st_size=35)
        context = Context(self.mock_server_config)
        self.assertEqual(3, len(context.stage_list))
        expected_targets = ['192.168.10.0/24',
                            '192.168.12.0/24',
                            '10.100.1.0/24'
                            ]
        expected_stage_names = [
            "discovery", "stage1", "stage2"
        ]
        for stage_idx in range(3):
            for target_idx in range(3):
                task = context.pop_target("127.0.0.1:1010")
                self.assertIsNotNone(task)
                self.assertEqual(expected_stage_names[stage_idx],
                                 task.stage_name)
                self.assertEqual(expected_targets[target_idx], task.target)
                self.assertEqual("-sS -n -p22", task.options)
                self.assertEqual(STATUS.SCHEDULED, task.status)
                self.assertEqual(1, len(context.active))
                self.assertEqual(task, context.active.get("127.0.0.1:1010"))
                if stage_idx == 0:
                    context.completed("127.0.0.1:1010")


if __name__ == '__main__':
    unittest.main()
