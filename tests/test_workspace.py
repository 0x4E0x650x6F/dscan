
import os
import pickle
import unittest
from io import BytesIO, StringIO
from os import DirEntry
from unittest.mock import MagicMock, Mock, patch

from dscan.models.scanner import (STATUS, Context, DiscoveryStage, File,
                                  ServerConfig, Stage, Task)


class FileSystemMockTestCase(unittest.TestCase):

    @staticmethod
    def build_mock(data):
        def read(size=-1):
            if size:
                if isinstance(data, BytesIO):
                    return data.getvalue()
                else:
                    return data.read(size)
            else:
                return data.read()

        handle = MagicMock(spect=open)
        handle.__enter__.return_value = handle
        handle.__exit__.return_value = False
        handle.__iter__.side_effect = data.__iter__
        handle.__next__.side_effect = data.__next__
        handle.readline = data.readline
        handle.read = read
        handle.seek = data.seek
        handle.tell = data.tell
        handle.write = data.write
        handle.writelines = data.writelines
        return handle

    def setUp(self) -> None:
        mos_isfile = patch('os.path.isfile')
        mos_stat = patch("os.stat")
        mos_access = patch('os.access')
        mos_access.return_value = True
        mos_isfile.return_value = True
        mos_isfile.start()
        mos_access.start()
        mos_stat = mos_stat.start()
        mos_stat.return_value = Mock(st_size=35)
        self.addCleanup(mos_isfile.stop)
        self.addCleanup(mos_access.stop)
        self.addCleanup(mos_stat.stop)


class TestStateFullFile(FileSystemMockTestCase):

    def setUp(self) -> None:
        super(TestStateFullFile, self).setUp()
        mopen = patch('builtins.open', spec=open)
        self.file_mock = mopen.start()
        self.file_mock.return_value = self.build_mock(
            StringIO("192.168.10.0/24\n192.168.12.0/24\n10.100.1.0/24\n"))
        self.targets_file = File('fake/run/targets.work')
        self.targets_file.open()
        self.addCleanup(mopen.stop)

    def test_open(self):
        self.assertTrue(True, self.targets_file.exists())
        self.assertTrue(True, self.targets_file.readable())
        self.assertEqual(3, self.targets_file.nlines)
        self.assertEqual(3, len(self.targets_file))
        line = self.targets_file.readline()
        self.assertEqual('192.168.10.0/24', line)
        self.assertEqual(1, self.targets_file.lineno)
        self.assertEqual(len('192.168.10.0/24\n'), self.targets_file.loc)
        self.targets_file.close()

    def test_serialize(self):
        line = self.targets_file.readline()
        self.assertEqual('192.168.10.0/24', line)
        self.assertEqual(1, self.targets_file.lineno)
        nobj_file = pickle.loads(pickle.dumps(self.targets_file))
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
        outdir = "fake/reports"
        self.data_path = os.path.join(os.path.dirname(__file__), 'data')

        with open(os.path.join(self.data_path,
                               "discovery-nonstandar.xml")) as f:
            self.report1 = StringIO(f.read())

        with open(os.path.join(self.data_path, "discovery-nonstandard.xml"))\
                as f:
            self.report2 = StringIO(f.read())

        patch_scandir = patch('os.scandir')
        scandir_mock = patch_scandir.start()
        mock_direntry1 = Mock(spec=DirEntry)
        mock_direntry1.name = "discovery-nonstandar.xml"
        mock_direntry1.path = os.path.join(outdir, "discovery-nonstandar.xml")
        mock_direntry2 = Mock(spec=DirEntry)
        mock_direntry2.name = "discovery-nonstandard.xml"
        mock_direntry2.path = os.path.join(outdir, "discovery-nonstandard.xml")
        scandir_mock.return_value = iter([mock_direntry1, mock_direntry2])

        super(TestRuntimeContext, self).setUp()
        targets_path = "fake/run/targets.work"
        options = "-sS -n -p22"

        ltargets_path = "fake/run/live_hosts.work"
        resume_path = "fake/run/current.trace"

        self.mock_server_config = MagicMock(spect=ServerConfig)
        self.mock_server_config.rundir = "fake/run"
        self.mock_server_config.queue_path = targets_path
        self.mock_server_config.ltargets_path = ltargets_path
        self.mock_server_config.resume_path = resume_path
        self.mock_server_config.stage_list = [
            DiscoveryStage(targets_path, options, outdir, ltargets_path),
            Stage("stage1", ltargets_path, options, outdir),
            Stage("stage2", ltargets_path, options, outdir)
        ]
        self.mock_server_config.save_context = ServerConfig.save_context
        self.mock_server_config.outdir = outdir
        self.addCleanup(patch_scandir.stop)
        self.live_targets = StringIO()
        self.resume = BytesIO()
        self.targets = StringIO('172.16.71.132\n172.16.71.133\n')
        self.mocks = {
            "fake/run/targets.work": self.targets,
            "fake/reports/discovery-nonstandar.xml": self.report1,
            "fake/reports/discovery-nonstandard.xml": self.report2,
            "fake/run/live_hosts.work": self.live_targets,
            "fake/run/current.trace": self.resume
        }

    def side_effect(self, *args):
        name = args[0]
        if name == "fake/run/live_hosts.work" or name \
                == 'fake/run/current.trace':
            self.live_targets.seek(0)
        return self.build_mock(self.mocks[name])

    def check_tasks(self, task_data, task, stage_name, nactive,
                    expected_target, expected_nactive=1):
        target, options = task_data
        self.assertIsNotNone(task_data)
        self.assertEqual(stage_name, task.stage_name)
        self.assertEqual(expected_target, target)
        self.assertEqual("-sS -n -p22", options)
        self.assertEqual(STATUS.SCHEDULED, task.status)
        self.assertEqual(expected_nactive, nactive)

    @patch('builtins.open', spec=open)
    def test_context_full_flow(self, mock_file):
        mock_file.side_effect = self.side_effect
        context = Context(self.mock_server_config)

        self.assertEqual(3, len(context.stage_list))
        expected_active_status = [('discovery', 2, 2, "100.00%"),
                                  ('stage1', 1, 1, "100.00%"),
                                  ('stage2', 1, 0, "0.00%")]
        expected_task_status = [
            ('127.0.0.1:1010', 'stage1', 'SCHEDULED', '172.16.71.132/31'),
            ('127.0.0.2:1010', 'stage2', 'SCHEDULED', '172.16.71.132/31')
        ]

        agent = "127.0.0.1:1010"
        # starts with stage 1 discovery
        task_data = context.pop(agent)
        task = context.active.get(agent)
        nactive = len(context.active)
        self.check_tasks(task_data, task, "discovery", nactive,
                         "172.16.71.132")

        context.completed(agent)

        # stage 1 discovery target 2
        task_data = context.pop(agent)
        task = context.active.get(agent)
        nactive = len(context.active)
        self.check_tasks(task_data, task, "discovery", nactive,
                         "172.16.71.133")

        context.completed(agent)

        # stage 1
        task_data = context.pop(agent)
        task = context.active.get(agent)
        nactive = len(context.active)
        self.check_tasks(task_data, task, "stage1", nactive,
                         "172.16.71.132/31")
        # if another agent pulls now should be 2 active and stage 2 should
        # start
        task_data = context.pop("127.0.0.2:1010")
        task = context.active.get("127.0.0.2:1010")
        nactive = len(context.active)
        self.check_tasks(task_data, task, "stage2", nactive,
                         "172.16.71.132/31", 2)
        task_status = context.tasks_status()

        self.assertEqual(expected_task_status, task_status)
        context.completed(agent)

        nstages, pending, completion = context.ctx_status()[0]
        self.assertEqual(3, nstages)
        self.assertEqual(0, pending)
        self.assertEqual("66.67%", completion)
        active_status = context.active_stages_status()
        self.assertEqual(expected_active_status, active_status)
        context.completed("127.0.0.2:1010")
        nstages, pending, completion = context.ctx_status()[0]
        self.assertEqual(3, nstages)
        self.assertEqual(0, pending)
        self.assertEqual("100.00%", completion)

        self.assertIsNone(context.pop(agent))

    @patch('builtins.open', spec=open)
    def test_discovery_inc_stage(self, mock_file):
        """
        The discovery stage needs to finish to produce the list of live
        targets for the other stages.
        """
        mock_file.side_effect = self.side_effect
        context = Context(self.mock_server_config)
        self.assertEqual(3, len(context.stage_list))
        context.pop("127.0.0.1:1010")
        context.pop("127.0.0.2:1010")
        self.assertIsNone(context.pop("127.0.0.3:1010"))

    @patch('builtins.open', spec=open)
    def test_interruption(self, mock_file):
        mock_file.side_effect = self.side_effect
        agent = "127.0.0.1:1010"
        context = Context(self.mock_server_config)
        _ = context.pop(agent)
        context.interrupted(agent)

        self.assertEqual(1, len(context.pending))
        _ = context.pop(agent)
        self.assertEqual(0, len(context.pending))

    @patch('builtins.open', spec=open)
    def test_status_update(self, mock_file):
        mock_file.side_effect = self.side_effect
        agent = "127.0.0.1:1010"
        context = Context(self.mock_server_config)
        _ = context.pop(agent)
        # the completed status is short lived as it's deleted after the
        # task is updated.
        test_cases = [
            ("running", STATUS.RUNNING),
            ("downloading", STATUS.DOWNLOADING),
            ("interrupted", STATUS.INTERRUPTED),
        ]

        for name, expected in test_cases:
            method = getattr(context, name)
            method(agent)
            task = context.active.get(agent)
            if name == "interrupted":
                self.assertEqual(None, task)
                self.assertEqual(1, len(context.pending))
                task = context.pending.pop(0)
            self.assertEqual(expected, task.status)

    @patch('builtins.open', spec=open)
    def test_context_resume(self, mock_file):
        mock_file.side_effect = self.side_effect
        agent1 = "127.0.0.1:1010"
        agent2 = "127.0.0.2:1010"
        context = Context(self.mock_server_config)
        task1 = context.pop(agent1)
        task2 = context.pop(agent2)
        context.running(agent1)
        self.mock_server_config.save_context(self.mock_server_config,
                                             context)
        mock_file.assert_any_call('fake/run/current.trace', "wb")

        restored_ctx = Context.create(self.mock_server_config)
        self.assertEqual(context.cstage_name, restored_ctx.cstage_name)
        self.assertEqual(len(context.stage_list), len(restored_ctx.stage_list))
        self.assertEqual(0, len(restored_ctx.active))
        self.assertEqual(context.reports_path, restored_ctx.reports_path)
        self.assertEqual(2, len(restored_ctx.pending))
        rtask1 = restored_ctx.pop(agent1)
        self.assertEqual(task1, rtask1)
        self.assertEqual(1, len(restored_ctx.active))
        rtask2 = restored_ctx.pop(agent2)
        self.assertEqual(task2, rtask2)
        self.assertEqual(2, len(restored_ctx.active))
        self.assertIsNotNone(restored_ctx._lock)
        restored_ctx.completed(agent1)
        restored_ctx.completed(agent2)
        _ = restored_ctx.pop(agent1)
        restored_ctx.completed(agent1)
        restored_ctx.completed(agent2)
        nstages, pending, completion = restored_ctx.ctx_status()[0]
        self.assertEqual(3, nstages)
        self.assertEqual(0, pending)
        self.assertEqual("66.67%", completion)
        self.assertEqual("stage1", restored_ctx.cstage_name)

    @patch("os.stat")
    def test_create(self, os_stat):
        os_stat.return_value = Mock(st_size=0)
        ctx = Context.create(self.mock_server_config)
        self.assertIsNotNone(ctx)


if __name__ == '__main__':
    unittest.main()
