#!/usr/bin/env python3
# encoding: utf-8

"""
scanner.py
scanner runtime models
"""

import os
import ipaddress
import hashlib
import threading
import pickle
from enum import Enum
from dscan import log
from parsers import TargetOptimization, ReportsParser


class ServerConfig:
    SERVER = (
        'server', 'stats', 'targets', 'live-targets', 'trace',
    )

    SSL_CERTS = (
        'certs', 'sslcert', 'sslkey'
    )

    SCAN_CONF = 'nmap-scan'

    def __init__(self, config, options, outdir):
        """
        :param config: configparser with the configuration
        :type config: `configparser.ConfigParser`
        :param options: argument parser `argparse.ArgumentParser`
        with the user options
        """
        self.outdir = outdir
        self.rundir = os.path.abspath(os.path.join(
            options.name, config.get(*self.SERVER[0:2:1])))
        self.queue_path = os.path.abspath(os.path.join(
            options.name, config.get(*self.SERVER[0:3:2])))
        self.ltargets_path = os.path.abspath(os.path.join(
            options.name, config.get(*self.SERVER[0:4:3])))
        self.resume_path = os.path.abspath(os.path.join(
            options.name, config.get(*self.SERVER[0:5:4])))
        self.host = options.b
        os.makedirs(self.rundir, exist_ok=True)
        # init scan stages !
        self.__create_stages(dict(config.items('nmap-scan')))
        # set cert properties
        self.sslcert = os.path.abspath(config.get(*self.SSL_CERTS[0:2:1]))
        self.sslkey = os.path.abspath(config.get(*self.SSL_CERTS[0:3:2]))
        digest: hashlib.sha512 = hashlib.sha512()
        try:
            with open(self.sslcert, 'rt') as cert:
                digest.update(cert.read().strip().encode("utf-8"))
                self.secret_key = digest.hexdigest().encode("utf-8")
        except OSError as ex:
            log.error(f"failed to open cert file {ex}")

    def __create_stages(self, scan_options):
        self.stage_list = []
        for name, options in scan_options.items():
            options = scan_options.get(name)
            if name == "discovery":
                self.stage_list.append(DiscoveryStage(self.queue_path,
                                                      options, self.outdir,
                                                      self.ltargets_path))
            else:
                self.stage_list.append(Stage(name, self.ltargets_path,
                                             options, self.outdir))

    def target_optimization(self, targets):
        """
        Takes a list of ip Addresses and groups all sequential ips in
        cidr notation.
        :param targets: `list` of `str`
        """
        assert len(targets) != 0, "Empty target list"
        if not os.path.isfile(self.resume_path):
            queue_optimization = TargetOptimization(self.queue_path)
            queue_optimization.save(targets)

    def save_context(self, ctx):
        """
        Serializes the context to resume later.
        :param ctx: instance of `Context`
        :type ctx: `Context`
        """
        log.info(f"Saving the current context {self.resume_path}")
        with open(self.resume_path, 'wb') as rfile:
            pickle.dump(ctx, rfile)


class Config:
    """
        Runtime configurations
    """

    BASE = (
        'base', 'reports',
    )

    def __init__(self, config, options):
        """
        Holds the configuration parameters
        used at runtime for both server and agent!
        :param config: configparser with the configuration
        :type config: `configparser.ConfigParser`
        :param options: argument parser `argparse.ArgumentParser`
        with the user options
        """
        self.port = options.p
        self.dataPath = os.path.join(os.path.dirname(__file__), "data")
        self.outdir = os.path.abspath(os.path.join(options.name, config.get(
            *self.BASE)))
        os.makedirs(self.outdir, exist_ok=True)
        self.config = None
        if options.cmd == 'srv':
            self.config = ServerConfig(config, options, self.outdir)
        else:
            self.host = options.s

    def __getattr__(self, name):
        if hasattr(self.config, name):
            return getattr(self.config, name)
        else:
            raise AttributeError(f"invalid key {name}")


class File:
    """
    Creates a stateful file object
    allows file to restore its previous state.
    """

    def __init__(self, path):
        """
        :param path:
        :type path: `str` File path
        """
        self._path = path
        self._fd = None
        self.nlines = 0
        self.lineno = 0
        self.loc = 0
        self.mode = 'r'

    def open(self, mode='r'):
        assert self.exists(), f"{self._path} is not a valid file"
        assert self.readable(), f"Unable to read: {self._path}"
        if not self._fd:
            self.mode = mode
            self._fd = open(self._path, mode)
            self._line_count()

    def readline(self):
        self.open()  # open the file if its not open already
        self.lineno += 1
        line = self._fd.readline()
        self.loc = self._fd.tell()
        if not line:
            return None
        return line.strip()

    def isempty(self):
        """
        Check if the file is emtpy
        :return: `True` if the file is empty
        """
        assert self.exists(), f"{self._path} is not a valid file"
        assert self.readable(), f"Unable to read: {self._path}"
        if os.stat(self._path).st_size > 0:
            return False
        else:
            return True

    def exists(self):
        """
        Returns a Boolean if the path is a valid file.
        proxy call to `os.path.isfile`
        :return: `True` if path is a valid file.
        """
        return os.path.isfile(self._path)

    def readable(self):
        """
        :return: `True` if file is readable.
        """
        return os.access(self._path, os.R_OK)

    def _line_count(self):
        """
        Counts the number of lines in the file.
        """
        if self.isempty():
            return 0

        lines = 0
        buf_size = 1024 * 1024
        read_f = self.read  # loop optimization
        buf = read_f(buf_size)

        while buf:
            lines += buf.count('\n')
            if not buf.endswith('\n'):
                lines += 1
            buf = read_f(buf_size)

        self.nlines = lines
        self._fd.seek(0)

    def __getattr__(self, name):
        if hasattr(self._fd, name):
            return getattr(self._fd, name)
        else:
            raise AttributeError(f"invalid key {name}")

    def __getstate__(self):
        # Copy the object's state from self.__dict__ which contains
        # all our instance attributes. Always use the dict.copy()
        # method to avoid modifying the original state.
        log.info(f"saving file: {self._path} loc:{self.loc} state")
        state = self.__dict__.copy()
        # Remove the unpickable entries.
        del state['_fd']
        return state

    def __setstate__(self, state):
        # Restore instance attributes (i.e., _path and nlines ...).
        self.__dict__.update(state)
        # Restore the previously opened file's state.
        log.info(f"restoring file: {self._path} loc:{self.loc} state")
        fd = open(self._path, self.mode)

        # set the file to the prev location.
        fd.seek(self.loc)
        self._fd = fd

    def __len__(self):
        self.open()
        return self.nlines

    def __str__(self):
        return f"File(path:{self._path}, nlines: {self.nlines}, lineno:" \
               f"{self.lineno}, mode:{self.mode})"


class STATUS(Enum):
    """
    Each Scan task has the following states:
    - Scheduled: the default state set when its created.
    - Running: Set after the agent has confirmed the task has started
    executing.
    - Interrupted: Set when the task is aborted by agent, or the server has
    been halted.
    - Downloading: Set when the agent notifies its ready to sent the report.
    - Completed: Set only after the report has been received successfully
    """
    SCHEDULED = 1
    RUNNING = 2
    INTERRUPTED = 3
    DOWNLOADING = 4
    COMPLETED = 5


class Task:
    """
    Representation of a scan task.
    A scan task is sent to an agent with a target and, scan options.
    Each task has the following states:
    - Scheduled: the default state set when its created.
    - Running: Set after the agent has confirmed the task has started
    executing.
    - Interrupted: Set when the task is aborted by agent, or the server has
    been halted.
    - Downloading: Set when the agent notifies its ready to sent the report.
    - Completed: Set only after the report has been received successfully.
    """

    def __init__(self, stage_name, options, target):
        """
        :param stage_name:
        :param options:
        :param target:
        :type stage_name: `str`
        :type options: `str`
        :type target: `str`
        """
        self.stage_name = stage_name
        self.options = options
        self.target = target
        self.status = STATUS.SCHEDULED

    def update(self, status):
        assert isinstance(status, STATUS)
        self.status = status

    def as_tuple(self):
        """
        returns a tuple with the target and scan options.
        :return: tuple options, target
        :rtype tuple:
        """
        return self.options, self.target


class Stage:

    def __init__(self, stage_name, targets_path, options, outdir):
        assert targets_path, "Invalid targets file Name"
        assert stage_name, "Invalid stage Name"
        self.targets_path = targets_path
        self.name = stage_name
        self.targets = File(self.targets_path)
        self.options = options
        self.reports_path = outdir
        self.ftargets = 0

    def next_task(self):
        target = self.targets.readline()
        if target:
            return Task(self.name, self.options, target)
        else:
            return None

    def inc_finished(self):
        self.ftargets += 1

    def process_results(self):
        """
        Meant to be overwritten, like for example stages like ping sweep aka
        discovery.
        """
        pass

    @property
    def isfinished(self):
        if self.targets.nlines == self.ftargets:
            return True
        else:
            return False

    def close(self):
        self.targets.close()

    def as_tuple(self):
        return self.name, self.targets.nlines, self.targets.lineno, \
               self.ftargets


class DiscoveryStage(Stage):

    def __init__(self, targets_path, options, outdir, ltargets_path):
        super().__init__("discovery", targets_path, options, outdir)
        self.ltargets_path = ltargets_path

    def process_results(self):
        results_parser = ReportsParser(self.reports_path, 'discovery-*.xml')
        live_queue = TargetOptimization(self.ltargets_path)
        live_queue.save(results_parser.hosts_up())


class Context:
    """
    Context is a thread safe proxy like class, responsible for all the
    execution flow and inherent logic.
    Acts as a proxy between the active stages and the `stage` implementation.
    """

    def __init__(self, options):
        self.stage_list = list(options.stage_list)
        self.cstage_name = None
        self.active_stages = {}
        self.reports_path = options.outdir
        self.active = {}
        self.pending = []
        self._lock = threading.Lock()

    def pop(self, agent):
        """
        Gets the next `Task` from the current Active Stage, if their are no
        pending `Tasks` to be executed.
        Pending tasks are tasks that are canceled or restored from a previous
        interrupted session.
        If a stage is finished (no more targets), the next stage will take
        another stage from the list until its finished!
        :param agent: str with ipaddress and port in ip:port format
        :return: A target to scan! `task`
        :rtype: `tuple`
        """
        with self._lock:
            task = None
            if len(self.pending) > 0:
                task = self.pending.pop(0)
            else:
                cstage = self.__cstage()
                if cstage:
                    task = cstage.next_task()
                    if not task:
                        # the only stage that needs to be finished
                        # to proceed is
                        # discovery as the other stages need the
                        # list of live hosts
                        if cstage.name != "discovery" or cstage.isfinished:
                            if cstage.isfinished:
                                cstage.process_results()
                                cstage.close()
                            cstage = self.__cstage(True)
                            if cstage:
                                task = cstage.next_task()

            # if we have a valid task save it in the active collection
            if task:
                self.active.update({agent: task})
                # the consumers only need scan related information...
                return task.as_tuple()

    def _update_task_status(self, agent, status):
        """
        Internal method updates  a task of a given stage status, its also
        responsible for managing the interrupted tasks.
        :param agent: str with ipaddress and port in ip:port format
        :param status: `STATUS` value to change.
        """
        with self._lock:
            task, tstage = self.__find_task_stage(agent)
            if task and tstage:
                task.update(status)
                if status == STATUS.COMPLETED:
                    tstage.inc_finished()
                if status == status.INTERRUPTED:
                    log.info(f"Scan of {task.target} running on {agent} was "
                             f"interrupted")
                    self.pending.append(task)
                    del self.active[agent]
            else:
                log.debug(f"One of this is none! {task}, {tstage}")

    def completed(self, agent):
        self._update_task_status(agent, STATUS.COMPLETED)

    def downloading(self, agent):
        self._update_task_status(agent, STATUS.DOWNLOADING)

    def interrupted(self, agent):
        self._update_task_status(agent, STATUS.INTERRUPTED)

    def running(self, agent):
        self._update_task_status(agent, STATUS.RUNNING)

    def get_report(self, file_name):
        """
        :param file_name: name of the file sent by the agent.
        :return: file descriptor to save the scan report.
        """
        try:
            report_file = open(os.path.join(self.reports_path, file_name),
                               "wb")
            return report_file
        except Exception as ex:
            log.error(f"Unable to open report for {file_name}")
            log.error(f"{ex}")
            return None

    def __cstage(self, force_next=False):
        """
        :param force_next: if True wil force the stage to advance one step
        defaults to False
        :type force_next: `bool`
        :return: An instance of `stage`
        :rtype: `stage`
        """
        try:
            if not self.cstage_name or force_next:
                stage = self.stage_list.pop(0)
                self.active_stages[stage.name] = stage
                self.cstage_name = stage.name

            return self.active_stages[self.cstage_name]
        except IndexError:
            log.error("Stage list is empty !")
            return None

    def __find_task_stage(self, agent):
        """
        :param agent: str with ipaddress and port in ip:port format
        :return: tuple `Task` and `Stage` that created that task
        :rtype: `tuple`
        """
        tstage = None
        task = self.active.get(agent, None)
        if task:
            tstage = self.active_stages.get(task.stage_name, None)
        return task, tstage

    @classmethod
    def create(cls, options):
        """
        :param options: instance of `ServerConfig`
        :type options: ´ServerConfig´
        :return: instance of `Context`
        :rtype: ´Context`
        """
        rpath = options.resume_path
        if os.path.isfile(rpath) and os.stat(rpath).st_size > 0:
            log.info("Found resume file, loading...!")
            with open(options.resume_path, 'rb') as rfile:
                # i had to make this to make this testable with mocks!
                # load with file didn't work, some how!
                data = rfile.read()
                ctx = pickle.loads(data)
                return ctx
        else:
            return cls(options)

    def __getstate__(self):
        with self._lock:
            log.info("saving context state")
            state = self.__dict__.copy()
            for task in state['active'].values():
                task.update(STATUS.INTERRUPTED)
                state['pending'].append(task)

            # close file descriptors on all active stages
            for active_stage in state['active_stages'].values():
                active_stage.close()

            state['active'] = {}
            # Remove the unpickable entries.
            del state['_lock']
            return state

    def __setstate__(self, state):
        # restore the previous state, needed due to the existence of non
        # serializable objects
        self.__dict__.update(state)
        log.info("Restoring context state")
        self._lock = threading.Lock()
