#!/usr/bin/env python3
# encoding: utf-8

"""
scanner.py
scanner runtime models
"""

import hashlib
import os
import pickle
import threading
import itertools
from enum import Enum
from dscan import log
from dscan.models.parsers import ReportsParser, TargetOptimization
from dscan.models.structures import Status, Report
from dscan.out import Display
from libnmap.process import NmapProcess


class Config:
    """
        Runtime configurations
    """
    SSL_CERTS = (
        'certs', 'sslcert', 'sslkey', 'ciphers', 'cert-hostname'
    )

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
        self.wspace = options.name
        self.port = options.p
        self.outdir = os.path.join(options.name, config.get(
            *self.BASE))
        os.makedirs(self.outdir, exist_ok=True)
        self.config = None
        if options.cmd == 'srv':
            self.config = ServerConfig(config, options, self.outdir)
            self.sslkey = self.get_work_path(config.get(*self.SSL_CERTS[0:3:2]))
            assert os.path.isfile(
                self.sslkey), "Certificate Private key not found"
            self.ciphers = config.get(*self.SSL_CERTS[0:4:3])
        else:
            self.host = options.s
        # set cert properties

        self.sslcert = self.get_work_path(config.get(*self.SSL_CERTS[0:2:1]))
        self.srv_hostname = config.get(*self.SSL_CERTS[0:5:4])

        assert os.path.isfile(self.sslcert), "Certificate file not found"

        digest: hashlib.sha512 = hashlib.sha512()
        try:
            with open(self.sslcert, 'rt') as cert:
                digest.update(cert.read().strip().encode("utf-8"))
                self.secret_key = digest.hexdigest().encode("utf-8")
        except OSError as ex:
            log.error(f"failed to open cert file {ex}")
            raise ex

    def get_work_path(self, path):
        return os.path.join(self.wspace, path)

    def __getattr__(self, name):
        if hasattr(self.config, name):
            return getattr(self.config, name)
        else:
            raise AttributeError(f"invalid key {name}")


class ServerConfig:
    """
    Server configuration parser.
    """
    SERVER = (
        'server', 'stats', 'targets', 'live-targets', 'trace',
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
        self.rundir = os.path.join(
            options.name, config.get(*self.SERVER[0:2:1]))
        self.queue_path = os.path.join(
            options.name, config.get(*self.SERVER[0:3:2]))
        self.ltargets_path = os.path.join(
            options.name, config.get(*self.SERVER[0:4:3]))
        self.resume_path = os.path.join(
            options.name, config.get(*self.SERVER[0:5:4]))
        self.host = options.b
        os.makedirs(self.rundir, exist_ok=True)
        # init scan stages !
        self.__create_stages(dict(config.items('nmap-scan')))

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
        :type: `list` of `str`
        """
        assert targets, "Empty target list"
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


class File:
    """
    Creates a stateful file object
    allows file to restore its previous state.
    """

    def __init__(self, path):
        """
        :param path: string of path to the file to open.
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
        Check if the file is emtpy.

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
            proxy call to `os.path.isfile`.

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
        fd = None
        # if the loc is 0 then we have an uninitialized stage
        # that depends on unfinished stage, will be opened when the first
        # time a target is pulled.
        if self.loc != 0 and self.exists():
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
        :param stage_name: stage name
        :param options: scan options.
        :param target: target ip address.
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
        return self.stage_name, self.status.name, self.target, \
            self.options

    def __str__(self):
        return f"{self.stage_name}, {self.status.name}, {self.target}" \
               f"{self.options}"


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
        """
        Get next target from the file.

        :return: Task.
        :rtype: `Task`
        """
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
        """
        Returns True if the number of lines is equal to the number of
            finished targets.

        :return: bool
        :rtype: `bool`
        """
        if self.targets.nlines == self.ftargets:
            return True
        else:
            return False

    @property
    def percentage(self):
        """
        Calculates the completion of this stage.

        :return: float of of the % completion.
        :rtype: `float`
        """
        if self.ftargets > 0:
            return float(self.ftargets) / float(self.targets.nlines) * 100
        else:
            return float(0)

    def as_tuple(self):
        """
        Returns the information as tuple, nlines, finished targets and %,
        used by Display to print scanner status.

        :return: tuple of strings.
        :rtype: `tuple` of `str`.
        """
        return self.name, self.targets.nlines, self.ftargets, \
            f"{self.percentage:.2f}%"

    def close(self):
        self.targets.close()


class DiscoveryStage(Stage):

    def __init__(self, targets_path, options, outdir, ltargets_path):
        super().__init__("discovery", targets_path, options, outdir)
        self.ltargets_path = ltargets_path

    def process_results(self):
        """
        When this stage is finished the `Context` will call this method to
        create a list of live targets.
        """
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
        self.nstages = len(self.stage_list)
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
        another stage from the list until its finished.

        :param agent:
            str with ipaddress and port in ip:port format, this allows the
            server to manage multiple agents in one host.
            to run multiple clients at once.
        :return: A target to scan! `task`
        :rtype: `tuple`
        """
        with self._lock:
            task = None
            if agent in self.active:
                # This exists to make shore we don't lose targets.
                # this would be better if we knew how many tries a target
                # had faced. TODO
                log.info(f"Agent {agent} is requesting a new task with a "
                         f"task in execution sending it again!")
                task = self.active.get(agent)
                task.update(STATUS.SCHEDULED)
                return task.as_tuple()[2:]

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
                return task.as_tuple()[2:]

    def completed(self, agent):
        """
        Marks a agent task as complete.

        :param agent: ip:port of agent
        :type agent: `str`
        """
        self._update_task_status(agent, STATUS.COMPLETED)

    def downloading(self, agent):
        """
        Marks a agent task as Downloading, notifying that the report
        download has started.

        :param agent: ip:port of agent
        :type agent: `str`
        """
        self._update_task_status(agent, STATUS.DOWNLOADING)

    def interrupted(self, agent):
        """
        Marks a task as interrupted, when agent disconnects for example.

        :param agent: ip:port of agent
        :type agent: `str`
        """
        self._update_task_status(agent, STATUS.INTERRUPTED)

    def running(self, agent):
        """
        After the server sends a target the agent notifies the task has
        started.

        :param agent: ip:port of agent
        :type agent: `str`
        """
        self._update_task_status(agent, STATUS.RUNNING)

    def get_report(self, agent, file_name):
        """
        :param agent: str with ipaddress and port in ip:port format
        :type agent: `str`
        :param file_name: name of the file sent by the agent.
        :type file_name: `str`
        :return: file descriptor to save the scan report.
        """
        try:
            _, tstage = self.__find_task_stage(agent)
            file_name = f"{tstage.name}-{file_name}"
            report_file = open(os.path.join(self.reports_path, file_name),
                               "wb")
            return report_file
        except Exception as ex:
            log.error(f"Unable to open report for {file_name}")
            log.error(f"{ex}")
            return None

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
                    # clean the completed task
                    del self.active[agent]
                if status == status.INTERRUPTED:
                    log.info(f"Scan of {task.target} running on {agent} was "
                             f"interrupted")
                    self.pending.append(task)
                    del self.active[agent]
            else:
                log.debug(f"Agent {agent} is trying to update {status} on "
                          f"non existing task")

    def __cstage(self, force_next=False):
        """
        :param force_next: if True wil force the stage to advance one step
        defaults to False.
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

    def tasks_status(self):
        """
        :return: list of tuple of active task's status.
        :rtype: `list` of `tuple`s
        """
        data = []
        for agent, task in self.active.items():
            data.append((agent, *task.as_tuple()[:3]))
        return data

    def active_stages_status(self):
        """
        :return: list of tuples with active stages status.
        :rtype: `list` of `tuples`
        """
        data = []
        for stage in self.active_stages.values():
            data.append(stage.as_tuple())
        return data

    @property
    def is_finished(self):
        """
        :return: bool iterates the active stages and collects all the
            `finished` properties, returns `True` if all of them are true.
        """
        status = [status.isfinished for status in self.active_stages.values()]
        return all(status) and len(status) == self.nstages

    def ctx_status(self):
        stage_comp = float(0)
        for stage in self.active_stages.values():
            stage_comp += stage.percentage
        return [(self.nstages, len(self.pending), "{:.2f}%"
                 .format((stage_comp / float(self.nstages * 100) * 100)))]

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


class ScanProcess:
    """
    Used by the agent (client side), its a proxy class
    to provide an interface to interact with `libnmap` responsible
    for the actual execution.
    Its implementation allows handling, duplicate file names, with numeric
    prefix, as well as keeping status on the execution process.
    """
    TASK_HEADERS = [
        "Target", "Nª completed Scans", "Status"
    ]

    def __init__(self, output):
        """
        wrapper around `libnmap` scan execution
        :param output: str path to save the reports
        """
        self.output = output
        # current target aka ctarget is a tuple (target, options).
        self.ctarget = None
        # number of successful scans finished
        self.number_scans = 0
        self.display = Display()
        self.status = None

    def __inc(self):
        """
        increments the number_scans.
        """
        self.number_scans += 1

    def report_name(self, extension):
        """
        Checks if a report with the current target.extension exists,
        and prepends a number if it does.

        :param extension: xml, nmap.
        :return: path str path and filename, the filename will be prefixed,
            by a number if the base+extension already exists in the outdir.
        :rtype: `str`
        """
        fname = self.ctarget[0].replace('/', '-')
        path = os.path.join(self.output, f"{fname}"
                                         f".{extension}")
        exists = os.path.isfile(path)
        prefix = itertools.count()
        while exists:
            n = next(prefix)
            path = os.path.join(self.output, f"{n}-{fname}"
                                             f".{extension}")
            exists = os.path.isfile(path)
        return path

    def run(self, target, options, callback):
        """
        Executes the scan on a given target.

        :param target:
        :param options:
        :param callback: callback function to report status to the server.
        :return: report object
        :rtype: `dscan.models.structures.Report`
        """
        self.ctarget = (target, options)
        nmap_proc = None
        try:
            options = " ".join([options, f"-oN {self.report_name('nmap')}"])
            nmap_proc = NmapProcess(targets=target, options=options,
                                    safe_mode=False,
                                    event_callback=self.show_status)

            log.info("Nmap scan started Sending success status")
            callback(Status.SUCCESS)
            rc = nmap_proc.run()
            if rc == 0:
                # after finished encode and hash the contents for transfer.
                self.__inc()
                data = nmap_proc.stdout.encode("utf-8")
                report_file = self.report_name("xml")
                with open(self.report_name("xml"), "wb") as rfile:
                    rfile.write(data)
                    rfile.flush()
                digest = hashlib.sha512(data).hexdigest()
                report = Report(len(data), os.path.basename(report_file),
                                digest)
                self.print(target, 100)
                return report
            else:
                callback(Status.FAILED)
                log.error(f"Nmap Scan failed {nmap_proc.stderr}")
        except Exception as ex:
            log.error(f"something went wrong {ex}")
            callback(Status.FAILED)
        finally:
            if nmap_proc:
                nmap_proc.stop()
                # orthodox fix NmapProcess is leaving subprocess streams open.
                subproc = getattr(nmap_proc, "_NmapProcess__nmap_proc")
                if subproc:
                    subproc.stdout.close()
                    subproc.stderr.close()

    def print(self, target, progress):
        self.display.print_table(self.TASK_HEADERS,
                                 [(target, self.number_scans,
                                   progress)], clear=True)

    def show_status(self, nmapscan=None):
        """
        :param nmapscan: takes `libnmap.process.NmapProcess` instance
            to display the current status of the scan.
        :type nmapscan: `libnmap.process.NmapProcess`
        """
        if nmapscan.is_running() and nmapscan.current_task:
            ntask = nmapscan.current_task
            self.display.print_table(self.TASK_HEADERS,
                                     [(self.ctarget[0], self.number_scans,
                                       ntask.progress)], clear=True)
