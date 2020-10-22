#!/usr/bin/env python3
# encoding: utf-8

"""
scanner.py
scanner runtime models
"""
import os
import ipaddress
import hashlib
from dscan import log
from itertools import (takewhile, repeat)


class ServerConfig:
    SERVER = (
        'server', 'stats', 'queue', 'trace',
    )

    SSL_CERTS = (
        'certs', 'sslcert', 'sslkey'
    )

    SCAN_CONF = 'nmap-scan'

    def __init__(self, config, options):
        """
        :param config: configparser with the configuration
        :type config: `configparser.ConfigParser`
        :param options: argument parser `argparse.ArgumentParser`
        with the user options
        """
        self.rundir = os.path.join(
            options.name, config.get(*self.SERVER[0:2:1]))
        self.queue_path = os.path.join(
            options.name, config.get(*self.SERVER[0:3:2]))
        self.resume_path = os.path.join(
            options.name, config.get(*self.SERVER[0:4:3]))
        self.host = options.b
        os.makedirs(self.rundir, exist_ok=True)
        # init scan stages !
        self.scan_options = dict(config.items('nmap-scan'))
        # set cert properties
        self.sslcert = config.get(*self.SSL_CERTS[0:2:1])
        self.sslkey = config.get(*self.SSL_CERTS[0:3:2])
        digest: hashlib.sha512 = hashlib.sha512()
        try:
            with open(self.sslcert, 'rt') as cert:
                digest.update(cert.read().strip().encode("utf-8"))
                self.secret_key = digest.hexdigest().encode("utf-8")
        except OSError as ex:
            log.error(f"failed to open cert file {ex}")

    def target_optimization(self, targets):
        """
        Takes a list of ip Addresses and groups all sequential ips in
        cidr notation.
        :param targets: `list` of `str`
        """
        assert len(targets) != 0, "Empty target list"
        if not os.path.isfile(self.resume_path):
            nets = []
            try:
                for target in targets:
                    nets.append(ipaddress.ip_network(target.strip()))
            except (TypeError, ValueError):
                log.error("Error optimizing targets")
                pass
            with open(self.queue_path, 'wt') as qfile:
                for net in ipaddress.collapse_addresses(nets):
                    if net.prefixlen < 24:
                        subs = map(lambda n: "%s\n" % n.with_prefixlen,
                                   net.subnets(new_prefix=24))
                        qfile.writelines(subs)
                    else:
                        qfile.write("%s\n" % net.with_prefixlen)


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
        self.outdir = os.path.join(options.name, config.get(*self.BASE))
        os.makedirs(self.outdir, exist_ok=True)
        self.config = None
        if options.cmd == 'srv':
            self.config = ServerConfig(config, options)
        else:
            self.host = options.s

    def __getattr__(self, name):
        if hasattr(self.config, name):
            return getattr(self.config, name)
        else:
            raise AttributeError("invalid key %s" % name)


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
        self._path = os.path.normpath(path)
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
        self.lineno += 1
        line = self._fd.readline()
        self.loc = self._fd.tell()
        if not line:
            return None
        if line.endswith('\n'):
            line = line[:-1]
        return self.loc, line

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
            raise AttributeError("invalid key %s" % name)

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
