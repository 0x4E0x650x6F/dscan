#!/usr/bin/env python3
# encoding: utf-8

"""
scanner.py
scanner runtime models
"""
import os
import ipaddress
import hashlib


class ServerConfig:

    SERVER = (
        'server', 'stats', 'queue', 'trace',
    )

    SSL_CERTS = (
        'certs', 'sslcert', 'sslkey'
    )

    SCAN_CONF = 'nmap-scan'

    def __init__(self, config, options):
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
            print("failed to open cert file")

    def target_optimization(self, targets):
        assert len(targets) != 0, "Empty target list"
        if not os.path.isfile(self.resume_path):
            nets = []
            try:
                for target in targets:
                    nets.append(ipaddress.ip_network(target.strip()))
            except (TypeError, ValueError):
                print("Error optimizing targets")
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
        :type config: configparser.ConfigParser
        :param options: argument parser object with the user options
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
