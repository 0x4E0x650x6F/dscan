#!/usr/bin/env python3
# encoding: utf-8

import os
import pickle
import unittest
from argparse import Namespace
from configparser import ConfigParser, ExtendedInterpolation
from unittest.mock import mock_open, patch

from dscan.models.scanner import Config, Context


class TestSettings(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.targets = [
            "192.168.10.0",
            "192.168.10.1",
            "192.168.10.2",
            "192.168.10.3",
            "192.168.10.4",
            "192.168.10.5",
            "192.168.10.6",
            "192.168.10.7",
            "192.168.10.8",
            "192.168.10.9",
            "192.168.10.10",
            "192.168.10.11",
            "192.168.10.12",
            "192.168.10.13",
            "192.168.10.14",
            "192.168.10.15",
            "192.168.12.0/24",
            "10.16.0.0/16"
        ]
        cls.expected_nets = [
            '10.16.0.0/24\n', '10.16.1.0/24\n', '10.16.2.0/24\n',
            '10.16.3.0/24\n', '10.16.4.0/24\n', '10.16.5.0/24\n',
            '10.16.6.0/24\n', '10.16.7.0/24\n', '10.16.8.0/24\n',
            '10.16.9.0/24\n', '10.16.10.0/24\n', '10.16.11.0/24\n',
            '10.16.12.0/24\n', '10.16.13.0/24\n', '10.16.14.0/24\n',
            '10.16.15.0/24\n', '10.16.16.0/24\n', '10.16.17.0/24\n',
            '10.16.18.0/24\n', '10.16.19.0/24\n', '10.16.20.0/24\n',
            '10.16.21.0/24\n', '10.16.22.0/24\n', '10.16.23.0/24\n',
            '10.16.24.0/24\n', '10.16.25.0/24\n', '10.16.26.0/24\n',
            '10.16.27.0/24\n', '10.16.28.0/24\n', '10.16.29.0/24\n',
            '10.16.30.0/24\n', '10.16.31.0/24\n', '10.16.32.0/24\n',
            '10.16.33.0/24\n', '10.16.34.0/24\n', '10.16.35.0/24\n',
            '10.16.36.0/24\n', '10.16.37.0/24\n', '10.16.38.0/24\n',
            '10.16.39.0/24\n', '10.16.40.0/24\n', '10.16.41.0/24\n',
            '10.16.42.0/24\n', '10.16.43.0/24\n', '10.16.44.0/24\n',
            '10.16.45.0/24\n', '10.16.46.0/24\n', '10.16.47.0/24\n',
            '10.16.48.0/24\n', '10.16.49.0/24\n', '10.16.50.0/24\n',
            '10.16.51.0/24\n', '10.16.52.0/24\n', '10.16.53.0/24\n',
            '10.16.54.0/24\n', '10.16.55.0/24\n', '10.16.56.0/24\n',
            '10.16.57.0/24\n', '10.16.58.0/24\n', '10.16.59.0/24\n',
            '10.16.60.0/24\n', '10.16.61.0/24\n', '10.16.62.0/24\n',
            '10.16.63.0/24\n', '10.16.64.0/24\n', '10.16.65.0/24\n',
            '10.16.66.0/24\n', '10.16.67.0/24\n', '10.16.68.0/24\n',
            '10.16.69.0/24\n', '10.16.70.0/24\n', '10.16.71.0/24\n',
            '10.16.72.0/24\n', '10.16.73.0/24\n', '10.16.74.0/24\n',
            '10.16.75.0/24\n', '10.16.76.0/24\n', '10.16.77.0/24\n',
            '10.16.78.0/24\n', '10.16.79.0/24\n', '10.16.80.0/24\n',
            '10.16.81.0/24\n', '10.16.82.0/24\n', '10.16.83.0/24\n',
            '10.16.84.0/24\n', '10.16.85.0/24\n', '10.16.86.0/24\n',
            '10.16.87.0/24\n', '10.16.88.0/24\n', '10.16.89.0/24\n',
            '10.16.90.0/24\n', '10.16.91.0/24\n', '10.16.92.0/24\n',
            '10.16.93.0/24\n', '10.16.94.0/24\n', '10.16.95.0/24\n',
            '10.16.96.0/24\n', '10.16.97.0/24\n', '10.16.98.0/24\n',
            '10.16.99.0/24\n', '10.16.100.0/24\n', '10.16.101.0/24\n',
            '10.16.102.0/24\n', '10.16.103.0/24\n', '10.16.104.0/24\n',
            '10.16.105.0/24\n', '10.16.106.0/24\n', '10.16.107.0/24\n',
            '10.16.108.0/24\n', '10.16.109.0/24\n', '10.16.110.0/24\n',
            '10.16.111.0/24\n', '10.16.112.0/24\n', '10.16.113.0/24\n',
            '10.16.114.0/24\n', '10.16.115.0/24\n', '10.16.116.0/24\n',
            '10.16.117.0/24\n', '10.16.118.0/24\n', '10.16.119.0/24\n',
            '10.16.120.0/24\n', '10.16.121.0/24\n', '10.16.122.0/24\n',
            '10.16.123.0/24\n', '10.16.124.0/24\n', '10.16.125.0/24\n',
            '10.16.126.0/24\n', '10.16.127.0/24\n', '10.16.128.0/24\n',
            '10.16.129.0/24\n', '10.16.130.0/24\n', '10.16.131.0/24\n',
            '10.16.132.0/24\n', '10.16.133.0/24\n', '10.16.134.0/24\n',
            '10.16.135.0/24\n', '10.16.136.0/24\n', '10.16.137.0/24\n',
            '10.16.138.0/24\n', '10.16.139.0/24\n', '10.16.140.0/24\n',
            '10.16.141.0/24\n', '10.16.142.0/24\n', '10.16.143.0/24\n',
            '10.16.144.0/24\n', '10.16.145.0/24\n', '10.16.146.0/24\n',
            '10.16.147.0/24\n', '10.16.148.0/24\n', '10.16.149.0/24\n',
            '10.16.150.0/24\n', '10.16.151.0/24\n', '10.16.152.0/24\n',
            '10.16.153.0/24\n', '10.16.154.0/24\n', '10.16.155.0/24\n',
            '10.16.156.0/24\n', '10.16.157.0/24\n', '10.16.158.0/24\n',
            '10.16.159.0/24\n', '10.16.160.0/24\n', '10.16.161.0/24\n',
            '10.16.162.0/24\n', '10.16.163.0/24\n', '10.16.164.0/24\n',
            '10.16.165.0/24\n', '10.16.166.0/24\n', '10.16.167.0/24\n',
            '10.16.168.0/24\n', '10.16.169.0/24\n', '10.16.170.0/24\n',
            '10.16.171.0/24\n', '10.16.172.0/24\n', '10.16.173.0/24\n',
            '10.16.174.0/24\n', '10.16.175.0/24\n', '10.16.176.0/24\n',
            '10.16.177.0/24\n', '10.16.178.0/24\n', '10.16.179.0/24\n',
            '10.16.180.0/24\n', '10.16.181.0/24\n', '10.16.182.0/24\n',
            '10.16.183.0/24\n', '10.16.184.0/24\n', '10.16.185.0/24\n',
            '10.16.186.0/24\n', '10.16.187.0/24\n', '10.16.188.0/24\n',
            '10.16.189.0/24\n', '10.16.190.0/24\n', '10.16.191.0/24\n',
            '10.16.192.0/24\n', '10.16.193.0/24\n', '10.16.194.0/24\n',
            '10.16.195.0/24\n', '10.16.196.0/24\n', '10.16.197.0/24\n',
            '10.16.198.0/24\n', '10.16.199.0/24\n', '10.16.200.0/24\n',
            '10.16.201.0/24\n', '10.16.202.0/24\n', '10.16.203.0/24\n',
            '10.16.204.0/24\n', '10.16.205.0/24\n', '10.16.206.0/24\n',
            '10.16.207.0/24\n', '10.16.208.0/24\n', '10.16.209.0/24\n',
            '10.16.210.0/24\n', '10.16.211.0/24\n', '10.16.212.0/24\n',
            '10.16.213.0/24\n', '10.16.214.0/24\n', '10.16.215.0/24\n',
            '10.16.216.0/24\n', '10.16.217.0/24\n', '10.16.218.0/24\n',
            '10.16.219.0/24\n', '10.16.220.0/24\n', '10.16.221.0/24\n',
            '10.16.222.0/24\n', '10.16.223.0/24\n', '10.16.224.0/24\n',
            '10.16.225.0/24\n', '10.16.226.0/24\n', '10.16.227.0/24\n',
            '10.16.228.0/24\n', '10.16.229.0/24\n', '10.16.230.0/24\n',
            '10.16.231.0/24\n', '10.16.232.0/24\n', '10.16.233.0/24\n',
            '10.16.234.0/24\n', '10.16.235.0/24\n', '10.16.236.0/24\n',
            '10.16.237.0/24\n', '10.16.238.0/24\n', '10.16.239.0/24\n',
            '10.16.240.0/24\n', '10.16.241.0/24\n', '10.16.242.0/24\n',
            '10.16.243.0/24\n', '10.16.244.0/24\n', '10.16.245.0/24\n',
            '10.16.246.0/24\n', '10.16.247.0/24\n', '10.16.248.0/24\n',
            '10.16.249.0/24\n', '10.16.250.0/24\n', '10.16.251.0/24\n',
            '10.16.252.0/24\n', '10.16.253.0/24\n', '10.16.254.0/24\n',
            '10.16.255.0/24\n', '192.168.10.0/28\n', '192.168.12.0/24\n'
        ]
        cls.ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM" \
                      "-SHA256:ECDHE-RSA-AES256-GCM-SHA384:" \
                      "ECDHE-ECDSA-AES256-GCM-SHA384:" \
                      "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:" \
                      "kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:" \
                      "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:" \
                      "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:" \
                      "ECDHE-ECDSA-AES256-SHA384:" \
                      "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:" \
                      "DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:" \
                      "DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:" \
                      "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:" \
                      "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"

    def setUp(self) -> None:

        self.server_options = Namespace(name='data', b='127.0.0.1', p='2040',
                                        cmd='srv', targets='foofile')
        self.agent_options = Namespace(name='data', s='127.0.0.1', p='2040',
                                       cmd='agent')
        self.cfg = ConfigParser(interpolation=ExtendedInterpolation())
        self.data = open(os.path.join(os.path.dirname(__file__),
                                      'data/dscan.conf'))
        self.cfg.read_file(self.data)
        patcher = patch('os.makedirs')
        mos_isfile = patch('os.path.isfile')
        mos_isfile.return_value = True
        self.mock_makedirs = patcher.start()
        mos_isfile.start()
        self.config = Config(self.cfg, self.server_options)
        self.addCleanup(patcher.stop)
        self.addCleanup(mos_isfile.stop)

    def tearDown(self) -> None:
        self.data.close()

    def test_server(self):
        expect_disc = "-n -sn -PE -PP -PS 21,22,23,25,80,113,31339 -PA 80," \
                      "113,443,10042"
        expect_st1 = "-sT -n -PE -PP -PS 21,22,23,25,80,113,31339 -PA 80," \
                     "113,443,10042 -p 80,443,8080"
        expect_st2 = "-sT -n -PE -PP -PS 21,22,23,25,80,113,31339 -PA 80," \
                     "113,443,10042 -p 25,135,137,139,445,1433,3306,5432"
        expect_st3 = "-sT -n -PE -PP -PS 21,22,23,25,80,113,31339 -PA 80," \
                     "113,443,10042 -p 23,21,22,110,111,2049,3389"
        expect_st4 = "-sT -n -PE -PP -PS 21,22,23,25,80,113,31339 -PA 80," \
                     "113,443,10042 -p 0-20,24,26-79,81-109,112-134,136,138," \
                     "140-442,444," \
                     "446-1432,1434-2048,2050-3305,3307-3388,3390-5431," \
                     "5433-8079,8081-29999"
        expect_st5 = "-sT -n -PE -PP -PS 21,22,23,25,80,113,31339 -PA 80," \
                     "113,443,10042 -p 30000-65535"

        self.assertEqual('127.0.0.1', self.config.host)
        self.assertEqual('2040', self.config.port)
        self.assertEqual('data/run/targets.work', self.config.queue_path)
        self.assertEqual('data/run/live-targets.work',
                         self.config.ltargets_path)
        self.assertEqual('data/run/current.trace', self.config.resume_path)
        self.assertEqual('data/certfile.crt', self.config.sslcert)
        self.assertEqual('data/keyfile.key', self.config.sslkey)
        self.assertEqual(self.ciphers, self.config.ciphers)
        self.assertEqual(expect_disc, self.config.stage_list[0].options)
        self.assertEqual(expect_st1, self.config.stage_list[1].options)
        self.assertEqual(expect_st2, self.config.stage_list[2].options)
        self.assertEqual(expect_st3, self.config.stage_list[3].options)
        self.assertEqual(expect_st4, self.config.stage_list[4].options)
        self.assertEqual(expect_st5, self.config.stage_list[5].options)
        self.assertEqual(2, self.mock_makedirs.call_count)
        self.assertEqual('data/reports', self.config.outdir)
        self.mock_makedirs.assert_any_call('data/reports', exist_ok=True)
        self.mock_makedirs.assert_any_call('data/run', exist_ok=True)

    def test_address_optimization(self):
        with patch('builtins.open', mock_open()) as mopen:
            handle = mopen.return_value
            with patch('os.path.isfile') as misfile:
                misfile.return_value = False
                self.config.target_optimization(self.targets)
                mopen.assert_any_call('data/run/targets.work', "wt")
                self.assertEqual(handle.write.call_count, 2)
                handle.writelines.assert_called_once()
                handle.write.assert_any_call('192.168.10.0/28\n')
                handle.write.assert_any_call('192.168.12.0/24\n')

    def test_save_context(self):
        with patch('builtins.open', mock_open()) as mopen:
            handle = mopen.return_value
            ctx = Context(self.config)
            self.config.save_context(ctx)
            mopen.assert_any_call('data/run/current.trace', "wb")
            self.assertEqual(1, handle.write.call_count)
            handle.write.assert_any_call(pickle.dumps(ctx))

    def test_agent(self):
        with patch('os.makedirs') as mock_makedirs:
            agent_config = Config(self.cfg, self.agent_options)
            self.assertEqual('data/reports', agent_config.outdir)
            self.assertEqual('127.0.0.1', agent_config.host)
            self.assertEqual('2040', agent_config.port)
            self.assertEqual('data/certfile.crt', agent_config.sslcert)
            self.assertEqual('dscan', agent_config.srv_hostname)

            self.assertEqual(1, mock_makedirs.call_count)
            mock_makedirs.assert_any_call('data/reports', exist_ok=True)


if __name__ == '__main__':
    unittest.main()
