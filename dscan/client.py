#!/usr/bin/env python3
# encoding: utf-8

"""
client.py
client side responsible for the managing clients and scan execution flow.
"""
import os
import hmac
import struct
import random
from socket import socket
from socket import AF_INET
from socket import SOCK_STREAM
from socket import timeout
import ssl
from dscan import log
from dscan.models.structures import Structure
from dscan.models.structures import Auth
from dscan.models.structures import Ready
from dscan.models.structures import Status
from string import ascii_uppercase


class Scanner:
    def __init__(self, output):
        """
        wrapper around `libnmap` scan execution
        :param output: str path to save the reports
        """
        self.output = output

    def run(self, target, options):
        """
        Executes the scan on a given target
        :param target:
        :param options:
        :return: report object
        :rtype: `dscan.models.structures.Report`
        """
        pass


class Agent:
    """
    Dscan client.
    """
    def __init__(self, config):
        """
        Agent client implementation
        :param config: `dscan.models.scanner.Config` instance with the
        runtime configurations.
        """
        self.connected = False
        self.config = config
        srv_hostname = config.srv_hostname
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.load_verify_locations(self.config.sslcert)
        self.socket = ssl_context.wrap_socket(socket(AF_INET, SOCK_STREAM),
                                              server_side=False,
                                              server_hostname=srv_hostname)
        self.scan = Scanner(self.config.outdir)

    def connect(self):
        """
        Start the client connects to the server and authenticates.
        :returns:
            True if was able to connect and authentication was successful else
            False
        :rtype:
            `bool`
        """
        con_retries = 0
        # while the connection retry is under 3 tries
        # everytime the connection is interrupted the client
        # tries to connect authenticates and requests a target!
        while con_retries < 3:
            try:
                self.socket.connect((self.config.host, self.config.port))
                self.connected = True
                if not self.do_auth():
                    # return out if auth was not successfully
                    self.connected = False
                    return
                # reset the counter if connection was successful.
                con_retries = 0
                # if authentication was successful request a target to scan.
                self.do_ready()
            except (timeout, ConnectionError) as e:
                con_retries += 1
                log.info(f"Connection Timeout - {e}")
                log.info(f"Attempt - {con_retries} to establish connection")
                self.connected = False
            finally:
                self.socket.close()

    def do_auth(self):
        """
        Initiate the authentication
        """
        log.info("Initiating authentication")
        opr = Structure.create(self.socket)
        if not opr:
            # unable to get message
            return False

        hmac_hash = hmac.new(self.config.secret_key, opr.data,
                             'sha512')
        digest = hmac_hash.hexdigest().encode("utf-8")

        self.socket.sendall(Auth(digest).pack())
        status_result = self.__check_status()
        if status_result:
            return status_result

    def do_ready(self):
        """
        This is recursive method and is responsible for, notifying the server
        is ready to execute a new scan, launch the scan and save the report.
        Until the server returns no target to scan.
        """
        alias = "".join(random.choice(ascii_uppercase) for _ in range(6))
        while self.connected:
            log.info("Requesting target...")
            self.socket.sendall(Ready(os.getuid(), alias).pack())
            cmd = Structure.create(self.socket)
            if not cmd:
                # unable to get message
                log.info("Unable to receive command from server")
                return

            log.info(f"Launching scan on {cmd}")
            report = self.scan.run(cmd.target, cmd.options)
            self.socket.sendall(report.pack())

            if self.__send_report(report):
                log.info("Report Transfer was successful")
            else:
                log.info("Report Transfer was unsuccessful")

    def __check_status(self):
        """
        Receives the status code from the server, and check the code value,
        see `dscan.models.structures.Status` for other valid status values.
        :return: True if the status code of the last operation is
        `dscan.models.structures.Status.SUCCESS` False otherwise.
        :rtype: `bool`
        """
        op_size = struct.calcsize("<B")
        op_bytes = self.socket.recv(op_size)
        if len(op_bytes) == 0:
            log.info("disconnected!")
            self.connected = False
            return False

        status, = struct.unpack("<B", op_bytes)
        if status == Status.SUCCESS.value:
            log.info("Operation Successful ...")
            return True
        else:
            log.info("Operation unsuccessful disconnecting...")
            return False

    def __send_report(self, report, retry=0):
        """
        Transfer the report.
        :param report: report message.
        :type report: `dscan.models.structures.Report`
        :param retry: number of attempts
        :type retry: `int`
        :return: bool the result of last try.
        :rtype: `bool`
        """
        nbytes = 0
        with open(os.path.join(self.config.outdir,
                               report.filename.decode("utf-8")),
                  "rb") as rfile:
            while nbytes < report.filesize:
                data = rfile.read(1024)
                self.socket.sendall(data)
                nbytes = nbytes + len(data)
        result = self.__check_status()
        if not result and retry < 3:
            retry += 1
            log.info(f"Transfer  retry {retry}")
            return self.__send_report(report, retry)
        else:
            return result
