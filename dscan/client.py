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
import threading
import time
from socket import socket
from socket import AF_INET
from socket import SOCK_STREAM
from socket import timeout
import ssl
from dscan import log
from dscan.models.structures import Structure, Operations
from dscan.models.structures import Auth
from dscan.models.structures import Ready
from dscan.models.structures import Status
from dscan.models.scanner import ScanProcess
from string import ascii_uppercase


class Agent:
    """
    Agent client implementation.
    """
    def __init__(self, config):
        """
        :param config: `dscan.models.scanner.Config`
        instance with the runtime configurations.
        """
        self.connected = False
        self.config = config
        self.con_retries = 0
        srv_hostname = config.srv_hostname
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.load_verify_locations(self.config.sslcert)
        self.socket = ssl_context.wrap_socket(socket(AF_INET, SOCK_STREAM),
                                              server_side=False,
                                              server_hostname=srv_hostname)
        self._terminate = threading.Event()
        self.scan = ScanProcess(self.config.outdir)

    def is_connected(self):
        """
        Check if the agent is still connected and not yet finished.

        :return: `True` if the client has disconnected or the terminate event
            has been triggered, else False.
        :rtype: `bool`
        """
        return self.con_retries < 3 and not self._terminate.is_set()

    def start(self):
        """
        Start the client connects to the server and authenticates.

        :return: True if was able to connect and authentication was
            successful else False.
        :rtype: `bool`
        """
        self.con_retries = 0
        # while the connection retry is under 3 tries
        # everytime the connection is interrupted the client
        # tries to connect authenticates and requests a target!
        while self.is_connected():
            try:
                self.socket.connect((self.config.host, self.config.port))
                self.connected = True
                if not self.do_auth():
                    # return out if auth was not successfully
                    self.connected = False
                    return
                # reset the counter if connection was successful.
                self.con_retries = 0
                # if authentication was successful request a target to scan.
                self.do_ready()
            except (timeout, ConnectionError, ValueError) as e:
                self.con_retries += 1
                log.error(f"Connection Timeout - {e}")
                log.error(f"Attempt - {self.con_retries} "
                          f"to establish connection")
                self.connected = False
                self.socket.close()
            finally:
                self.socket.close()

    def shutdown(self):
        """
        Set the terminate event On, to shutdown the agent.
        """
        self._terminate.set()

    def do_auth(self):
        """
        Initiate the authentication.

        :return: True if the status code of the last operation is
            `dscan.models.structures.Status.SUCCESS` False otherwise.
        :rtype: `bool`
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

            if cmd.op_code == Operations.STATUS and cmd.status == Status.FINISHED:
                log.info("received a Finished status, Terminating!")
                self.con_retries = 3
                return

            if cmd.op_code == Operations.STATUS and cmd.status == Status.UNFINISHED:
                log.info("received a Unfinished will retry later!")
                time.sleep(5)
                log.info("retrying.. Target request!")
                continue

            log.info(f"Launching scan on {cmd}")
            report = self.scan.run(cmd.target.decode("utf-8"),
                                   cmd.options.decode("utf-8"),
                                   self.send_status)
            if report:
                self.socket.sendall(report.pack())
                if self.__send_report(report):
                    log.info("Report Transfer was successful")
                else:
                    log.error("Report Transfer was unsuccessful")
            else:
                self.send_status(Status.FAILED.value)

    def send_status(self, status):
        """
        :param status: int of a valid `dscan.models.structures.Status`
        """
        self.socket.sendall(struct.pack("<B", status))

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
            log.error("Operation unsuccessful disconnecting...")
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
