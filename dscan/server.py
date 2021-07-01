#!/usr/bin/env python3
# encoding: utf-8

"""
server.py
server side responsible for the managing clients and scan execution flow.
"""
import hashlib
import hmac
import ssl
import os
import socket
import struct
import threading
from socketserver import TCPServer
from socketserver import ThreadingMixIn
from socketserver import BaseRequestHandler

from dscan.models.scanner import Context
from dscan.models.structures import Auth, Status, ExitStatus
from dscan.models.structures import Command
from dscan.models.structures import Structure
from dscan import log


class DScanServer(ThreadingMixIn, TCPServer):
    """
    Foundation of the Server.
    Implements the shutdown with `threading.Event`, and ssl configurations.
    and injects `threading.Event` to the `RequestHandlerClass`
    """
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, options, **kwargs):
        self._terminate = threading.Event()
        self.options = options
        self.ctx = Context.create(options)
        super().__init__(*args, **kwargs)

    @property
    def secret_key(self):
        """
        :return: str secret key generated in the config based on the
            certificate
        """
        return self.options.secret_key

    def get_request(self) -> tuple:
        """
        Used to add ssl support.

        :return: returns a `ssl.wrap_socket`
        :rtype: ´ssl.wrap_socket´
        """
        # noinspection PyTupleAssignmentBalance
        client, addr = super().get_request()
        # TODO: protocol version is hardcoded!
        client_ssl = ssl.wrap_socket(client, keyfile=self.options.sslkey,
                                     certfile=self.options.sslcert,
                                     ssl_version=ssl.PROTOCOL_TLSv1_2,
                                     ca_certs=None,
                                     server_side=True,
                                     do_handshake_on_connect=True,
                                     suppress_ragged_eofs=True,
                                     ciphers=self.options.ciphers)
        return client_ssl, addr

    def finish_request(self, request, client_address) -> BaseRequestHandler:
        """
        Finish one request by instantiating RequestHandlerClass.

        :return: `RequestHandlerClass`
        :rtype: ´RequestHandlerClass´
        """
        return self.RequestHandlerClass(request, client_address,
                                        self, terminate_event=self._terminate,
                                        context=self.ctx)

    def shutdown(self):
        """
         An override to allow a local terminate event to be set!
        """
        self._terminate.set()
        super().shutdown()
        self.server_close()
        if not self.ctx.is_finished:
            self.options.save_context(self.ctx)


class AgentHandler(BaseRequestHandler):
    HEADER = "<B"
    """
    Created when an agent connects, holds all the agents available actions.
    Terminates when scan targets finishes or an agent disconnects.
    """
    def __init__(self, *args, terminate_event, context, **kwargs):
        self._terminate = terminate_event
        self.ctx = context
        self.msg = None
        self.authenticated = False
        self.connected = False
        super().__init__(*args, **kwargs)

    @property
    def agent(self):
        """
        string representation of a connection ip:port.

        :return: str format of agent name ip:port
        """
        return "{}:{}".format(*self.client_address)

    @property
    def is_connected(self):
        """
        Check if the client is still connected, the terminate event has not
        been set and all stages are finished or not.

        :return: True if the client has disconnected or
            the terminate event has been triggered, else False
        :rtype: `bool`
        """
        return self.connected and not self._terminate.is_set() \
            and not self.ctx.is_finished

    def dispatcher(self):
        """
        Command dispatcher all logic to decode and dispatch the call.
        """
        self.msg = Structure.create(self.request)
        if not self.msg:
            self.connected = False
            log.info("Disconnected!")
            # mark any running task as interrupted
            # so that other agent can take it later
            self.ctx.interrupted(self.agent)
            return

        command_name = f"do_{self.msg.op_code.name.lower()}"
        if not hasattr(self, command_name):
            self.send_status(Status.FAILED)  # invalid command
            return

        command = getattr(self, command_name)
        # the only command authorized for unauthenticated agents
        if command_name != "do_AUTH" and not self.authenticated:
            self.send_status(Status.UNAUTHORIZED)
            self.connected = False
            self.request.close()
            return
        # call the command !
        command()

    def handle(self):
        """
        First method to be called by `BaseRequestHandler`.
        responsible for initial call to authentication `do_auth`,
        and `dispatcher`, the connection is kept alive as long as agent is
        connected and their are targets to be delivered.
        """
        log.info(f"{self.client_address} connected!")
        self.connected = True
        try:
            while self.is_connected:
                try:
                    # start by requesting authentication
                    if not self.authenticated:
                        self.do_auth()

                    self.dispatcher()
                except (socket.timeout, ConnectionError) as e:
                    log.info(f"{self.client_address} Timeout - {e}")
                    self.connected = False
                    # mark any running task as interrupted
                    # so that other agent can take it later
                    self.ctx.interrupted(self.agent)

                # wait a bit, in case a shutdown was requested!
                self._terminate.wait(1.0)
        finally:
            if self.ctx.is_finished:
                log.info("All stages are finished sending terminate event.")
                self.server.shutdown()
            self.request.close()

    def do_auth(self):
        """
        Handles the agent's authentication.
        """
        log.info(f"{self.client_address} initialized Authentication")
        challenge = os.urandom(128)
        self.request.sendall(Auth(challenge).pack())
        # wait for the client response

        self.msg = Structure.create(self.request)
        if not self.msg:
            # something's wrong with the message!
            self.send_status(Status.FAILED)
            return

        hmac_hash = hmac.new(self.server.secret_key, challenge, 'sha512')
        digest = hmac_hash.hexdigest().encode("utf-8")

        if hmac.compare_digest(digest, self.msg.data):
            log.info("Authenticated Successfully")
            self.authenticated = True
            self.send_status(Status.SUCCESS)
        else:
            self.send_status(Status.UNAUTHORIZED)
            self.request.close()

    def do_ready(self):
        """
        After the authentication the agent notifies the server, that is
        ready to start scanning.
        This will handle the request and send a target to be scanned.
        """
        log.info("is Ready for targets")

        log.info(f"Agent is running with uid {self.msg.uid}")
        if self.msg.uid != 0:
            log.info("Waning! agent is not running as root "
                     "syn scans might abort not enough privileges!")

        target_data = self.ctx.pop(self.agent)
        if not target_data:
            if self.ctx.is_finished:
                log.info("Target is None and all stages are finished")
                # send empty command and terminate!
                cmd = Command("", "")
                self.request.sendall(cmd.pack())
                self.connected = False
            else:
                log.info("Waiting for a stage to finish")
                cmd = ExitStatus(Status.UNFINISHED)
                self.request.sendall(cmd.pack())
            return

        cmd = Command(*target_data)
        self.request.sendall(cmd.pack())
        status_bytes = self.request.recv(1)

        if len(status_bytes) == 0:
            self.connected = False
            log.info("Disconnected!")
            self.ctx.interrupted(self.agent)
            return

        status, = struct.unpack("<B", status_bytes)
        if status == Status.SUCCESS.value:
            log.info("Started scanning !")
            self.ctx.running(self.agent)
        else:
            log.error("Scan command returned Error")
            log.info("Server is Terminating connection!")
            self.connected = False
            self.ctx.interrupted(self.agent)

    def do_report(self):
        """
        When the scan the ends, the agent notifies the server that is ready
        to send the report.
        This method will handle the report transfer save the report in the
        reports directory and make the target as finished
        if the file hashes match.
        """
        log.info("Agent Reporting Complete Scan!")
        log.info(f"Filename {self.msg.filename} total file size "
                 f"{self.msg.filesize} file hash {self.msg.filehash}")

        file_size = self.msg.filesize
        nbytes = 0
        report = self.ctx.get_report(self.agent,
                                     self.msg.filename.decode("utf-8"))
        try:
            digest = hashlib.sha512()
            self.ctx.downloading(self.agent)
            while nbytes < file_size:
                data = self.request.recv(1024)
                report.write(data)
                digest.update(data)
                nbytes = nbytes + len(data)

            if not hmac.compare_digest(digest.hexdigest().encode("utf-8"),
                                       self.msg.filehash):
                log.error(f"Files are not equal! {digest.hexdigest()}")
                self.send_status(Status.FAILED)
            else:
                log.info("files are equal!")
                self.ctx.completed(self.agent)
                self.send_status(Status.SUCCESS)
        finally:
            if report:
                report.flush()
                report.close()

    def send_status(self, code):
        """
        Sends a status code to the server.

        :param code:
        :type code: `dscan.models.structures.Status`
        """
        log.info(f"Sending status code {code}")
        response = struct.pack("<B", code)
        self.request.sendall(response)
