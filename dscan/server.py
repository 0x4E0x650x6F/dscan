#!/usr/bin/env python3
# encoding: utf-8

"""
server.py
server side responsible for the managing clients and scan execution flow.
"""
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
from structures import Auth, Status
from structures import Ready
from structures import Command
from structures import Report
from structures import Structure
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
        return self.options.secret_key

    def get_request(self) -> tuple:
        """
        Used to add ssl support.
        :return: returns a `ssl.wrap_socket`
        :rtype ´ssl.wrap_socket´
        """
        # noinspection PyTupleAssignmentBalance
        client, addr = super().get_request()
        # TODO: protocol version is hardcoded!
        client_ssl = ssl.wrap_socket(client, keyfile=self.options.sslkey,
                                     certfile=self.options.sslcert,
                                     ssl_version=ssl.PROTOCOL_SSLv23,
                                     ca_certs=None,
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
                                        self, self._terminate)

    def shutdown(self):
        # an override to allow a local terminate event to be set!
        self._terminate.set()
        super().shutdown()
        self.server_close()


class AgentHandler(BaseRequestHandler):
    HEADER = "<B"

    def __init__(self, request, client_address,
                 server: DScanServer, terminate_event):
        self._terminate = terminate_event
        self.msg = None
        self.authenticated = False
        self.connected = False
        super().__init__(request, client_address, server)

    def is_connected(self):
        """

        :return: True if the client has disconnected or
        the terminate event has been triggered, else False
        :rtype `bool`
        """
        return self.connected or not self._terminate.is_set()

    def parse_message(self):
        """
        used to parse a message
        :return: True if message was decoded successfully False otherwise.
        :rtype: `bool`
        """
        try:
            op_size = struct.calcsize(self.HEADER)
            op_bytes = self.request.recv(op_size)
            if len(op_bytes) == 0:
                # agent disconnected !
                self.msg = None
                return

            op, = struct.unpack(self.HEADER, op_bytes)
            self.msg = Structure.create(op, self.request)
            return True
        except (struct.error, ValueError) as e:
            log.info("Error parsing the message %s" % e)
            return False

    def dispatcher(self):
        """
        Command dispatcher all logic
        to decode and dispatch the call
        """
        if not self.parse_message():
            self.connected = False
            log.info("Disconnected!")
            return

        command_name = f"do_{self.msg.op_code.name.lower()}"
        if not hasattr(self, command_name):
            self.send_error(Status.FAILED)  # invalid command
            return

        command = getattr(self, command_name)
        # the only command authorized for unauthenticated agents
        if command_name != "do_AUTH" and not self.authenticated:
            self.send_error(Status.UNAUTHORIZED)
            self.connected = False
            self.request.close()
            return
        # call the command !
        command()

    def handle(self):
        log.info(f"{self.client_address} connected!")
        self.connected = True
        try:
            while self.is_connected():
                try:
                    # start by requesting authentication
                    if not self.authenticated:
                        self.do_auth()

                    self.dispatcher()
                except (socket.timeout, ConnectionError) as e:
                    log.info(f"{self.client_address} Timeout - {e}")
                    self.connected = False

                # wait a bit, in case a shutdown was requested!
                self._terminate.wait(1.0)
        finally:
            self.request.close()

    def do_auth(self):
        log.info(f"{self.client_address} initialized Authentication")
        challenge = os.urandom(128)
        self.request.sendall(Auth(challenge))
        # wait for the client response

        if not self.parse_message():
            # something's wrong with the message!
            self.send_error(Status.FAILED)
            return

        hmac_hash = hmac.new(self.server.secret_key, challenge, 'sha512')
        digest = hmac_hash.hexdigest().encode("utf-8")

        if hmac.compare_digest(digest, self.msg.data):
            log.info("Authenticated Successfully")
            self.authenticated = True
        else:
            self.send_error(Status.UNAUTHORIZED)
            self.request.close()

    def send_error(self, code):
        log.info(f"Sending Error code {code}")
        response = struct.pack("<B", code)
        self.request.sendall(response)
