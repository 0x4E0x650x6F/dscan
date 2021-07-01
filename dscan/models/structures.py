#!/usr/bin/env python3
# encoding: utf-8

"""
structures.py
network elements of the scanner
"""
import struct
from enum import IntEnum
from dscan import log


class Status(IntEnum):
    """
    Code values for the response status.
    """
    SUCCESS = 0x00
    UNAUTHORIZED = 0x01
    FINISHED = 0x02
    UNFINISHED = 0x03
    FAILED = 0xFF


class Operations(IntEnum):
    """
    Commands available!
    """
    AUTH = 0x01
    READY = 0x02
    COMMAND = 0x03
    STATUS = 0x04
    REPORT = 0x05


class Structure:
    __slots__ = ()
    op_code = None
    _format = None
    HEADER = "<B"
    """
    The object representation for the info exchanged between
    agents and servers.
    """
    def __init__(self, *args, sock=None):
        if not sock:
            self.setData(*args)
        else:
            self.unpack(sock)

    def setData(self, *args):
        fields = getattr(self, '__slots__', [])
        if len(args) != len(fields):
            raise TypeError("Expected {} args".format(len(fields)))

        for name, value in zip(fields, args):
            if isinstance(value, str):
                value = value.encode("ascii")
            setattr(self, name, value)

    def unpack(self, sock):
        """
        Unpacks a known command based on the predefined
        :param sock:
        :return: Instance of a message subclass
        """
        if self._format:
            if isinstance(self._format, str):
                struct_size = struct.calcsize(self._format)
                data = struct.unpack(self._format,
                                     sock.recv(struct_size))
                return self.setData(*data)
            else:
                size_fmt = self._format[0]
                sz_nbytes = struct.calcsize(size_fmt)
                sz_bytes = sock.recv(sz_nbytes)
                sz = struct.unpack(size_fmt, sz_bytes)

                data_fmt = self._format[1].format(*sz)
                dt_nbytes = struct.calcsize(data_fmt)
                dt_bytes = sock.recv(dt_nbytes)
                data = struct.unpack(data_fmt, dt_bytes)
                return self.setData(*data)

    def pack(self):
        """
        Returns a `struct.pack` string ready to be sent
        :return: `struct.pack`
        """
        fmt = ''
        byte_order = ''
        values = [getattr(self, name, '') for name in self.__slots__]
        if self._format:
            if isinstance(self._format, str):
                if self._format.startswith(('<', '>', '!', '@')):
                    byte_order = self._format[0]
                    fmt = self._format[1:]
                fmt = f"{byte_order}B{fmt}"
                return struct.pack(fmt, self.op_code.value, *values)
            else:
                fmt = "{0}B{1}".format(*self._format)
                lengths = [len(getattr(self, name, '')) for name in
                           self.__slots__
                           if isinstance(getattr(self, name, ''), bytes)]
                fmt = fmt.format(*lengths)
                return struct.pack(fmt, self.op_code.value, *lengths, *values)

    @classmethod
    def create(cls, sock):
        try:
            op_size = struct.calcsize(cls.HEADER)
            op_bytes = sock.recv(op_size)
            if len(op_bytes) == 0:
                # agent disconnected !
                return
            op, = struct.unpack(cls.HEADER, op_bytes)

            subs = cls.__subclasses__()
            for operation in subs:
                if operation.op_code.value == op:
                    return operation(sock=sock)
            return None
        except (struct.error, ValueError) as e:
            log.info("Error parsing the message %s" % e)
            return None


class Auth(Structure):
    """
    Authentication Request
    from an Agent to server!
    """
    __slots__ = ('data', )
    _format = "<128s"

    op_code = Operations.AUTH

    def __str__(self):
        return f"Auth(op_code={self.op_code}, data={self.data})"


class Ready(Structure):
    """
    Ready to start Scan !
    Sent by an Agent to the server
    With the client's current user id
    """
    __slots__ = ('uid', 'alias')
    _format = ('<B', 'I{0}s')
    op_code = Operations.READY

    def __str__(self):
        return f"Ready({self.op_code}, uid={self.uid}, alias={self.alias})"


class Command(Structure):
    """
    Scan task information !
    Send by the server to the agent.
    final format is  <BB?s?s
    """
    __slots__ = ('target', "options")
    _format = ('<BB', '{0}s{1}s')
    op_code = Operations.COMMAND

    def __str__(self):
        return f"Command(op_code={self.op_code}, target={self.target}, " \
               f"options={self.options})"


class ExitStatus(Structure):
    """
      Scan Result Status !
      Send both server and agent to signal the exit status of a operation.
      final format is  <BB
   """
    __slots__ = ("status", )
    _format = '<B'
    op_code = Operations.STATUS

    def __str__(self):
        return f"Status(op_code={self.op_code}, " \
               f"status={self.status}"


class Report(Structure):
    """
    When an agent's task terminates,
    it initiates a report transfer request
    """
    __slots__ = ('filesize', 'filename', 'filehash')
    _format = ('<BB', 'I{0}s{1}s')
    op_code = Operations.REPORT

    def __str__(self):
        return f"Report(op_code={self.op_code}, filesize={self.filesize}," \
               f" filename={self.filename!s}, filehash={self.filehash})"
