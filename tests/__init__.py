import io
import logging
import os
from configparser import ConfigParser, ExtendedInterpolation
from unittest.mock import Mock

from dscan.models.structures import Structure

log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)

data_path = os.path.join(os.path.dirname(__file__), "data")

pwd = os.getcwd()


def create_config():
    cfg = ConfigParser(interpolation=ExtendedInterpolation())
    data = open(os.path.join(data_path, 'dscan.conf'))
    cfg.read_file(data)
    data.close()
    return cfg


class BufMock:

    def __init__(self, *commands):
        self.reads = []
        for cmd in commands:
            if hasattr(cmd, 'pack'):
                self.reads.append(io.BytesIO(cmd.pack()))
            else:
                if isinstance(cmd, bytes):
                    self.reads.append(io.BytesIO(cmd))
                else:
                    self.reads.append(cmd)
        self.cur_cmd = None
        self.count = 0

    def read(self, size):
        if self.count >= len(self.reads):
            return ''
        if not self.cur_cmd:
            self.cur_cmd = self.reads[self.count]

        if isinstance(self.cur_cmd, io.BytesIO):
            data = self.cur_cmd.read1(size)
        else:
            data = self.cur_cmd.read(size)

        if len(data) == 0 and (self.count + 1) < len(self.reads) \
                and len(self.reads):
            self.count += 1
            self.cur_cmd = self.reads[self.count]
            if isinstance(self.cur_cmd, io.BytesIO):
                data = self.cur_cmd.read1(size)
            else:
                data = self.cur_cmd.read(size)
        return data
