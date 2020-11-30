"""
parsers.py
parsers models, input ip address list collapse, or
scanner results to parse.
"""
import fnmatch
import ipaddress
import os
import argparse
from libnmap.parser import NmapParser, NmapParserException

from dscan import log


def parse_args():
    """
    Used by main to parse the user arguments.

    :return: argparse instance.
    :rtype: `argparse.ArgumentParser`
    """
    parser = argparse.ArgumentParser(prog='Distributed scanner')
    parser.add_argument('--name', type=str, required=True)

    subparsers = parser.add_subparsers(dest='cmd')
    subparsers.required = True
    parser_server = subparsers.add_parser('srv')
    parser_server.add_argument('--config', required=True)
    parser_server.add_argument('-b', default='0.0.0.0')
    parser_server.add_argument('-p', type=int, default=2040)
    parser_server.add_argument('targets', type=argparse.FileType('rt'))
    parser_agent = subparsers.add_parser('agent')
    parser_agent.add_argument('--config', required=True)
    parser_agent.add_argument('-s', required=True)
    parser_agent.add_argument('-p', type=int, default=2040)
    parser_config = subparsers.add_parser('config')
    parser_config.add_argument("-email", type=str, required=True)
    parser_config.add_argument("-cn", type=str, required=True)
    parser_config.add_argument("-c", type=str, required=True)
    parser_config.add_argument("-l", type=str, required=True)
    parser_config.add_argument("-st", type=str, required=True)
    parser_config.add_argument("-o", type=str, required=True)
    parser_config.add_argument("-ou", type=str, required=True)
    parser_config.add_argument("-days", type=int, required=True)
    return parser


class ReportsParser:
    """
    XML Nmap results parser.
    """

    def __init__(self, reports_path, pattern):
        """
        :param reports_path: path where the reports are stored
        :param pattern: pattern `fnmatch` to find valid files to extract
        the results from.
        """
        self.path = reports_path
        self.pattern = pattern

    def hosts_up(self):
        """
        :return: list of hosts up.
        :rtype: `list`
        """
        hosts_up = []
        for host in self.__walk():
            if host.is_up():
                hosts_up.append(host.ipv4)
        return hosts_up

    def __walk(self):
        """
        information.
        :yield: A list with the filtered values
        :rtype: `list`
        """
        for report in os.scandir(self.path):
            if fnmatch.fnmatch(report.name, self.pattern):
                try:
                    nmap_report = NmapParser.parse_fromfile(report.path)
                    yield from nmap_report.hosts
                except NmapParserException as ex:
                    log.error(f"Error parsing {report} - {ex}")


class TargetOptimization:
    """
    This class takes lists of hosts or networks, and attempts to optimize
        them by either split big cidr like /8 /16 in /24 or in rage format
        192.168.10.1-4.
    """

    def __init__(self, fpath, cidr="/24"):
        self.cidr = cidr
        self.fpath = fpath

    def save(self, targets):
        """
        Takes a list of targets to optimize and saves it in the workspace path.

        :param targets: `list` of targets (`str` and top optimize.
        :type: targets: `list` of `str`
        """
        assert targets, "Empty target list"
        ips = []

        with open(self.fpath, 'wt') as qfile:
            for target in targets:
                try:
                    if "/" in target:
                        net = ipaddress.ip_network(target.strip())
                        if net.prefixlen < 24:
                            subs = map(lambda n: f"{n.with_prefixlen}\n",
                                       net.subnets(new_prefix=24))
                            qfile.writelines(subs)
                        else:
                            qfile.write(f"{net.with_prefixlen}\n")
                    else:
                        ips.append(ipaddress.ip_address(target.strip()))
                except (TypeError, ValueError):
                    log.error(f"Error optimizing target: {target}")

            # sorting the ip addresses.
            ips.sort(key=ipaddress.get_mixed_type_key)
            # find consecutive ip address ranges.
            if ips:
                for first, last in ipaddress._find_address_range(ips):
                    ip_range = list(ipaddress.summarize_address_range(first,
                                                                      last))
                    # if the number of ranges is more than one network in cidr
                    # format then the glob format x.x.x.x-y is more efficient,
                    # since nmap supports this format.
                    if len(ip_range) > 1:
                        qfile.write(f"{first}-{last.exploded.split('.')[3]}\n")
                    else:
                        qfile.write(f"{ip_range.pop().with_prefixlen}\n")