"""
parsers.py
parsers models, input ip address list collapse, or
scanner results to parse.
"""
import fnmatch
import ipaddress
import os

from libnmap.parser import NmapParser, NmapParserException

from dscan import log


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
        assert len(targets) != 0, "Empty target list"
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
            try:
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
            except StopIteration:
                log.error("No hosts!")
                pass
