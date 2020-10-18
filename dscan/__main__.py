#!/usr/bin/env python3
# encoding: utf-8

import argparse
from datetime import datetime


FORMAT = '%(asctime)s - %(levelname)s - %(message)s'


def main():
    pass


if __name__ == "__main__":
    now = datetime.now().strftime("%b-%d-%Y-%H-%M")

    # logging.basicConfig(filename="drecon-%s.log" % (now),
    #                    format=FORMAT,
    #                    level=logging.INFO)

    parser = argparse.ArgumentParser(prog='Distributed scanner')
    parser.add_argument('--name', type=str, required=True)
    subparsers = parser.add_subparsers(dest='cmd')
    subparsers.required = True
    parser_server = subparsers.add_parser('srv')
    parser_server.add_argument('-b', default='0.0.0.0')
    parser_server.add_argument('-p', type=str, default='2040')
    parser_server.add_argument('targets', type=argparse.FileType('rt'))
    parser_agent = subparsers.add_parser('agent')
    parser_agent.add_argument('-s', default='0.0.0.0', required=True)
    parser_agent.add_argument('-p', type=str, default='2040')
    args = parser.parse_args()
    main()
