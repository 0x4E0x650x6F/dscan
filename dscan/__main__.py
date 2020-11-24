#!/usr/bin/env python3
# encoding: utf-8

import logging
import argparse
import os
import threading
from configparser import ConfigParser, ExtendedInterpolation
from datetime import datetime

from dscan.client import Agent
from dscan.models.scanner import Config
from dscan.server import DScanServer
from dscan.server import AgentHandler
from dscan import dataPath
from dscan.out import ContextDisplay

FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

def create_config(options):
    cfg = ConfigParser(interpolation=ExtendedInterpolation())
    data = open(os.path.join(dataPath, 'dscan.conf'))
    cfg.read_file(data)
    data.close()
    return Config(cfg, options)


def create_server(options):
    settings = create_config(options)
    server = DScanServer((settings.host, settings.port),
                         AgentHandler, options=settings)

    server_thread = threading.Thread(target=server.serve_forever)
    # Exit the server thread when the main thread terminates
    server_thread.daemon = True
    server_thread.start()
    logging.info(f"Server loop running in thread:{server_thread.name}")
    out = ContextDisplay(server.ctx)
    out.show()
    return server


def create_agent(options):
    settings = create_config(options)
    agent = Agent(settings)
    agent_thread = threading.Thread(target=agent.start)
    agent_thread.start()
    return agent


def main():
    worker = None
    try:
        if args.cmd == "agent":
            worker = create_agent(args)
        else:
            worker = create_server(args)
    except (KeyboardInterrupt, Exception) as ex:
        logging.info("Forced shutdown was requested!")
        logging.info(f"{ex}")
        if worker:
            worker.shutdown()


if __name__ == "__main__":
    now = datetime.now().strftime("%b-%d-%Y-%H-%M")

    logging.basicConfig(filename=f"drecon-{now}.log", format=FORMAT,
                        level=logging.INFO)

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
