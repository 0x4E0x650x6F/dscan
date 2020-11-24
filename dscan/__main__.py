#!/usr/bin/env python3
# encoding: utf-8

import logging
import argparse
import os
import threading
from configparser import ConfigParser, ExtendedInterpolation
from datetime import datetime
import shutil
from dscan.client import Agent
from dscan.models.scanner import Config
from dscan.server import DScanServer
from dscan.server import AgentHandler
from dscan import dataPath
from dscan.out import ContextDisplay

FORMAT = '%(asctime)s - %(levelname)s - %(message)s'


def create_config(options):
    cfg = ConfigParser(interpolation=ExtendedInterpolation())
    conf_path = os.path.join(dataPath, 'dscan.conf')
    if options.config:
        conf_path = options.config
    data = open(conf_path)
    cfg.read_file(data)
    data.close()
    config = Config(cfg, options)
    config.target_optimization(options.targets)
    return config


def create_server(options):

    settings = create_config(options)
    server = DScanServer((settings.host, settings.port),
                         AgentHandler, options=settings)

    server_thread = threading.Thread(target=server.serve_forever)
    # Exit the server thread when the main thread terminates
    server_thread.daemon = True
    try:
        server_thread.start()
        logging.info(f"Server loop running in thread:{server_thread.name}")
        out = ContextDisplay(server.ctx)
        out.show()
        server_thread.join()
    except (KeyboardInterrupt, Exception) as ex:
        logging.info("Forced shutdown was requested!")
        logging.info(f"{ex}")
        if server:
            server.shutdown()


def create_agent(options):
    settings = create_config(options)
    agent = Agent(settings)
    agent_thread = threading.Thread(target=agent.start)
    try:
        agent_thread.start()
        agent_thread.join()
    except (KeyboardInterrupt, Exception) as ex:
        logging.info("Forced shutdown was requested!")
        logging.info(f"{ex}")
        if agent_thread:
            agent.shutdown()


def setup_config(options):
    os.makedirs(options.name, exist_ok=True)
    shutil.copy(os.path.join(dataPath, "dscan.conf"),
                os.path.join(options.name, "dscan.conf"))


def main():
    if args.cmd == "agent":
        create_agent(args)
    elif args.cmd == "srv":
        create_server(args)
    else:
        setup_config(args)


if __name__ == "__main__":
    now = datetime.now().strftime("%b-%d-%Y-%H-%M")

    logging.basicConfig(filename=f"drecon-{now}.log", format=FORMAT,
                        level=logging.DEBUG)

    parser = argparse.ArgumentParser(prog='Distributed scanner')
    parser.add_argument('--name', type=str, required=True)
    parser.add_argument('--config', required=True)
    subparsers = parser.add_subparsers(dest='cmd')
    subparsers.required = True
    parser_server = subparsers.add_parser('srv')
    parser_server.add_argument('-b', default='0.0.0.0')
    parser_server.add_argument('-p', type=int, default=2040)
    parser_server.add_argument('targets', type=argparse.FileType('rt'))
    parser_agent = subparsers.add_parser('agent')
    parser_agent.add_argument('-s', required=True)
    parser_agent.add_argument('-p', type=str, default='2040')
    parser_agent = subparsers.add_parser('config')
    args = parser.parse_args()
    main()
