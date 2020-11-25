#!/usr/bin/env python3
# encoding: utf-8

import logging
import os
import threading
import shutil
from subprocess import Popen
from subprocess import PIPE
from configparser import ConfigParser, ExtendedInterpolation
from datetime import datetime
from dscan.models.parsers import parse_args
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
        conf_path = os.path.join(options.name, options.config)
    data = open(conf_path)
    cfg.read_file(data)
    data.close()
    config = Config(cfg, options)

    handler = logging.FileHandler(os.path.join(args.name, f"drecon-{now}.log"))
    handler.setFormatter(logging.Formatter(FORMAT))
    log = logging.getLogger()
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    return config


def create_server(options):
    settings = create_config(options)
    settings.target_optimization(options.targets)
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
    shutil.copy(os.path.join(dataPath, "agent.conf"),
                os.path.join(options.name, "agent.conf"))

    subj = f"/C={options.c}/ST={options.st}/L={options.l}" \
           f"/O={options.o}/OU={options.ou}/" \
           f"CN={options.cn}/emailAddress={options.email}"

    ssl_args = ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout',
                os.path.join(options.name, 'keyfile.key'), '-x509', '-days',
                '3650', '-out', os.path.join(options.name, 'certfile.crt'),
                '-subj', subj
                ]
    with Popen(["openssl", *ssl_args], stdout=PIPE) as proc:
        print(proc.stdout.read())


def main():
    if args.cmd == "agent":
        create_agent(args)
    elif args.cmd == "srv":
        create_server(args)
    else:
        setup_config(args)


if __name__ == "__main__":
    now = datetime.now().strftime("%b-%d-%Y-%H-%M")
    parser = parse_args()
    args = parser.parse_args()
    main()
