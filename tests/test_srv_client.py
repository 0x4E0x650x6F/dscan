import io
import os
import shutil
import threading
import unittest
from argparse import Namespace

from dscan.client import Agent
from dscan.models.scanner import Config
from dscan.out import ContextDisplay
from dscan.server import AgentHandler, DScanServer
from tests import create_config, data_path, log


class TestCase(unittest.TestCase):
    def setUp(self):
        targets = io.StringIO("127.0.0.1\n")
        options_agent = Namespace(name='data/data_agent', s='127.0.0.1',
                                  p=9011,
                                  cmd='agent')
        options_srv = Namespace(name='data', b='127.0.0.1', p=9011,
                                cmd='srv', targets=targets)

        self.cfg = create_config()
        self.settings_srv = Config(self.cfg, options_srv)
        self.settings_srv.target_optimization(targets)
        self.settings_agent = Config(self.cfg, options_agent)

    def tearDown(self):
        shutil.rmtree(os.path.join(data_path, "reports"))
        shutil.rmtree(os.path.join(data_path, "run"))
        shutil.rmtree(os.path.join(data_path, "data_agent"))

    @unittest.SkipTest
    def test_client_server_integration(self):

        server = DScanServer((self.settings_srv.host, self.settings_srv.port),
                             AgentHandler, options=self.settings_srv)

        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        agent = Agent(self.settings_agent)
        try:
            server_thread.start()
            log.info(f"Server loop running in thread: {server_thread.name}")
            out = ContextDisplay(server.ctx)
            out.show()

            agent.start()
        except KeyboardInterrupt:
            print("asking for shutdown !")
            server.shutdown()
            agent.shutdown()


if __name__ == '__main__':
    unittest.main()
