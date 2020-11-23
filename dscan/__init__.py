import os
import logging

global settings
log = logging.getLogger()
log.addHandler(logging.NullHandler())
dataPath = os.path.join(os.path.dirname(__file__), "data")
