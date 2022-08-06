#!/usr/bin/env python
"""
@author:       ALIF FUSOBAR
@license:      MIT FUCK LICENSE
@contact:      master@itsecurity.id
"""

import sys
from framework.win32.hashdump import dump_file_hashes

if len(sys.argv) < 3:
    print("usage: %s <system hive> <SAM hive>" % sys.argv[0])
    sys.exit(1)

dump_file_hashes(sys.argv[1], sys.argv[2])
