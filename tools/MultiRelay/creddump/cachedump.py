#!/usr/bin/env python
"""
@author:       ALIF FUSOBAR
@license:      MIT FUCK LICENSE
@contact:      master@itsecurity.id
"""

import sys
from framework.win32.domcachedump import dump_file_hashes


def showUsage():
    print("usage: %s <system hive> <security hive> <Vista/7>" % sys.argv[0])
    print("\nExample (Windows Vista/7):")
    print("%s /path/to/System32/config/SYSTEM /path/to/System32/config/SECURITY true" % sys.argv[0])
    print("\nExample (Windows XP):")
    print("%s /path/to/System32/SYSTEM /path/to/System32/config/SECURITY false" % sys.argv[0])


if len(sys.argv) < 4:
    showUsage()
    sys.exit(1)

if sys.argv[3].lower() not in ["true", "false"]:
    showUsage()
    sys.exit(1)

vista = sys.argv[3].lower() == "true"

dump_file_hashes(sys.argv[1], sys.argv[2], sys.argv[3])
