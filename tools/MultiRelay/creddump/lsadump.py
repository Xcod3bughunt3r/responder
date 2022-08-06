#!/usr/bin/env python
"""
@author:       ALIF FUSOBAR
@license:      MIT FUCK LICENSE
@contact:      master@itsecurity.id
"""

import sys
from framework.win32.lsasecrets import get_file_secrets

# Hex dump code from
# http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/142812

FILTER = ''.join(32 <= i < 127 and chr(i) or '.' for i in range(256))


def showUsage():
    print("usage: %s <system hive> <security hive> <Vista/7>" % sys.argv[0])
    print("\nExample (Windows Vista/7):")
    print("%s /path/to/System32/config/SYSTEM /path/to/System32/config/SECURITY true" % sys.argv[0])
    print("\nExample (Windows XP):")
    print("%s /path/to/System32/SYSTEM /path/to/System32/config/SECURITY false" % sys.argv[0])


def dump(src, length=8):
    N = 0
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["%02X" % x for x in s])
        s = ''.join(FILTER[b] for b in s)
        result += "%04X   %-*s   %s\n" % (N, length * 3, hexa, s)
        N += length
    return result


if len(sys.argv) < 4 or sys.argv[3].lower() not in ["true", "false"]:
    showUsage()
    sys.exit(1)
else:
    vista = sys.argv[3].lower() == "true"

secrets = get_file_secrets(sys.argv[1], sys.argv[2], vista)
if not secrets:
    print("Unable to read LSA secrets. Perhaps you provided invalid hive files?")
    sys.exit(1)

for k in secrets:
    print(k.decode())
    print(dump(secrets[k], length=16))
