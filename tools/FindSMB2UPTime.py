#!/usr/bin/env python
"""
@author    : ALIF FUSOBAR
@nickname  : Xcod3bughunt3r
@license   : MIT FUCK LICENSE
@contact   : master@itsecurity.id
"""

import re,sys,socket,struct
import os
import datetime
import multiprocessing
from socket import *

sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), '..')))
from packets import SMBHeaderReq, SMB2NegoReq, SMB2NegoDataReq

def GetBootTime(data):
    Filetime = int(struct.unpack('<q',data)[0])
    if Filetime == 0:  # server may not disclose this info
        return 0, "Unknown"
    t = divmod(Filetime - 116444736000000000, 10000000)
    time = datetime.datetime.fromtimestamp(t[0])
    return time, time.strftime('%Y-%m-%d %H:%M:%S')


def IsDCVuln(t, host):
    if t[0] == 0:
        print("Server", host[0], "did not disclose its boot time")
        return

    Date = datetime.datetime(2014, 11, 17, 0, 30)
    if t[0] < Date:
        print("System is up since:", t[1])
        print("This system may be vulnerable to MS14-068")
    Date = datetime.datetime(2017, 0o3, 14, 0, 30)
    if t[0] < Date:
        print("System is up since:", t[1])
        print("This system may be vulnerable to MS17-010")
    print("Server", host[0], "is up since:", t[1])


def run(host):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(host)

        Header = SMBHeaderReq(Cmd="\x72",Flag1="\x18",Flag2="\x53\xc8")
        Nego = SMB2NegoReq(Data = SMB2NegoDataReq())
        Nego.calculate()

        Packet = str(Header)+str(Nego)
        Buffer = struct.pack(">i", len(Packet)) + Packet
        s.send(Buffer)

        data = s.recv(1024)
        if data[4:5] == "\xff":
            print("Server", host[0], "doesn't support SMBv2")
        if data[4:5] == "\xfe":
            IsDCVuln(GetBootTime(data[116:124]), host)

    except KeyboardInterrupt:
        s.close()
        sys.exit("\rExiting...")
    except:
        s.close()
        pass

def atod(a):
    return struct.unpack("!L",inet_aton(a))[0]

def dtoa(d):
    return inet_ntoa(struct.pack("!L", d))

if __name__ == "__main__":
    if len(sys.argv)<=1:
        sys.exit('Usage: python '+sys.argv[0]+' 10.1.3.37\nor:\nUsage: python '+sys.argv[0]+' 10.1.3.37/24')

    m = re.search("/", str(sys.argv[1]))
    if m :
        net,_,mask = sys.argv[1].partition('/')
        mask = int(mask)
        net = atod(net)
        threads = []
        for host in (dtoa(net+n) for n in range(0, 1<<32-mask)):
            p = multiprocessing.Process(target=run, args=((host,445),))
            threads.append(p)
            p.start()
    else:
        run((str(sys.argv[1]),445))
