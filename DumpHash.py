#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools.

import sqlite3

def DumpHashToFile(outfile, data):
	with open(outfile,"w") as dump:
		dump.write(data)

def DbConnect():
    cursor = sqlite3.connect("./Responder.db")
    return cursor

def GetResponderCompleteNTLMv2Hash(cursor):
     res = cursor.execute("SELECT fullhash FROM Responder WHERE type LIKE '%v2%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)")
     Output = ""
     for row in res.fetchall():
         Output += '{0}'.format(row[0])+'\n'
     return Output

def GetResponderCompleteNTLMv1Hash(cursor):
     res = cursor.execute("SELECT fullhash FROM Responder WHERE type LIKE '%v1%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)")
     Output = ""
     for row in res.fetchall():
         Output += '{0}'.format(row[0])+'\n'
     return Output

cursor = DbConnect()
print("Dumping NTLMV2 hashes:")
v2 = GetResponderCompleteNTLMv2Hash(cursor)
DumpHashToFile("DumpNTLMv2.txt", v2)
print(v2)
print("\nDumping NTLMv1 hashes:")
v1 = GetResponderCompleteNTLMv1Hash(cursor)
DumpHashToFile("DumpNTLMv1.txt", v1)
print(v1)
