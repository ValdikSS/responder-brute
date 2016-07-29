#!/usr/bin/env python3 
'''
Very simple NTLM hash monitor & brute forcer
Monitors Responder database (Responder.db) and runs
user supplied command to brute force it.

Configuration is stored in config.py
'''

import os.path
import sys
import time
import subprocess
import argparse
import io
import shlex
from enum import Enum
import config
def err(*args):
    print(file=sys.stderr, *args)

try:
    import sqlite3
except Exception as e:
    err("ERROR: no sqlite3 Python module found!")
    sys.exit(1)

# Hash types
class Hashtype(Enum):
    cracked    = 1
    noncracked = 2
    notfound   = 3
    every      = 4

HASH_NOTFOUND="!!NOTFOUND!!"
HASH_ERROR="!!HASHERROR!!"

class Storage:
    # Dummy class to store everything
    pass

class Responderdb:
    # Responder.db class
    def __init__(self, path='Responder.db'):
        self.path = path
        try:
            self.__connect()
            self.__disconnect()
        except Exception as e:
            err("Can't use Responder.db: {} {}".format(str(e), repr(e)))

    def __connect(self):
        self.conn = sqlite3.connect(self.path)
        self.c = self.conn.cursor()

    def __disconnect(self):
        self.conn.close()
    
    def __exec(self, query, paramtuple=tuple(), retdata=False):
        try:
            self.__connect()
            self.c.execute(query, paramtuple)
            self.conn.commit()

            if retdata:
                rdata = self.c.fetchall()
        finally:
            self.__disconnect()
        if retdata:
            return rdata
    
    def get_hashes(self, hashtype=Hashtype.every):
        if hashtype == Hashtype.every:
            hashes = self.__exec("SELECT cleartext, type, fullhash FROM responder", retdata=True)
        elif hashtype == Hashtype.cracked:
            hashes = self.__exec("SELECT cleartext, type, fullhash FROM responder WHERE cleartext NOT IN (?,?,?)",
                                 ('', HASH_NOTFOUND, HASH_ERROR), retdata=True)
        elif hashtype == Hashtype.noncracked:
            hashes = self.__exec("SELECT cleartext, type, fullhash FROM responder WHERE cleartext == ''", retdata=True)
        elif hashtype == Hashtype.notfound:
            hashes = self.__exec("SELECT cleartext, type, fullhash FROM responder WHERE cleartext IN (?,?,?)",
                                 ('', HASH_NOTFOUND, HASH_ERROR), retdata=True)
        else:
            err(color_red("ERROR:"), "Wrong hashtype defined!")
            return
        return hashes
    
    def get_hashes_with_cleartext_passwords(self):
        hashes = self.__exec("SELECT cleartext, fullhash FROM responder WHERE cleartext != '' AND cleartext NOT IN (?,?)",
                                 (HASH_NOTFOUND,HASH_ERROR), retdata=True)
        return hashes
    
    def set_hash_password(self, fullhash, password):
        self.__exec("UPDATE responder SET cleartext=? WHERE fullhash=?", (password, fullhash))
        
def brute(command, postcommand, inputfile, inputtype, timeout):
    try:
        proc = subprocess.check_output(shlex.split(command.format(hash=inputfile, hashtype=inputtype)),
                                       timeout=timeout)
        if postcommand:
            proc = subprocess.check_output(shlex.split(postcommand.format(inputfile)),
                                           timeout=timeout)
    except subprocess.CalledProcessError as e:
        # OK for hashcat
        if e.returncode == 1 and not postcommand:
            return e.output
        err(color_red("ERROR:"), "Error running bruteforce command! {} {}".format(str(e), e.output))
        return False
    except subprocess.TimeoutExpired:
        err("Bruteforce timeout expired!")
        return False

    return proc

def color_green(text):
    return "\033[0;32m{}\033[0m".format(text)

def color_green_bold(text):
    return "\033[0;1;32m{}\033[0m".format(text)

def color_red(text):
    return "\033[0;31m{}\033[0m".format(text)

def color_yellow(text):
    return "\033[0;33m{}\033[0m".format(text)

def is_valid_hash(text):
    return (text.count(':') >= 4 and len(text) >= 120)

def get_pass_from_fullhash(text):
    if config.MODE == 'john':
        return (text.split(":")[1])
    elif config.MODE == 'hashcat':
        return (text.split(":")[-1])

def main():
    parser = argparse.ArgumentParser(description='responder-brute')
    parser.add_argument('--clear', action='store_true', help='Clear NOTFOUND flag in Responder.db to brute non cracked hashes again')
    parser.add_argument('--clear-all', action='store_true', help='Clear all cleartext passwords in Responder.db')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--show', action='store_true', help='Show (do not brute) all hashes in Responder.db')
    group.add_argument('--show-cracked', action='store_true', help='Show only cracked hashes in Responder.db')
    group.add_argument('--show-not-cracked', action='store_true', help='Show only NOT cracked hashes in Responder.db')
    args = parser.parse_args()

    if not os.path.isfile(config.RESPONDERDB):
        err(color_red("ERROR:"), config.RESPONDERDB, "cannot be found.")
        sys.exit(1)

    rdb = Responderdb(config.RESPONDERDB)
    if args.show:
        err("=== ALL HASHES IN RESPONDER.DB ===")
        print(sep="\n\n", *rdb.get_hashes(Hashtype.every))
        sys.exit(0)
    elif args.show_cracked:
        err("=== CRACKED HASHES ONLY IN RESPONDER.DB ===")
        print(sep="\n\n", *rdb.get_hashes_with_cleartext_passwords())
        sys.exit(0)
    elif args.show_not_cracked:
        err("=== NON-CRACKED HASHES ONLY IN RESPONDER.DB ===")
        print(sep="\n\n", *rdb.get_hashes(Hashtype.notfound))
        sys.exit(0)
    elif args.clear:
        hashes = rdb.get_hashes(Hashtype.notfound)
        for _, _, curhash in hashes:
            rdb.set_hash_password(curhash, '')
        err("Done!")
        sys.exit(0)
    elif args.clear_all:
        hashes = rdb.get_hashes(Hashtype.every)
        for _, _, curhash in hashes:
            rdb.set_hash_password(curhash, '')
        err("Done!")
        sys.exit(0)
        

    # Get not cracked hashes
    while True:
        nchashes = rdb.get_hashes(Hashtype.noncracked)
        for curcleartext, curnchashtype, curnchash in nchashes:
            if curnchashtype.lower().startswith('ntlmv2'):
                brute_type = config.HASHTYPE_NTLMv2
            elif curnchashtype.lower().startswith('ntlmv1'):
                brute_type = config.HASHTYPE_NTLMv1
            else:
                err(color_red("ERROR:"), "Unknown hash type", curnchashtype)
                rdb.set_hash_password(curnchash, HASH_ERROR)
                continue
            err(color_yellow("Cracking"), curnchash)
            with open(config.CURRENTHASHFILE, "w") as f:
                f.write(curnchash)
            output = brute(config.COMMAND, config.COMMAND_POST, config.CURRENTHASHFILE,
                           brute_type, config.TIMEOUT)
            cleartextpass = None
            if not output:
                err(color_red("ERROR:"), ": Can't get bruteforce output, something went wrong!")
                rdb.set_hash_password(curnchash, HASH_ERROR)
                continue
            output = output.decode('utf-8')
            outputstr = io.StringIO(output)
            for outline in outputstr:
                if is_valid_hash(outline):
                    cleartextpass = get_pass_from_fullhash(outline).rstrip("\n")
                    if not cleartextpass:
                        cleartextpass = 'NO PASSWORD'
                    print(color_green_bold("The pass is:"), cleartextpass)
                    rdb.set_hash_password(curnchash, cleartextpass)
            if not cleartextpass:
                rdb.set_hash_password(curnchash, HASH_NOTFOUND)
            err(color_yellow("Done."))
        time.sleep(config.POLLTIME)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)
