#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect
import os
import sys
from enum import Enum
import string
import random
import hmac
import requests
import re

""" <config> """
# SERVICE INFO
PORT = "8080"
session = requests.Session()

# DEBUG -- logs to stderr, TRACE -- verbose log
DEBUG = os.getenv("DEBUG", False)
TRACE = os.getenv("TRACE", False)
""" </config> """

FLAGS_ID = []
FLAGS = []
FLAG_RE = re.compile("[a-zA-Z0-9]{31}=")

def check(host):
    print("check!")
    
    


def put(host, flag_id, flag, vuln):
    
    send_data = {"username" : flag_id, "password" : hmac.new(flag_id.encode()).hexdigest()}
    session.post("http://" + host + ":" + PORT + "/signup", data = send_data)
    
    send_data = {"username" : flag_id, "password" : hmac.new(flag_id.encode()).hexdigest()}
    session.post("http://" + host + ":" + PORT + "/auth", data = send_data)
    
    send_data = {"recipe" : flag}
    session.post("http://" + host + ":" + PORT + "/bar", data = send_data)
    


def get(host, flag_id, flag, vuln):
    try:
        send_data = {"username" : flag_id, "password" : hmac.new(flag_id.encode()).hexdigest()}
        requests.post("http://" + host + ":" + PORT + "/auth", data = send_data)
    
        responce = requests.get("http://" + host + ":" + PORT + "/recipes").text
        
        found_flag = FLAG_RE.findall(responce)
        
        if found_flag == flag:
            die(
                ExitStatus.OK,
                f"Usage: {host} get IP FLAGID FLAG",
            )
        
        else:
            die(
                ExitStatus.CORRUPT,
                f"Usage: {host} get IP FLAGID FLAG",
            )
    except:
        die(
            ExitStatus.MUMBLE,
            f"Exception: {e}. Stack:\n {inspect.stack()}",
        )

""" <common> """


class ExitStatus(Enum):
    OK = 101
    CORRUPT = 102
    MUMBLE = 103
    DOWN = 104
    CHECKER_ERROR = 110


def _log(obj):
    if DEBUG and obj:
        caller = inspect.stack()[1].function
        print(f"[{caller}] {obj}", file=sys.stderr, flush=True)
    return obj


def die(code: ExitStatus, msg: str):
    if msg:
        print(msg, file=sys.stderr, flush=True)
    exit(code.value)

def rand_string(N=12, alphabet=string.ascii_letters + string.digits):
    return ''.join(random.choice(alphabet) for _ in range(N))
    
def generate_secret():
    secret = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(31))
    return secret + '='


def _main():
    action, *args = sys.argv[1:]
    #vuln = 0
    flag_id = rand_string(15)
    FLAGS_ID.append(flag_id)
    flag = generate_secret()
    FLAGS_ID.append(flag_id)
    
    #try:
    if action == "check":
        host, = args
        check(host)
    elif action == "put":
        #host, flag_id, flag, vuln = args
        host, = args
        put(host, flag_id, flag, vuln)
    elif action == "get":
        #host, flag_id, flag, vuln = args
        host, = args
        get(host, flag_id, flag, vuln)
    else:
        raise IndexError
    #except ValueError:
        #die(
            #ExitStatus.CHECKER_ERROR,
            #f"Usage: {sys.argv[0]} check|put|get IP FLAGID FLAG",
        #)
    #except Exception as e:
        #die(
            #ExitStatus.CHECKER_ERROR,
            #f"Exception: {e}. Stack:\n {inspect.stack()}",
        #)


""" </common> """

if __name__ == "__main__":
    _main()
