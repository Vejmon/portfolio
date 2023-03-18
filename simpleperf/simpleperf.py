import sys
import argparse
import re
import socket
import threading as th


# function to validate the ip address given as an argument, validatet with a regex pattern.
# if we don't have a valid ip address we terminate the program
def valid_ip(inn):  # ip address must start with 1-3 digits seperated by a dot, repeated three more times.
    ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_regex.match(inn):
        return inn
    else:
        raise ValueError(f"{inn} is not a valid ip address.\nRequired dotted decimal notation.\nExample: 3.3.3.3")


# check if port is an integer and between 1024 - 65535
def valid_port(inn):
    try:
        ut = int(inn)
    except ValueError:
        raise argparse.ArgumentTypeError(f"port must be an integer, {inn} isn't")
    if not (1024 <= ut <= 65535):
        raise argparse.ArgumentTypeError(f'port number: ({inn}) must be within range [1024 - 65535]')
    return ut


# check if time input is an integer and more than zero
def valid_time(inn):
    try:
        ut = int(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"time must be an integer, {inn} isn't")
    if ut < 0:
        raise argparse.ArgumentTypeError(f"time must be a positive integer, {inn} isn't")
    return ut


# check if the input is an integer and more than zero
def valid_num(inn):
    try:
        ut = int(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"bytes must be an integer, {inn} isn't")
    if ut < 0:
        raise argparse.ArgumentTypeError(f"bytes must be a positive integer, {inn} isn't")
    return ut



# start the argument parser
parse = argparse.ArgumentParser(description="optional arguments for simpleperf", epilog='simpleperf --help')

# optional arguments, with long and short name, default values when needed
parse.add_argument('-s', '--server', action='store_true', help='enables server mode')
parse.add_argument('-c', '--client', action='store_true', help='enables client mode')
parse.add_argument('-p', '--port', type=valid_port, default=8088, help="which port to bind/open")

# server arguments ignored if running a client
parse.add_argument('-b', '--bind', type=valid_ip, default=socket.gethostbyname(socket.gethostname()),
                   help="ipv4 adress to bind server to")
parse.add_argument('-f', '--format', choices=['B', 'KB', 'MB', 'GB', 'TB'],
                   type=str, default='MB', help="format output with SI prefix")

# client arguments ignored if running a server
parse.add_argument('-I', '--serverip', type=valid_ip, default=socket.gethostbyname(socket.gethostname()),
                   help="ipv4 address to connect with")
parse.add_argument('-t', '--time', type=valid_time, default=25, help="time duration to transfer bytes")
parse.add_argument('-i', '--interval', type=valid_time, default=25, help='intervall between prints to consoll')
parse.add_argument('-P', '--parallel', type=int, choices=[1, 2, 3, 4, 5], default=1,
                   help='run client in parallel, max 5 threads')
parse.add_argument('-n', '--num', type=valid_num, required=False, help='amount of bytes to transfer')

dashes = "------------------------------------------------------------"

# parse the arguments
args = parse.parse_args()


def handle_client(con, cli_arg):



# an instance of simpleperf may only be server or client
if not (args.server ^ args.client):
    raise AttributeError("you must run either in server or client mode")


# function to handle incomming connections, they are handled in separate threads
def server():
    # tuple with ip, and port as an integer
    serv_port = int(args.port)
    serv_ip = args.bind

        # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:
        # attempt to bind to port, quit if failed.
        try:
            serv.bind((serv_ip, serv_port))
        except:
            print(f'bind failed to port: {serv_port},  quitting')
            sys.exit(1)

        serv.listen(15)
        print(f"{dashes}\n   a simpleperf server is listening on port <{serv_ip}:{serv_port}>\n{dashes}")

        #accepts a connection and start a thread handling the connection.
        while True:
            # accepts an incoming client and deliver requested document.
            con, rport = serv.accept()
            raddr = con.getpeername()

            f"A simpleperf client with <{raddr}:{rport}> is connected with <{serv_ip}:{serv_port} >"
            # start a thread
            t = th.Thread()



def client():

    # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
        serv_ip = args.serverip
        serv_port = int(args.port)

        print(f"{serv_ip}:{serv_port}")

        #build a byte message which is 1000 B aprox 1 KB
        msg = ("wop!" * 250).encode()

        # set a timeout timer.
        cli.settimeout(11)
        # attempt to connect to a server
        try:
            con = cli.connect((serv_ip, serv_port))
        except ConnectionError:
            raise ConnectionError("connection failed")



if args.server:
    server()
else:
    client()
