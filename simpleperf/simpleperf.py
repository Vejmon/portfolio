# import re
import subprocess
import sys
import argparse
import socket
import threading
import threading as th
import ipaddress
import time
import itertools
import math

connections = []
connected = False


class EnCon:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class EnServer(EnCon):
    def __init__(self, ip, port, connected):
        super().__init__(ip, port)
        self.connected = connected


class TimeClient(EnCon):
    def __init__(self, ip, port, interval, tid, byte, form):
        super().__init__(ip, port)
        self.interval = interval
        self.tid = tid
        self.bytes = byte
        self.form = form


class NumClient(EnCon):
    def __init__(self, ip, port, interval, num, byte, form):
        super().__init__(ip, port)
        self.interval = interval
        self.num = num
        self.byte = byte
        self.form = form


# a function to run ifconfig and grab the first ipv4 address we find.
# which makes sense to set as default address when running in server mode.
def get_ip():
    # Run the ifconfig command and capture the output, and decode bytes to string
    ifconf = subprocess.check_output(['ifconfig']).decode()

    # Split the output into lines
    ifconf_lines = ifconf.split('\n')

    # if no valid address is grabbed from ifconfig.
    address = False
    # Find the line that contains the IP address
    for line in ifconf_lines:
        if 'inet ' in line:
            address = line.split()[1]
            break
    # return an arbitrary default value, or the one we grabbed.
    if ipaddress.ip_address(address):
        return address
    else:
        return "10.0.0.2"


# function to validate the ip address given as an argument, validatet with a regex pattern.
# if we don't have a valid ip address we terminate the program
def valid_ip(inn):  # ip address must start with 1-3 digits seperated by a dot, repeated three more times.
    try:
        ip = ipaddress.ip_address(inn)
    except ValueError:
        print(f"{inn} is not a valid ip address.\nRequired dotted decimal notation.\nExample: 3.3.3.3")
        sys.exit(1)
        # cast the ipv4 apress to string
    return str(ip)
    # ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


# check if port is an integer and between 1024 - 65535
def valid_port(inn):
    try:
        ut = int(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"port must be an integer, {inn} isn't")
    if not (1024 <= ut <= 65535):
        raise argparse.ArgumentTypeError(f'port number: ({inn}) must be within range [1024 - 65535]')
    return ut


# returns a dictionary containing arguments
# def args_to_dict(inn):

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
parse.add_argument('-f', '--format', choices=['B', 'KB', 'MB', 'GB'],
                   type=str, default='MB', help="format output with SI prefix")

# server arguments ignored if running a server
parse.add_argument('-b', '--bind', type=valid_ip, default=get_ip(),  # attempts to grab ip from ifconfig
                   help="ipv4 adress to bind server to")

# client arguments ignored if running a client
parse.add_argument('-I', '--serverip', type=valid_ip, default="10.0.0.2",  # default value is set to node h1
                   help="ipv4 address to connect with")
parse.add_argument('-t', '--time', type=valid_time, default=25, help="time duration to transfer bytes")
parse.add_argument('-i', '--interval', type=valid_time, default=25, help='intervall between prints to consoll')
parse.add_argument('-P', '--parallel', type=int, choices=[1, 2, 3, 4, 5], default=1,
                   help='run client in parallel, max 5 threads')
parse.add_argument('-n', '--num', type=valid_num, required=False, help='amount of bytes to transfer')

dashes = "-------------------------------------------------------------"

# parse the arguments
args = parse.parse_args()
print(args)

# an instance of simpleperf may only be server or client
if not (args.server ^ args.client):
    raise AttributeError("you must run either in server or client mode")


def how_many_bytes(format, value):
    if format == "B":
        return int(value)
    elif format == "KB":
        return int(value * 1000)
    elif format == "MB":
        return int(value * 1_000_000)
    else:
        return int(value * 1_000_000_000)


# function to handle a single connection from a client
def server_handle_client(con):
    # assign remote address and port
    # assign local address and port
    raddr, rport = con.getpeername()
    laddr, lport = con.getsockname()

    print(f"A simpleperf client with address <{raddr}:{rport}> is connected with <{laddr}:{lport}>")

    # recieve a packet containing args from the client.
    cli_args = con.recv(2042).decode()
    # stores the clients, arguments.
    cli_args_splitted = cli_args.split(":")
    unit = cli_args_splitted[0]
    value = cli_args_splitted[1]

    # string we will append bytes to.
    total_bytes = ""
    # if we expect to listen for a given time.
    if unit == "time":
        then = time.perf_counter()
        now = time.perf_counter()
        while (then - now) < value:
            print(f"recv on TIME {value}")
            total_bytes += con.recv(1024).decode()
    else:
        format_value = cli_args.split(":")[3]
        value = how_many_bytes(format_value, value)
        while len(total_bytes) <= value:
            print(f"recv BYTES {value}")
            total_bytes += con.recv(1024).decode()


# function to handle incomming connections, they are handled in separate threads
def server():
    # tuple with ip, and port as an integer

    server = EnServer(args.bind, args.port, connections)

    # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servsock:
        # attempt to bind to port, quit if failed.
        try:
            servsock.bind((server.ip, server.port))
        except:
            print(f'bind failed to port: {server.port},  quitting')
            sys.exit(1)

        servsock.listen(15)
        print(f"{dashes}\n   a simpleperf server is listening on <{server.ip}:{server.port}>\n{dashes}")

        # accepts a connection and start a thread handling the connection.
        while True:
            # accepts an incoming client and deliver requested document.
            con, addr_info = servsock.accept()

            # start a thread
            t = th.Thread(target=server_handle_client, args=(con, ))
            # thread ends if main thread ends.
            t.setDaemon(True)
            # start the thread
            t.start()

def transfer_time_client(enClient):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:

        cli.settimeout(11)
        try:
            cli.connect((enClient.ip, enClient.port))
        except ConnectionError:
            raise ConnectionError(f"Connection to {enClient.ip}:{enClient.port} failed, quitting")

        # grab remote address and port
        raddr, rport = cli.getpeername()

        print(f"{enClient.ip}:{enClient.port} connected with server {raddr}:{rport}")

        cli.send(enClient)


def transfer_byte_client(enClient):
    # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:

        # set a timeout timer.
        cli.settimeout(11)
        try:
            cli.connect((enClient.ip, enClient.port))
        except ConnectionError:
            raise ConnectionError(f"Connection to {enClient.ip}:{enClient.port} failed, quitting")

        # grab remote address and port
        raddr, rport = cli.getpeername()
        # print info
        print(f"{enClient.ip}:{enClient.port} connected with server {raddr}:{rport}")

        # build a byte message which is 1000 B aprox 1 KB, unless we are working with single bytes.
        if args.format == 'B':
            msg = "w"
        else:
            msg = ("wop!" * 250).encode()

        # let server now about how long to recieve, or how many bits to recieve (overrides time)

        """if args.num:
            a_connection = {"nr": nr,
                            "local": f"{args.bind}:{args.port}",
                            "remote": f"{raddr}:{rport}",
                            "bytes:": int(args.num),
                            "interval": int(args.interval),
                            "sentBytes": 0}
            cli_args = f"num:{args.num}:{args.interval}:{args.format}"
        else:
            a_connection = {"nr": nr,
                            "local": f"{args.bind}:{args.port}",
                            "remote": f"{raddr}:{rport}",
                            "time": args.time,
                            "interval": args.interval,
                            "sentBytes": 0}

            cli_args = f"time:{args.time}:{args.interval}"
        """
        cli.send(enClient)


# stop printing when done sending bytes.
def print_byte_client(enClient):
    then = time.perf_counter()
    this_step = 0
    next_step = 1
    prev_byte = 0
    while enClient.num > enClient.byte:
        time.sleep(enClient.interval)
        rate = rate = (enClient.byte - prev_byte) / enClient.interval
        print(f"[{id(enClient)}  {enClient.ip}:{enClient.port}   {this_step} - "
              f"{next_step}   {enClient.byte}   {enClient.form}        {rate}")
        this_step = this_step + 1
        next_step = next_step + 1
        prev_byte = enClient.byte
    now = time.perf_counter()
    rate = enClient.byte / (now - then)
    print(f"[{id(enClient)}  {enClient.ip}:{enClient.port}   {this_step} - "
          f"{next_step}   {enClient.byte}   {enClient.form}        {rate}")

# stop printing when time is met.
def print_time_client(enClient):
    steps = math.floor(enClient.tid / time)
    prev_bytes = 0
    this_step = 0
    for i in range(steps):
        time.sleep(enClient.interval)
        this_step = enClient.interval * i
        next_step = enClient.interval * (i + 1)
        rate = (enClient.byte - prev_bytes) / enClient.interval
        print(f"[{id(enClient)}  {enClient.ip}:{enClient.port}   {this_step} - "
              f"{next_step}   {enClient.byte}   {enClient.form}        {rate}")
        # set the time between prints.

    rate = enClient.byte / enClient.tid
    print(f"[{id(enClient)}  {enClient.ip}:{enClient.port}   {this_step} - {enClient.tid}   "
          f"{enClient.byte}   {enClient.form}        {rate}")


# creates seperate threads for the clients.
def client():

    # establish n connections acording to -P flag
    for i in range(args.parallel):
        if args.num:
            enCon = NumClient(args.serverip, args.port, args.interval, args.num, 0, args.format)
            th.Thread(target=transfer_byte_client, args=(enCon, )).start()
            th.Thread(target=print_byte_client, args=(enCon, )).start()
        else:
            enCon = TimeClient(args.serverip, args.port, args.interval, args.num, 0, args.format)
            th.Thread(target=transfer_time_client, args=(enCon,)).start()
            th.Thread(target=print_time_client, args=(enCon, )).start()

    # start a print method for the group of connections.
    print(f"{dashes}\nID        Interval        Recieved        Bandwidth")

# if in server mode run server, otherwise run client mode
if args.server:
    server()
else:
    client()
