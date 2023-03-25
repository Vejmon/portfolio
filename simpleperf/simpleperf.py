# import re
import subprocess
import sys
import argparse
import socket
import threading
import threading as th
import ipaddress
import time
import json
import itertools
import math

nyServer = False


class EnCon:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class EnServer(EnCon):
    def __init__(self, ip, port, connections):
        super().__init__(ip, port)
        self.connections = connections


class TimeClient(EnCon):
    def __init__(self, ip, port, interval, tid, form, parallel):
        super().__init__(ip, port)
        self.interval = interval
        self.tid = tid
        self.form = form
        self.parallel = parallel
        self.byte = ""

    def __str__(self):
        return '{"ip": "%s", "port": %s, "interval": %s, "tid": %s, "form": "%s", "parallel": %s}' % \
            (self.ip, self.port, self.interval, self.tid, self.form, self.parallel)


class NumClient(EnCon):
    def __init__(self, ip, port, interval, num, form, parallel):
        super().__init__(ip, port)
        self.interval = interval
        self.num = num
        self.byte = ""
        self.form = form
        self.parallel = parallel

    def __str__(self):
        return '{"ip": "%s", "port": %s, "interval": %s, "num": %s, "form": "%s", "parallel": %s}' % \
            (self.ip, self.port, self.interval, self.num, self.form, self.parallel)


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
parse.add_argument('-t', '--time', type=valid_time, default=3, help="time duration to transfer bytes")
parse.add_argument('-i', '--interval', type=valid_time, default=3, help='intervall between prints to consoll')
parse.add_argument('-P', '--parallel', type=int, choices=[1, 2, 3, 4, 5], default=1,
                   help='run client in parallel, max 5 threads')
parse.add_argument('-n', '--num', type=valid_num, required=False, help='amount of bytes to transfer')

dashes = "-------------------------------------------------------------"

# parse the arguments
args = parse.parse_args()
# print(args)

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


def format_bytes(format, value):
    if format == "B":
        return int(value)
    elif format == "KB":
        a = (value / 1000.0)
        return "%.2f%s" %(a, format)
    elif format == "MB":
        a = (value / 1_000_000.0)
        return "%.2f%s" % (a, format)
    else:
        a =  (value / 1_000_000_000.0)
        return "%.2f%s" % (a, format)


# function to handle a single connection from a client
def server_handle_client(con, serveren):
    global nyServer
    # assign remote address and port
    # assign local address and port
    raddr, rport = con.getpeername()
    laddr, lport = con.getsockname()

    print(f"A simpleperf client with address <{raddr}:{rport}> is connected with <{laddr}:{lport}>")

    # recieve a packet containing a client object
    cli_args = json.loads(con.recv(2042).decode())

    # attempt to create numClient, if num flag is set.
    # else make a timeClient.
    try:
        remote_client = NumClient(raddr, rport, cli_args['interval'],
                                  cli_args['num'], cli_args['form'], cli_args['parallel'])
    except KeyError:
        remote_client = TimeClient(raddr, rport, cli_args['interval'],
                                   cli_args['tid'], cli_args['form'], cli_args['parallel'])

    # append the connection to our server object
    serveren.connections.append(remote_client)
    # start a print session when all are connected. and set up a new server object
    if len(serveren.connections) == remote_client.parallel:
        print("fakk")
        nyServer = True
        if isinstance(remote_client, NumClient):
            th.Thread(target=print_byte, args=(serveren.connections, remote_client.num, remote_client.interval)).start()
        else:
            th.Thread(target=print_time, args=(serveren.connections, remote_client.tid, remote_client.interval)).start()

    # start recieving and quit on num limit or time.
    if isinstance(remote_client, NumClient):
        treshold = how_many_bytes(remote_client.form, remote_client.num)
        while len(remote_client.byte) < treshold:
            msg = con.recv(1024).decode()
            remote_client.byte += msg
    else:
        then = time.perf_counter()
        now = time.perf_counter()
        while (now - then) < remote_client.tid:
            msg = con.recv(1024).decode()
            
            remote_client.byte += msg
            now = time.perf_counter()



# function to handle incomming connections, they are handled in separate threads
def server():
    global nyServer
    # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servsock:
        # attempt to bind to port, quit if failed.
        try:
            servsock.bind((args.bind, args.port))
        except:
            print(f'bind failed to port: {args.port},  quitting')
            sys.exit(1)

        servsock.listen(15)
        print(f"{dashes}\n   a simpleperf server is listening on <{args.bind}:{args.port}>\n{dashes}")
        server = EnServer(args.bind, args.port, [])
        # accepts a connection and start a thread handling the connection.
        while True:
            # accepts an incoming client and deliver requested document.
            con, addr_info = servsock.accept()
            if nyServer:
                server = EnServer(addr_info[0], addr_info[1], [])
                nyServer = False
            # start a thread which is deamon, so it quits when main thread quits.
            t = th.Thread(target=server_handle_client, args=(con, server), daemon=True)
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
        ip, port = cli.getsockname()
        raddr, rport = cli.getpeername()

        print(f"local: {ip}:{port} connected with remote: {raddr}:{rport}")
        cli.send(enClient.__str__().encode())
        time.sleep(0.5)

        if args.format == 'B':
            msg = "w"
        else:
            msg = ("wop!" * 250)

        then = time.perf_counter()
        now = 0
        while (now - then) < enClient.tid:
            cli.send(msg.encode())
            enClient.byte += msg
            now = time.perf_counter()
        cli.shutdown(1)
        cli.detach()



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
        ip, port = cli.getsockname()
        raddr, rport = cli.getpeername()
        # print info
        print(f"local: {ip}:{port} connected with remote: {raddr}:{rport}")

        # build a byte message which is 1000 B aprox 1 KB, unless we are working with single bytes.
        if args.format == 'B':
            msg = "w"
        else:
            msg = ("wop!" * 250)

        treshold = how_many_bytes(enClient.form, enClient.num)
        cli.send(enClient.__str__().encode())
        time.sleep(0.5)
        # sends
        while len(enClient.byte) < treshold:
            cli.send(msg.encode())
            enClient.byte += msg
        cli.shutdown(1)
        cli.detach()


# stop printing when done sending bytes.
def print_byte(clients, byte, interval):
    full_list = []
    for cli in clients:
        full_list.append(False)
    # start a print method for the group of connections.
    print(f"{dashes}\nID        Interval        Recieved        Bandwidth\n")
    while not any(full_list):
        #sleep for the time interval
        time.sleep(interval)
        for i in range(len(clients)):
            c = clients[i]
            this_step = interval * i
            next_step = interval * (i + 1)
            rate = len(c.byte) / (interval * (i + 1))
            form_rate = format_bytes(c.form, rate)
            form_bytes = format_bytes(c.form, len(c.byte))

            if len(clients[i].byte) >= byte:
                full_list[i] = True
            print(f"{c.ip}:{c.port}       {this_step} - {next_step}  "
                  f"   {form_bytes}        {form_rate}")
    print(f"\n{dashes}")

# stop printing when time is met.
def print_time(clients, tid, interval):
    # start a print method for the group of connections.
    print(f"{dashes}\nID        Interval        Recieved        Bandwidth\n")
    then = time.perf_counter()
    now = 0
    this_step = 0
    next_step = 1
    while (now - then) < tid:
        time.sleep(interval)
        for c in clients:
            rate = len(c.byte) / (next_step * interval)
            form_rate = format_bytes(c.form, rate)
            form_bytes = format_bytes(c.form, len(c.byte))
            print(f"{c.ip}:{c.port}        {this_step} - {next_step}"
                  f"        {form_bytes}       {form_rate}")

        this_step = this_step + 1
        next_step = next_step + 1
        now = time.perf_counter()
    print(f"\n{dashes}")

# creates seperate threads for the clients.
def client():
    # establish n connections acording to -P flag
    clients = []
    # if num flag is set, overides time flag.
    if args.num:
        for i in range(args.parallel):
            enCon = NumClient(args.serverip, args.port, args.interval, args.num, args.format, args.parallel)
            clients.append(enCon)
            th.Thread(target=transfer_byte_client, args=(enCon,)).start()
        time.sleep(0.5)
        print_byte(clients, args.byte, args.interval)
    else:
        for i in range(args.parallel):
            enCon = TimeClient(args.serverip, args.port, args.interval, args.time, args.format, args.parallel)
            clients.append(enCon)
            th.Thread(target=transfer_time_client, args=(enCon,)).start()
        time.sleep(0.5)
        print_time(clients, args.time, args.interval)


# if in server mode run server, otherwise run client mode
if args.server:
    server()
else:
    client()
