import re
import subprocess
import sys
import argparse
import socket
import threading as th
import ipaddress
import time
import json
import math

# a variable used for building a list of connections on the server side
# nyServer goes high when the expected amount of clients are connected.
# a new instance of EnServer is then buildt, and may start recieving clients.
nyServer = False


# a class which holds some information about a connection, a list of clients and if they are done or not, individually
class ConnectedClients:
    def __init__(self, ):
        # defaults to five, but is usually owerwritten
        self.parallel = 5
        self.connections = []

    def set_parallel(self, parallel):
        self.parallel = parallel

    def mixed_clients(self):
        valid_id = self.connections[0].id
        for c in self.connections:
            if c.id != valid_id:
                return True
        return False

    def all_done(self):
        for c in self.connections:
            if not c.is_done:
                return False
        return True

    def all_connected(self):
        if self.parallel == len(self.connections):
            return True
        else:
            return False


# base class for both my types of clients, num and time
class AllClient:
    def __init__(self, ip, port, interval, form, parallel, con):
        self.ip = ip
        self.port = port
        self.interval = interval
        self.form = form
        self.parallel = parallel
        self.is_done = False
        self.byte = 0
        self.prev_bytes = 0
        self.id = ""
        self.con = con
        self.raddr = ""
        self.rport = 0

    def set_remote_address(self, raddr, rport):
        self.raddr = raddr
        self.rport = rport

    def print_connection_statement(self):
        print(f"local: {self.ip}:{self.port} connected with remote: {self.raddr}:{self.rport}")

    def set_socket(self, con):
        self.con = con

    def format_bytes(self, value):
        if self.form == "B":
            return int(value, self.form)
        elif self.form == "KB":
            a = (value / 1000.0)
            return "%.2f%s" % (a, self.form)
        elif self.form == "MB":
            a = (value / 1_000_000.0)
            return "%.2f%s" % (a, self.form)
        else:  # GB
            a = (value / 1_000_000_000.0)
            return "%.2f%s" % (a, self.form)

    def gracefully_close_client(self):
        self.con.send("BYE".encode())
        data = self.con.recv(1024).decode()
        if data == "ACK:BYE":
            self.con.shutdown(1)
            self.con.close()
            return True
        return False

    def gracefully_close_server(self, data):
        if "BYE" in data:
            self.con.send("ACK:BYE".encode())
            self.con.shutdown(1)
            self.con.close()
        else:
            print(f"{self.ip} fant ikke BYE!")
            data = self.con.recv(1024).decode()
            if "BYE" in data:
                self.con.send("ACK:BYE".encode())
                self.con.shutdown(1)
                self.con.close()

    def recieve_bytes(self):
        while not self.is_done:
            # recieve a chunk of data,
            data = self.con.recv(2048)
            # if the there is no information in the chunk, we quit.
            if not data:
                print(f"Connection {self.ip}:{self.port} has failed!")
                sys.exit(1)

            # we add the chunk to the tally
            self.byte = self.byte + len(data)
            # if the last part of a recieved chunk is 'D' for Done we are done recieving.
            if data.decode()[-1] == "D":
                self.is_done = True
                self.gracefully_close_server(data)
                break

    # msg must be bytes sized and size must be an int
    # and be the amount of bytes, we wish to transfer
    def send_bytes(self, msg, size):
        while not self.is_done:
            self.con.send(msg)
            self.byte = self.byte + size

    def intervall_print(self, now, then, start, totals):

        interval_time = now - then
        if totals:
            interval_bytes = self.byte
        else:
            interval_bytes = self.byte - self.prev_bytes

        str_then = "%.2f's'" % (then - start)
        str_now = "%.2f's'" % (now - then)
        str_recieved = self.format_bytes(interval_bytes)
        interval_bytes_ps = "%.2fMbps" % (interval_bytes * 0.000008 / interval_time)

        print(f"{self.ip}:{self.port}       {str_then} - {str_now}  "
              f"   {str_recieved}        {interval_bytes_ps}")
        self.prev_bytes = self.byte

    def server_print(self, now, start):
        interval_time = now - start
        # rate for the total duration of a recieving server. 0.000008 = (mega*bits) = (8/1_000_000)
        interval_bytes_ps = "%.2fMbps" % (self.byte * 0.000008 / interval_time)
        str_now = "%.2f's'" % interval_time
        str_recieved = self.format_bytes(self.byte)

        print(f"{self.ip}:{self.port}       0.00 - {str_now}  "
              f"   {str_recieved}        {interval_bytes_ps}")

    def generate_msg(self):
        if self.form == "B":
            return "w".encode()
        else:
            msg = "wops" * 250
            return msg.encode()

    def set_id(self, id):
        self.id = str(id)


# clients default to a timeclient, sending bytes for a time-period.
class TimeClient(AllClient):
    def __init__(self, ip, port, interval, tid, form, parallel, con):
        super().__init__(ip, port, interval, form, parallel, con)
        self.tid = tid

    def __str__(self):  # prints a string in JSON formatting representing the client
        return '{"ip": "%s", "port": %s, "interval": %s, "tid": %s, "form": "%s", "parallel": %s}' % \
            (self.ip, self.port, self.interval, self.tid, self.form, self.parallel)

    def get_important(self):  # used for validating that the list of connected clients are equal
        return [self.interval, self.tid, self.form, self.parallel, self.ip]

    """def time_finished(self, now, then):
        if (now - then) > self.tid:
            self.is_done = True
            return True
        else:"""


# num clients override a time client, since the time flag is always set by default.
# a num client doesn't support sending based on time.
class NumClient(AllClient):
    def __init__(self, ip, port, interval, num, form, parallel, con):
        super().__init__(ip, port, interval, form, parallel, con)
        self.num = num
        self.treshold = self.how_many_bytes()

    def byte_finished(self):
        if self.byte > self.treshold:
            self.is_done = True

    def how_many_bytes(self):
        if self.form == "B":
            return int(self.num)
        elif self.form == "KB":
            return int(self.num * 1000)
        elif self.form == "MB":
            return int(self.num * 1_000_000)
        else:  # GB
            return int(self.num * 1_000_000_000)

    def __str__(self):  # prints a string in JSON formatting representing the client
        return '{"ip": "%s", "port": %s, "interval": %s, "num": %s, "form": "%s", "parallel": %s}' % \
            (self.ip, self.port, self.interval, self.num, self.form, self.parallel)

    def get_important(self):  # used for validating that the list of connected clients are equal
        return [self.interval, self.num, self.form, self.parallel, self.ip]


# a function to run ifconfig on a node and grab the first ipv4 address we find.
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


# function to validate the ip address given as an argument, validatet with a regex pattern and the ipaddress library.
# if we don't have a valid ip address we terminate the program, and print a fault
def valid_ip(inn):  # ip address must start with 1-3 digits seperated by a dot, repeated three more times.
    # I've decided to use an incomplete regex, "257.0.0.0" for example isn't an ip address but this regex allows them.
    # ipaddress however translates input from the user however eg: ipaddress.ip_address(10) returns 0.0.0.10
    # the task specifies that the ipaddress needs to be in a dotted decimal format, this is now achieved.
    ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_regex.match(inn):
        print(f"an ipaddress needs to be in a dotted decimal format!\n {inn}, is not!")
        sys.exit(1)
    try:
        ip = ipaddress.ip_address(inn)
    except ValueError:
        print(f"{inn} is not a valid ip address.")
        sys.exit(1)
        # ipaddress returns an IPv4Address object, we cast it to string our use
    return str(ip)


# check if port is an integer and between 1024 - 65535
def valid_port(inn):
    # if the input isn't an integer, we complain and quit
    try:
        ut = int(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"port must be an integer, {inn} isn't")
    # if the input isn't within range, we complain and quit
    if not (1024 <= ut <= 65535):
        raise argparse.ArgumentTypeError(f'port number: ({inn}) must be within range [1024 - 65535]')
    return ut


# check if time input is an integer and more than zero
# same as num, I just wanted a different print statement
# and after reading the docs, I'm only allowed to pass one argument to these functions.
def valid_time(inn):
    # if the input isn't an integer we complain and quit
    try:
        ut = int(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"time must be an integer, {inn} isn't")
    # if the input isn't more than zero, we complain and quit
    if ut < 0:
        raise argparse.ArgumentTypeError(f"time must be a positive integer, {inn} isn't")
    return ut


# check if the input is an integer and more than zero
# same as time, I just wanted a different print statement
# and after reading the docs, I'm only allowed to pass one argument to these functions.
def valid_num(inn):
    # if the input isn't an integer we complain and quit
    try:
        ut = int(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"bytes must be an integer, {inn} isn't")
    # if the input isn't more than zero, we complain and quit
    if ut < 0:
        raise argparse.ArgumentTypeError(f"bytes must be a positive integer, {inn} isn't")
    return ut


# start the argument parser
parse = argparse.ArgumentParser(description="optional arguments for simpleperf", epilog='simpleperf --help')

# optional arguments, with long and short name, default values when needed, info for the help page
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
                   help="ipv4 address to connect with")     # bytt tilbake!
parse.add_argument('-t', '--time', type=valid_time, default=50, help="time duration to transfer bytes")
parse.add_argument('-i', '--interval', type=valid_time, default=25, help='intervall between prints to consoll')
parse.add_argument('-P', '--parallel', type=int, choices=[1, 2, 3, 4, 5], default=1,
                   help='run client in parallel, max 5 threads')
parse.add_argument('-n', '--num', type=valid_num, required=False, help='amount of bytes to transfer')

dashes = "------------------------------------------------------------------------------"
client_header = "   IP:Port           Interval           Sent            Bandwidth"
server_header = "   IP:Port           Interval           Received        Bandwidth"

# parse the arguments
args = parse.parse_args()

# an instance of simpleperf may only be server or client
if not (args.server ^ args.client):
    raise AttributeError("you must run either in server or client mode")


def time_client(clients):
    # print a connection statement from each client
    for c in clients.connections:
        c.print_connection_statement()
    # print a header for the transfer of bytes
    print(f"{dashes}\n{client_header}\n")

    # the message should always be 1KB when we are dealing with a TimeClient
    msg = "wops" * 250
    msg_size = 1000
    msg = msg.encode()

    # calculate how many times we need to print
    # having a bigger intervall than the total transmitt time does not make sense

    if args.interval > args.time:
        args.interval = args.time
    loops = math.floor(args.time / args.interval)

    # start a timer and a time for the periods between intervalls
    start = time.time()
    now = time.time()
    then = 0.0
    number_of_prints = 0

    # create individual threads for each connection to send bytes.
    for c in clients.connections:
        th.Thread(target=c.send_bytes, daemon=True, args=(msg, msg_size)).start()

    # periodically check if we are done transmitting
    for i in range(loops):
        time.sleep(args.interval)
        now = time.time()

        for c in clients.connections:
            c.intervall_print(now, then, start, False)
            then = time.time()
    number_of_prints = number_of_prints + 1

    # if we have more than one interval, print a totalsum, for all
    if number_of_prints > 1:
        print(f"{dashes}\nTotals:\n")
        for c in clients.connections:
            c.intervall_print(now, start, start, True)

    # transmitt a D for done
    for c in clients.connections:
        c.con.send("D".encode())

    # allow server to catch up
    time.sleep(0.5)

    # close all the connections
    for c in clients.connections:
        th.Thread(target=c.gracefully_close_client).start()


def num_client(clients):
    # print a connection statement from each client
    for c in clients.connections:
        c.print_connection_statement()
    # print a header for the transfer of bytes
    print(f"{dashes}\n{client_header}\n")
    # calculate the size of the message to be sent
    msg = clients.connections[0].generate_msg()
    msg_size = len(msg)

    # start a timer and a time for the periods between intervalls
    start = time.time()
    now = time.time()
    then = 0.0
    number_of_prints = 0

    # create individual threads for each connection to send bytes.

    for c in clients.connections:
        th.Thread(target=c.send_bytes, daemon=True, args=(msg, msg_size)).start()

    # periodically check if we are done transmitting
    while not clients.all_done():
        now = time.time()
        for c in clients.connections:
            c.byte_finished()
        # if print intervall is met we print a statemnt for each connection
        if (now - start) > args.time:
            for c in clients.connections:
                c.intervall_print(now, then, start, False)
                then = time.time()
        number_of_prints = number_of_prints + 1
        time.sleep(0.3)
    # transmitt a D for done
    for c in clients.connections:
        c.con.send("D".encode())

    # print an end statement for each connection if we have more than one intervall
    if number_of_prints > 1:
        for c in clients.connections:
            c.intervall_print(now, then, start, True)

    # allow server to catch up
    time.sleep(0.5)

    # close all the connections
    for c in clients.connections:
        th.Thread(target=c.gracefully_close_client).start()


def client():
    connected_list = ConnectedClients()
    connected_list.set_parallel(args.parallel)

    # client_sock.settimeout(1)

    # create enough connections.
    while not connected_list.all_connected():
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_sock.connect((args.serverip, args.port))
        except ConnectionError:
            print(f"Connection to {args.serverip}:{args.port} has failed, quitting!")
            sys.exit(1)
        # create a client, and send it to the server.
        # if num flag is set, overrides time.
        if args.num:
            en_client = NumClient(args.serverip, args.port, args.interval,
                                  args.num, args.format, args.parallel, client_sock)
            connected_list.connections.append(en_client)
        else:
            en_client = TimeClient(args.serverip, args.port, args.interval,
                                   args.time, args.format, args.parallel, client_sock)
            connected_list.connections.append(en_client)

        en_client.set_id(id(connected_list))
        client_sock.send(en_client.__str__().encode())

    # lets the server catch up, and be ready to recieve
    time.sleep(0.5)
    if args.num:
        num_client(connected_list)
    else:
        time_client(connected_list)


def server_handle_clients(clients):
    # we first check that all the connections we got are from the same client,
    # I believe I have a bug here, that if two clients open a connection at the exact same time.
    # the list of clients may be a mixed list.
    if clients.mixed_clients():
        print("fatal error, mixed set of connected clients, server shutting down!")
        for c in clients:
            c.con.close()
        sys.exit()

    # print a statement about each connection
    for c in clients.connections:
        c.print_connection_statement()

    # print a header for the recieving of bytes
    print(f"{dashes}\n{server_header}\n")

    start = time.time()
    # start individual threads that recieve bytes from their connection, until they are signaled done, or fail
    for c in clients.connections:
        th.Thread(target=c.recieve_bytes, daemon=True).start()

    # periodically check if we are done recieving bytes.
    while not clients.all_done():
        time.sleep(0.3)
    # stop the clock
    now = time.time()
    # print the calculation from the different connections
    for c in clients.connections:
        c.server_print(start, now)


def server():
    # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servsock:
        # attempt to bind to port, quit if failed.
        try:
            servsock.bind((args.bind, args.port))
        except ConnectionError:
            print(f'bind failed to port: {args.port},  quitting')
            sys.exit(1)

        servsock.listen(65535)
        print(f"{dashes}\n   a simpleperf server is listening on <{args.bind}:{args.port}>\n{dashes}")

        # server = conn(args.bind, args.port)
        # accepts a connection and a ConnectedClients class to handle connected clients.
        connected_clients = ConnectedClients()
        # perpetually recieve a connection, and a client, creates a group of connections and then handles them
        while True:
            # accepts an incoming client and receive info about the connection.
            try:
                con, addr_info = servsock.accept()
            # quit if the user terminates the program
            except KeyboardInterrupt:
                print("interrupt recieved, attempting to shut down")
                servsock.shutdown(1)
                servsock.close()
                sys.exit()
            # quit if the connection fails for some reason
            except ConnectionError:
                print("Connection failed, attempting to shut down")
                servsock.shutdown(1)
                servsock.close()
                sys.exit(1)

            # assign remote address and port
            # assign local address and port
            raddr, rport = con.getpeername()
            laddr, lport = con.getsockname()

            setup = json.loads(con.recv(1024).decode())
            connected_clients.set_parallel(setup['parallel'])

            # create an AllClient from the recieved setup info.
            try:
                remote_client = AllClient(raddr, rport, setup['interval'],
                                          setup['form'], setup['parallel'], con)
            except ValueError:
                print(f"fatal error, couldn't create client from {raddr}:{rport}")
                sys.exit(1)

            # add the connection to the list of connections.
            connected_clients.connections.append(remote_client)

            if connected_clients.all_connected():
                # start a thread which is deamon, so it quits when main thread quits.
                th.Thread(target=server_handle_clients, args=(connected_clients,), daemon=True).start()
                # create a new group
                connected_clients = ConnectedClients()


# if in server mode run server, otherwise run client mode
if args.server:
    server()
else:
    client()
