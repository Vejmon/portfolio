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

# variables used for formatting prints, so that they are all alike.
dashes = "------------------------------------------------------------------------------"
client_header = "   IP:Port           Interval            Sent          Bandwidth"
server_header = "   IP:Port           Interval          Received          Rate"


# a class which holds some information about a group of  connections,
# a list of clients, and how many we expect to recieve.
class ConnectedClients:
    def __init__(self):
        # defaults to five, but is usually owerwritten
        self.parallel = 5
        self.connections = []

    # set how many connections to expect
    def set_parallel(self, parallel):
        self.parallel = parallel

    # check if all connections have same id, a more thorough explanation of this presumed bug in "server_handle_clients"
    def mixed_clients(self):
        valid_id = self.connections[0].id
        for c in self.connections:
            if c.id != valid_id:
                return True
        return False

    # checks if there are any clients are done receiving or sending
    def any_done(self):
        for c in self.connections:
            if c.is_done:
                return True
        return False

    # check if all clients are done, sending or receiving.
    def all_done(self):
        for c in self.connections:
            if not c.is_done:
                return False
        return True

    # check if we are done adding clients to our list.
    def all_connected(self):
        if self.parallel == len(self.connections):
            return True
        else:
            return False


# base class for both my types of clients, num and time
# they inherit alot from this class, but need a few different functions and variables since they behave different
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
        self.treshold = math.inf
        self.time_done = 0.0

    # print a statement to the console regarding a connected client.
    def print_connection_statement(self):
        raddr, rport = self.con.getpeername()
        laddr, lport = self.con.getsockname()

        print(f"local: {laddr}:{lport} connected with remote: {raddr}:{rport}")

    # attempts to disconnect a client from a server,
    # wait's for acknowledgement from the server that we are done sending bytes.
    # if something fails, we pretend the client is done sending bytes. and close the connection
    def gracefully_close_client(self):
        try:
            self.con.send("BYE".encode())
        except ConnectionResetError:
            print(f"Connection to {args.serverip}:{args.port} can't be established, attempting to close")
            self.con.close()
            self.is_done = True
        except BrokenPipeError:
            print(f"Connection to {args.serverip}:{args.port} can't be established, attempting to close")
            self.con.close()
            self.is_done = True

        # attempts to recieve an ack
        data = self.con.recv(1024).decode()
        if data == "ACK:BYE":
            print(f"{data} recieved from {self.ip}:{self.port}, closing socket")
            self.con.close()
        else:
            print("didn't find ACK!, attempting to close")
            self.con.close()

    # is run when a server_client recieves a BYE message. we then respond with an ack and attempt to close the connection.
    def gracefully_close_server(self):
        try:
            self.con.send("ACK:BYE".encode())
        except ConnectionResetError:
            print(f"Connection to {args.serverip}:{args.port} has ended, client can't be reached")
            self.is_done = True
        except BrokenPipeError:
            print(f"Connection to {args.serverip}:{args.port} has ended, client can't be reached")
            self.is_done = True

        self.con.shutdown(1)
        self.con.close()

    # used as a single thread, repeatedly recieve bytes and search for a BYE message from the client, if found we quit.
    def recieve_bytes(self):
        while not self.is_done:
            # recieve a chunk of data,
            data = self.con.recv(2048)
            # if the there is no information in the chunk, we quit.
            if not data:
                self.time_done = time.time()
                self.is_done = True
                print(f"Connection remote: {self.ip}:{self.port} has failed!")
                sys.exit(1)

            # we add the chunk to the tally
            self.byte = self.byte + len(data)
            # search after a BYE statement from the client
            data_decoded = data.decode()

            if "BYE" in data_decoded:
                self.is_done = True
                self.time_done = time.time()
                self.gracefully_close_server()
                break

    # msg must be bytes sized and size must be an int
    # and be the amount of bytes, we wish to transfer
    def send_bytes(self, msg, size):
        while not self.is_done:
            try:
                self.con.send(msg)
            except ConnectionResetError:
                print(f"Connection to {args.serverip}:{args.port} has failed! server has ended")
                self.is_done = True
            except BrokenPipeError:
                print(f"Connection to {args.serverip}:{args.port} has failed! server has ended")
                self.is_done = True
            # increment number of bytes sent
            self.byte = self.byte + size

            # if treshold is met store time and set is_done to true
            if self.byte >= self.treshold:
                self.time_done = time.time()
                self.is_done = True

    # used when a then time can be established, prints how many bytes have been recieved and how fast in the interval
    def intervall_print(self, now, then, start):
        interval_bytes = self.byte - self.prev_bytes
        self.prev_bytes = self.byte
        str_then = "%.2fs" % (then - start)
        str_now = "%.2fs" % (now - start)
        interval_time = now - then
        str_recieved = format_bytes(interval_bytes)
        # 0.000008 is a constant for making a number of bytes into Mb, (8/1_000_000)
        interval_bytes_ps = "%.2fMbps" % ((interval_bytes * 0.000008) / interval_time)

        print(f"{self.ip}:{self.port}       {str_then} - {str_now}  "
              f"   {str_recieved}        {interval_bytes_ps}")

    # used to print a total sum of rate and bytes, start time is also set to be 0.0.
    def server_print(self, now, start):
        interval_time = now - start
        # rate for the total duration of a recieving server or client. 0.000008 = (mega*bits) = (8/1_000_000)
        interval_bytes_ps = "%.2fMbps" % (self.byte * 0.000008 / interval_time)
        str_now = "%.2fs" % interval_time
        str_recieved = format_bytes(self.byte)

        print(f"{self.ip}:{self.port}        0.00s - {str_now}  "
              f"   {str_recieved}        {interval_bytes_ps}")
        self.prev_bytes = self.byte

    # checks if we are to send single bytes at a time, or a group of 1KB
    def generate_msg(self):
        if self.form == "B":
            return "w".encode()
        else:
            msg = "wops" * 250
            return msg.encode()

    # used to set id to a client, so that we may validate that they are all from the same connection.
    def set_id(self, id):
        self.id = str(id)


# clients default to a timeclient, sending bytes for a time-period. this class is mostly depricated at this point.
class TimeClient(AllClient):
    def __init__(self, ip, port, interval, tid, form, parallel, con):
        super().__init__(ip, port, interval, form, parallel, con)
        self.tid = tid

    def __str__(self):  # prints a string in JSON formatting representing the client
        return '{"ip": "%s", "port": %s, "interval": %s, "tid": %s, "form": "%s", "parallel": %s}' % \
            (self.ip, self.port, self.interval, self.tid, self.form, self.parallel)


# num clients override a time client, since the time flag is always set by default.
# a num client doesn't support sending based on time.
class NumClient(AllClient):
    def __init__(self, ip, port, interval, num, form, parallel, con):
        super().__init__(ip, port, interval, form, parallel, con)
        self.num = num
        self.time_done = 0.0
        self.treshold = self.how_many_bytes()

    # converts arguments from the user to an amount of bytes to be sent or recieved.
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


# parse arguments the user may input when running the skript, some are required in a sense, others are optional
def get_args():
    # start the argument parser
    parse = argparse.ArgumentParser(prog="Simpleperf",
                                    description="opens a tcp connection between a host and a server, "
                                                "then stress that connection, written in python",
                                    epilog='simpleperf --help')

    # optional arguments, with long and short name, default values when needed, info for the help page
    parse.add_argument('-s', '--server', action='store_true', help='enables server mode')
    parse.add_argument('-c', '--client', action='store_true', help='enables client mode')
    parse.add_argument('-p', '--port', type=valid_port, default=8088, help="which port to bind/open")
    parse.add_argument('-f', '--format', choices=['B', 'KB', 'MB', 'GB'],
                       type=str, default='MB', help="format output with SI prefix, and set num threshold")

    # server arguments ignored if running a server
    parse.add_argument('-b', '--bind', type=valid_ip, default=get_ip(),  # attempts to grab ip from ifconfig
                       help="ipv4 adress to bind server to, default binds to local address")

    # client arguments ignored if running a client
    parse.add_argument('-I', '--serverip', type=valid_ip, default="10.0.0.2",  # default value is set to node h1
                       help="ipv4 address to connect with, default connects with node h1")
    parse.add_argument('-t', '--time', type=valid_time, default=25, help="time duration to transfer bytes")
    parse.add_argument('-i', '--interval', type=valid_time, default=25, help='time interval between prints to console')
    parse.add_argument('-P', '--parallel', type=int, choices=[1, 2, 3, 4, 5], default=1,
                       help='run client in parallel, max 5 threads')
    parse.add_argument('-n', '--num', type=valid_num, required=False,
                       help='amount of bytes to transfer, takes format flag into account')

    # parse the arguments
    return parse.parse_args()


args = get_args()

# an instance of simpleperf may only be server or client, this functions as an xor operator
if not (args.server ^ args.client):
    raise AttributeError("you must run either in server or client mode")

# takes the -f flag into account when transforming a number of bytes into desired formating.
def format_bytes(value):
    if args.format == "B":
        return "%s%s" % (value, args.format)
    elif args.format == "KB":
        a = (value / 1000.0)
        return "%.2f%s" % (a, args.format)
    elif args.format == "MB":
        a = (value / 1_000_000.0)
        return "%.2f%s" % (a, args.format)
    else:  # GB
        a = (value / 1_000_000_000.0)
        return "%.2f%s" % (a, args.format)

# clients is a ConnectedClients class, this function is used to handle a group of parallel connections.
# we start a clock, and start sending bytes to a server.
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

    if args.interval > args.time:
        args.interval = args.time

    # start a timer and a time for the periods between intervalls
    start = time.time()
    now = start
    then = start
    first_print = True

    # create individual threads for each connection to send bytes.
    for c in clients.connections:
        th.Thread(target=c.send_bytes, daemon=True, args=(msg, msg_size)).start()

    # periodically check if we are done transmitting
    while (now - start) < args.time and not clients.all_done():

        if (now - then) > args.interval:
            if first_print:
                for c in clients.connections:
                    c.server_print(now, start)
            else:
                for c in clients.connections:
                    c.intervall_print(now, then, start)
            first_print = False
            then = time.time()
            print("--")

        time.sleep(0.1)
        now = time.time()


    for c in clients.connections:
        # stop sending bytes.
        c.is_done = True
        # send a bye message to server to let it know we are done.
        th.Thread(target=c.gracefully_close_client).start()

    # print either the last intervall, or the first.
    for c in clients.connections:
        c.intervall_print(now, then, start)

    if not first_print:
        # print a total sum for all clients if we have printed more than once, making the statement more human-readable.
        print(f"{dashes}\nTotals:")
        for c in clients.connections:
            c.server_print(now, start)


# if num flag is set, we are to send a number of bytes.
# this  is handled in this function, clients is a ConnectedClients class, containing a list of connections.
def num_client(clients):
    # calculate the size of the message to be sent
    # depends on the -f flag, if program is invoked with -n 7 and -f 9, then we are only to send 9 bytes.
    # we then need to send only 1 byte at a time.
    msg = clients.connections[0].generate_msg()
    msg_size = len(msg)

    # check the time, and store it for now.
    start = time.time()
    now = start
    then = start
    #
    first_print = True

    for c in clients.connections:
        # print a connection statement from each client
        c.print_connection_statement()
        # create individual threads for each connection to send bytes.
        th.Thread(target=c.send_bytes, daemon=True, args=(msg, msg_size)).start()

    # print a header for the transfer of bytes
    print(f"{dashes}\n{client_header}\n")

    # periodically check if we are done transmitting
    # since we are sending a number of bytes, the threads in c.send_bytes() handles if they are done or not.
    while not clients.all_done():

        # store time, if transmission isn't done
        now = time.time()
        for c in clients.connections:
            if not c.is_done:
                c.time_done = now

        # if print intervall is met we print a statement for each connection
        if (now - then) > args.interval:
            for c in clients.connections:
                if first_print:
                    if not c.is_done:
                        c.server_print(c.time_done, then)
                else:
                    if not c.is_done:
                        c.intervall_print(c.time_done, then, start)
            print("--")  # used to group together prints making the statement more readable
            first_print = False
            then = time.time()

        # let the client focus on sending bytes for a bit.
        time.sleep(0.1)

    for c in clients.connections:
        c.intervall_print(c.time_done, then, start)

    # print total sum for all clients, if we have more than one print.
    if not first_print:
        print(f"{dashes}\nTotals:\n")
        for c in clients.connections:
            c.server_print(c.time_done, start)

    # attempt to close connection
    for c in clients.connections:
        th.Thread(target=c.gracefully_close_client).start()


# used to create either NumClients or TimeClients and add them to a group of connections.
# when we are done creating a socket connection, and we are done transmitting the info,
# we either start sending bytes with a time constraint or a number of bytes constraint.
def client():
    # create a list of connected clients, in a ConnectClients class.
    connected_list = ConnectedClients()
    # add info about how many clients we are to expect.
    connected_list.set_parallel(args.parallel)

    # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    # and loop until we have created enough clients and connections.
    while not connected_list.all_connected():
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_sock.connect((args.serverip, args.port))
        except ConnectionError:
            print(f"Connection to {args.serverip}:{args.port} has failed, quitting!")
            sys.exit(1)

        # create a client, and send it to the server.
        laddr, lport = client_sock.getsockname()

        # if num flag is set we create a NumClient, otherwise we make a TimeClient.
        # since the timeflag is set by default. we then add the client to our list of clients.
        if args.num:
            en_client = NumClient(laddr, lport, args.interval,
                                  args.num, args.format, args.parallel, client_sock)
            connected_list.connections.append(en_client)
        else:
            en_client = TimeClient(laddr, lport, args.interval,
                                   args.time, args.format, args.parallel, client_sock)
            connected_list.connections.append(en_client)

        # to catch if all connection are from the same client I've added this id variable,
        # read more below in server_handle_clients
        en_client.set_id(id(connected_list))

        # let server know som info about our client
        client_sock.send(en_client.__str__().encode())

    # start a transmission with either time constraint or bytes.
    if args.num:
        num_client(connected_list)
    else:
        time_client(connected_list)


# clients is a ConnectedClients class.
# this function is used to start threads which shall receive bytes until a "BYE" is received.
# we also wanẗ to do some generall checkups of how the transmission is going and if all connections fail,
# we print what we got and exit.
def server_handle_clients(clients):
    # we first check that all the connections we got are from the same client,
    # I believe I have a bug here, that if two clients open a connection at the exact same time.
    # the list of clients may be a mixed list. I haven't been able to recreate this bug, but I believe it's there.
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

    # check the time and store it in a variable
    start = time.time()
    # start individual threads that recieve bytes from their connection, until they are signaled done, or fail
    for c in clients.connections:
        th.Thread(target=c.recieve_bytes, daemon=True).start()

    # periodically check if we are done recieving bytes.
    while not clients.all_done():
        time.sleep(0.1)

    # print the total calculation from the different connections
    for c in clients.connections:
        c.server_print(c.time_done, start)


# sets up basic functionality of a server using socket, starts recieving and putting client connections into groups.
# then starts a thread to handle a group of connected clients.
def server():
    # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servsock:
        # attempt to bind to port, quit if failed.
        try:
            servsock.bind((args.bind, args.port))
        except ConnectionError:
            print(f'bind failed to port: {args.port},  quitting')
            sys.exit(1)

        # makes servsock a listening connection, ready to accept incoming client connections.
        servsock.listen()
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
                print("keyboard interrupt recieved, attempting to shut down")
                servsock.close()
                sys.exit(1)
            # quit if the connection fails for some reason
            except ConnectionError:
                print("Connection failed, attempting to shut down")
                servsock.close()
                sys.exit(1)

            # assign remote address and port
            raddr, rport = con.getpeername()

            # recieve a json object containing information about the clients attempting to connect to our server.
            setup = json.loads(con.recv(1024).decode())
            # grab the parallel variable from the clients.
            connected_clients.set_parallel(setup['parallel'])

            # create an AllClient from the recieved setup info.
            # since we don't care on the server side wether the constraint is number of bytes, or time.
            try:
                remote_client = AllClient(raddr, rport, setup['interval'],
                                          setup['form'], setup['parallel'], con)
            except ValueError:
                print(f"fatal error, couldn't create client from {raddr}:{rport}")
                sys.exit(1)

            # add the connection to the list of connections.
            connected_clients.connections.append(remote_client)
            # if the list is full, we start a new one, ready to recieve a new batch of connections.
            # we also start a thread to handle the connections we just recieved.
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
