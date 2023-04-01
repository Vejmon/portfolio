import re
import subprocess
import sys
import argparse
import socket
import threading as th
import ipaddress
import time
import json

# a variable used for building a list of connections on the server side
# nyServer goes high when the expected amount of clients are connected.
# a new instance of EnServer is then buildt, and may start recieving clients.
nyServer = False


# a base class the others are buildt upon, much space isn't saved, I thought there would be more...
class EnCon:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


# a class which holds some information about a connection, a list of clients and if they are done or not, individually
class EnServer(EnCon):
    def __init__(self, ip, port):
        super().__init__(ip, port)
        self.connections = []
        self.is_done = []


# clients default to a timeclient, sending bytes for a time-period.
class TimeClient(EnCon):
    def __init__(self, ip, port, interval, tid, form, parallel, byte):
        super().__init__(ip, port)
        self.interval = interval
        self.tid = tid
        self.form = form
        self.parallel = parallel
        self.byte = byte
        self.is_done = False

    def __str__(self):  # prints a string in JSON formatting representing the client
        return '{"ip": "%s", "port": %s, "interval": %s, "tid": %s, "form": "%s", "parallel": %s}' % \
            (self.ip, self.port, self.interval, self.tid, self.form, self.parallel)

    def get_important(self):  # used for validating that the list of connected clients are equal
        return [self.interval, self.tid, self.form, self.parallel, self.ip]


# num clients override a time client, since the time flag is always set by default.
# a num client doesn't support sending based on time.
class NumClient(EnCon):
    def __init__(self, ip, port, interval, num, form, parallel, byte):
        super().__init__(ip, port)
        self.interval = interval
        self.num = num
        self.byte = byte
        self.form = form
        self.parallel = parallel
        self.is_done = False

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


# returns a dictionary containing arguments
# def args_to_dict(inn):

# check if time input is an integer and more than zero
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
                   help="ipv4 address to connect with")
parse.add_argument('-t', '--time', type=valid_time, default=50, help="time duration to transfer bytes")
parse.add_argument('-i', '--interval', type=valid_time, default=25, help='intervall between prints to consoll')
parse.add_argument('-P', '--parallel', type=int, choices=[1, 2, 3, 4, 5], default=1,
                   help='run client in parallel, max 5 threads')
parse.add_argument('-n', '--num', type=valid_num, required=False, help='amount of bytes to transfer')

dashes = "---------------------------------------------------------------------------------------"

# parse the arguments
args = parse.parse_args()

# an instance of simpleperf may only be server or client
if not (args.server ^ args.client):
    raise AttributeError("you must run either in server or client mode")


# returns the value as true bytes, based on the -f flag.from
# if a user sets -f 'B' -num 9 only 9 bytes should be sent
def how_many_bytes(format, value):
    if format == "B":
        return int(value)
    elif format == "KB":
        return int(value * 1000)
    elif format == "MB":
        return int(value * 1_000_000)
    else:
        # GB
        return int(value * 1_000_000_000)


# formats a byte-per second as a string with two decimals
def returnMbps(value):
    return "%.2fMbps" % (value * 8 / 1_000_000)


# returns a string containing the received/sent bytes with the requested format
def format_bytes(format, value):
    if format == "B":
        return int(value)
    elif format == "KB":
        a = (value / 1000.0)
        return "%.2f%s" % (a, format)
    elif format == "MB":
        a = (value / 1_000_000.0)
        return "%.2f%s" % (a, format)
    else:
        # GB
        a = (value / 1_000_000_000.0)
        return "%.2f%s" % (a, format)


def recieve(con, en_client):
    while not en_client.is_done:
        en_client.byte.append(con.recv(2042))


def transmitt(con, en_client, msg, size):
    while not en_client.is_done:
        con.send(msg)
        en_client.byte += size


# function to handle a single connection from a client
def server_handle_client(con, serveren):
    global nyServer
    # assign remote address and port
    # assign local address and port
    raddr, rport = con.getpeername()
    laddr, lport = con.getsockname()

    print(f"A simpleperf client with address <{raddr}:{rport}> is connected with <{laddr}:{lport}>")

    con.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)

    # recieve a packet containing a client object
    cli_args = json.loads(con.recv(2042).decode())

    # attempt to create numClient, if num flag is set.
    # else make a timeClient.
    try:
        remote_client = NumClient(raddr, rport, cli_args['interval'],
                                  cli_args['num'], cli_args['form'], cli_args['parallel'], [])
    except KeyError:
        remote_client = TimeClient(raddr, rport, cli_args['interval'],
                                   cli_args['tid'], cli_args['form'], cli_args['parallel'], [])

    # append the connection to our server object
    connection_number = len(serveren.connections)
    serveren.connections.append(remote_client)
    serveren.is_done.append(False)
    # start a print session when all are connected. and set up a new server object
    if len(serveren.connections) == remote_client.parallel:
        nyServer = True
        th.Thread(target=server_print, args=(serveren,)).start()

    # start recieving and quit on num limit or time.
    # start print thread

    data = con.recv(2042)
    remote_client.byte.append(data)
    lastChar = data.decode()[-1]
    t = th.Thread(target=recieve, args=(con, remote_client))
    t.start()

    while lastChar != "D":
        time.sleep(2)
        data = remote_client.byte[len(remote_client.byte) - 1].decode()
        lastChar = data[-1]
        print(lastChar)
        if not data:
            # if there is no data, something has gone wrong, and we quit.
            print(f"Connection with {remote_client.ip}:{remote_client.port} has failed!")
            con.close()
            break

    remote_client.is_done = True
    serveren.is_done[connection_number] = True
    time.sleep(0.5)

    data = con.recv(1024).decode()
    remote_client.byte = remote_client.byte + data
    fin = remote_client.byte[-3:]
    if fin == "BYE":
        con.send("ACK:BYE".encode())
        con.shutdown(1)
    else:
        print("what")
    con.close()


# function to handle incomming connections, they are handled in separate threads
def server():
    global nyServer
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
        server = EnServer(args.bind, args.port)
        # accepts a connection and start a thread handling the connection.
        while True:
            # accepts an incoming client and deliver requested document.
            con, addr_info = servsock.accept()
            if nyServer:
                server = EnServer(addr_info[0], addr_info[1])
                nyServer = False
            # start a thread which is deamon, so it quits when main thread quits.
            t = th.Thread(target=server_handle_client, args=(con, server), daemon=True)
            # start the thread
            t.start()


#
def transfer_time_client(enClient, full_list):
    number = len(full_list) - 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:

        cli.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
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
            msg = "wop!" * 250
        then = time.time()
        now = 0

        msg_size = len(msg)
        msg = msg.encode()
        t = th.Thread(target=transmitt, args=(cli, enClient, msg, msg_size))
        t.start()
        while (now - then) < enClient.tid:
            time.sleep(0.7)
        full_list[number] = True
        enClient.is_done = True
        cli.send("D".encode())

        time.sleep(0.5)
        cli.send("BYE".encode())

        ack = cli.recv(1024).decode()
        if ack == "ACK:BYE":
            cli.shutdown(1)
        else:
            print("ack not recieved forsing a close")

        cli.close()


def transfer_byte_client(enClient, full_list):
    number = len(full_list) -1
    # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
        cli.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)

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

        msg_size = len(msg)
        msg = msg.encode()

        cli.send(enClient.__str__().encode())
        treshold = how_many_bytes(enClient.form, enClient.num)
        # allows the server to catch up, before we start our measurements
        time.sleep(0.5)

        for thread in th.enumerate():
            print(thread.name)

        # sends bytes until we reached requested bytes.
        t = th.Thread(target=transmitt, args=(cli, enClient, msg, msg_size))
        t.start()

        while len(enClient.byte) < treshold:
            time.sleep(2)

        full_list[number] = True
        enClient.is_done = True
        # when we are finished, send the code D for done:
        cli.send("D".encode())

        fin = cli.recv(1024).decode()
        if fin == "FIN":
            cli.send("FIN".encode())
            ack = cli.recv(1024)
            if ack == "ACK":
                cli.shutdown(1)
        else:
            print("what")
        cli.close()


# prints until client says claims transfer is done
def server_print(enServer):
    # we first check that all the connections we got are from the same client,
    # I believe I have a bug here, that if two clients open a connection at the exact same time.
    # the list of clients may be a mixed list.
    # if the list has more than one connection
    if len(enServer.connections) > 1:
        for i in range(1, len(enServer.connections)):
            if enServer.connections[i - 1].get_important() != enServer.connections[i].get_important():
                raise TypeError('Mixed set of clients!!!!')
    # I haven't been able to reproduce this bug, but I believe it is there.

    # prints labels
    print(f"{dashes}\n  IP:Port           Interval             Recieved        Bandwidth\n")
    # wait untill we are done recieving bytes.
    start = time.time()
    while not all(enServer.is_done):
        time.sleep(0.1)

    end = time.time()
    time_difference = end - start
    intervall_str = "%.2fs" % time_difference
    # print some information about each connection
    for c in enServer.connections:
        recieved = format_bytes(c.form, len(c.byte))
        rate = returnMbps(len(c.byte) / time_difference)
        print(f"{c.ip}:{c.port}       {0} - {intervall_str}  "
              f"   {recieved}        {rate}")
    print(dashes)


# stop printing when done sending bytes.
def print_byte(clients, full_list, interval):
    # prints labels
    print(f"{dashes}\n  IP:Port           Interval             Sent        Bandwidth\n")

    # start a print method for the group of connections.
    prev_bytes = []
    start = time.time()
    then = time.time()
    now = 0
    prev_step = 0.0
    start = time.time()
    for c in clients:
        prev_bytes.append(0)

    # prints while we are sending, attemps to break cycle when done
    while not all(full_list):
        time.sleep(0.7)
        now = time.time()

        if (now - then) > interval:
            next_step = "%.2f" % (now - start)
            then = time.time()
            for i in range(len(clients)):
                c = clients[i]
                num_bytes = 0
                for j in range(c.byte):
                    num_bytes += len(c.byte[i])

                a_prev_byte = num_bytes - prev_bytes[i]
                prev_bytes[i] = num_bytes
                form_bytes = format_bytes(c.form, num_bytes)
                rate = returnMbps(a_prev_byte / interval)

                print(f"{c.ip}:{c.port}        {prev_step} - {next_step}"
                      f"        {form_bytes}       {rate}")
            prev_step = next_step
        # we need to quit after one run if time and intervall are equal


# stop printing when time is met.
def print_time(clients, tid, interval, full_list):
    # if time interval is bigger than time, we print after time is done.
    # example tid = 4, and interval 50, doesn't make much sense
    if interval > tid:
        interval = tid

    # print labels
    print(f"{dashes}\n IP:Port            Interval           Sent        Bandwidth\n")
    #
    start = time.time()
    then = time.time()
    now = 0
    prev_step = 0.0
    # a list containing how many bytes each client has recieved
    prev_bytes = []
    for c in clients:
        prev_bytes.append(0)

    while not all(full_list):
        time.sleep(0.7)
        now = time.time()

        if (now - then) > interval:
            next_step = "%.2f" % (now - start)
            then = time.time()
            for i in range(len(clients)):
                c = clients[i]
                num_bytes = c.byte
                a_prev_byte = num_bytes - prev_bytes[i]
                prev_bytes[i] = num_bytes
                form_bytes = format_bytes(c.form, num_bytes)
                rate = returnMbps(a_prev_byte / interval)

                print(f"{c.ip}:{c.port}        {prev_step} - {next_step}"
                      f"        {form_bytes}       {rate}")
            prev_step = next_step

    print(f"\n{dashes}")


# creates seperate threads for the clients.
def client():
    # establish n connections acording to -P flag
    clients = []
    full_list = []
    # if num flag is set, overides time flag.
    print(f"{dashes}\nA simpleperf client is attempting to connect with <{args.serverip}:{args.port}>\n{dashes}")
    if args.num:
        for i in range(args.parallel):
            en_con = NumClient(args.serverip, args.port, args.interval, args.num, args.format, args.parallel, 0)
            clients.append(en_con)
            full_list.append(False)
            th.Thread(target=transfer_byte_client, daemon=False, args=(en_con, full_list)).start()
        time.sleep(0.5)
        th.Thread(target=print_byte, args=(clients, full_list, args.interval), daemon=True).start()
    else:
        for i in range(args.parallel):
            en_con = TimeClient(args.serverip, args.port, args.interval, args.time, args.format, args.parallel, 0)
            clients.append(en_con)
            full_list.append(False)
            th.Thread(target=transfer_time_client, daemon=False, args=(en_con, full_list)).start()
        time.sleep(0.5)
        th.Thread(target=print_time, daemon=True, args=(clients, args.time, args.interval, full_list)).start()


# if in server mode run server, otherwise run client mode
if args.server:
    server()
else:
    client()
