simpleperf is a tool used to measure total bandwith between to nodes on a network.
to connect two nodes, one must be running a server version of this program, and the other a client. 

simpleperf opens a tcp connection and ipv4 is used for addressing between the hosts.
both the server and client will print statements about the transferring if bytes between them.

use either -c, '--client' or -s, '--server' to specify, one must be set, although they are marked as optional.

when in server mode:

    -p, --port, sets which port to bind server to, connecting clients must attempt to connect with the same port.
        DEFAULT: 8088
    -f, --format, specify which SI prefix used when printing the amount of received bytes on the server.
        DEFAULT: MB
    -b, --bind, set which ipv4 address to bind server to, must be dotted decimal format: 3.3.3.3
        DEFAULT: attempts to grab a local ip from ifconfig.
the remote address is used when printing to console in order to keep tabs of which connection is which when running parallel connections.

when in client mode:

    -p, --port, set which port to attempt to connect with
        DEFAULT: 8088
    -I, --serverip, set which ipv4 address to connect with, must be dotted decimal format: 3.3.3.3
        DEFAULT: 10.0.0.2 (node h1)
    -t, --time, set the total amount in seconds, where the client is to transfer bytes to a server.
        DEFAULT: 25
    -i, -interval, set time in seconds between prints to console
        DEFAULT: 25
    -n, --num, specify total amount of bytes to transfer to a server, may only be an integer.
        used in conjunction with -f, --format flag.
        DEFAULT: NONE
    -f, --format, set SI prefix for prints, and also threshold when -n, --num flag is set.
        DEFAULT: MB
    -P, --parallel, open up to five parallel connections, to the same server.
        DEFAULT: 1
the local address is used when printing to console in order to keep tabs of which connection is which when running parallel connections.

examples:

    simpleperf.py -c -n 10 -P 3
    starts three parallel connections which will transmitt 10MB each to a server on node h1.
    will print to console every 25 seconds.
    
    simpleper.py -s -f KB -p 12202
    run a simpleperf server on port 12202 with the first ip in ifconfig, format prints with KB.

    simpleperf.py -c -t 90 -i 3 -I 10.0.7.2 -p 12202 
    start a connection with node h9 on port 12202, and transmitt bytes for 90 secnods, 
    will print to console every three seconds

    simpleperf.py -n 120 -f B -c
    starts a connection with node h1, and transmitt 120 bytes to it.

python libraries used:

    re                          subprocess
    sys                         argparse
    socket                      threading
    ipaddress                   time
    json                        math

I've also decided that the print statement on both client and serverside is using the client's ip-port pair,
so that keeping tabs about which parallel connections throughput is which might be easier