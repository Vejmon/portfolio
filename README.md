simpleperf must be run as a server and a client.

simepleperf can be run together with some arguments.

use either -c, '--client' or -s, '--server' to specify, one must be set.

when in server mode:

    -p, --port, sets which port to bind server to, connecting clients must attempt to connect with the same port.
        DEFAULT: 8088
    -f, --format, specify which SI prefix used when printing the amount of received bytes on the server.
        DEFAULT: MB
    -b, --bind, set which ipv4 address to bind server to, must be dotted decimal format: 3.3.3.3
        DEFAULT: attempts to grab a local ip from ifconfig.

when in client mode:

    -p, --port, set which port to attempt to connect with
        DEFAULT: 8088
    -I, --serverip, set which ipv4 address to connect with, must be dotted decimal format: 3.3.3.3
        DEFAULT: 10.0.0.2 (node h1)
    -t, --time, set the total amount in seconds, where the client is to transfer bytes to a server.
        DEFAULT: 25
    -i, -interval, set time in seconds between prints to console
        DEFAULT: 25
    -n, --num, specify total amount of bytes to transfer to a server, may only be an integer. used in conjunction with -f, --format flag.
        DEFAULT: NONE
    -f, --format, set SI prefix for prints, and also threshold when -n, --num flag is set.
        DEFAULT: MB
    -P, --parallel, open up to five parallel connections, to the same server.
        DEFAULT: 1
