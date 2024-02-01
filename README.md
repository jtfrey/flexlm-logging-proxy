# flexlm-logging-proxy

FLEXlm license daemons log client identification that includes:

- Client machine's hostname
- Client user id on client's machine
- Client machine's display identifier
- Client process id on client's machine

On all architectures the machine's hostname will often be an arbitrary string, not necessarily the DNS name.  Likewise, the user id for a person on one machine may not be the same on any other machine.

The IP address of the client machine would be a very useful item to log, but FLEXlm does not include it.  A _report log_ feature is present that prompts the vendor daemon to emit an encrypted binary log file that reportedly includes the IP addresses, but as it is encrypted and the algorithm/key are unknown it is of no use.

Inserting a TCP proxy between the client machine and the FLEXlm daemon would intercept the connection from the client and be able to log the client's IP address; if the other client identifying information could be intercepted then a connection between the FLEXlm logging and IP addresses could be established.  As it happens, the initial data packet sent by the FLEXlm TCP client includes all that information.

## Vendor daemon proxy

The vendor daemon proxy is present because we initially wanted to intercept the FLEXlm daemon's reply

```
0000  2f 25 12 5a 00 35 01 13 00 00 00 00 41 00 00 00   /%.Z.5......A...
0010  00 00 00 00 6d 61 74 68 77 6f 72 6b 73 2e 6c 6d   ....mathworks.lm
0020  2e 75 64 65 6c 2e 65 64 75 00 00 00 9c 40 00 00   .udel.edu....@..
0030  00 00 00 54 44                                    ...TD
```

and rewrite it to direct the client to connect to our proxy rather than the port on which the vendor daemon itself is listening.  By collecting replies from various FLEXlm servers, that packet appears to consist of:

- [4 bytes] a checksum
- [2 bytes] packet size in bytes (16-bit BE integer)
- [14 bytes] unknown and variable in content
- [N+1 bytes] hostname on which vendor daemon is running, with NUL-terminator
- [4 bytes] TCP port on which vendor daemon is listening (32-bit BE integer)
- [7 bytes] common footer

When the proxy altered the hostname and TCP port but preserved all other fields, the client would discard the reply, close the connection, and try again.  The algorithm and initial data used in computing the checksum is unknown, so there is no way for the proxy to rewrite the reply so that the vendor daemon can be proxied.

It should be possible to run the FLEXlm lmgrd and vendor daemons in a container and map the in-container TCP ports to alternative ports in the host namespace.  This would allow this proxy to run on port :40000 on the server, forwarding to :40001 which is then connected to :40000 in the container namespace.  Since the hostname and port would be the same for both the proxy and the vendor daemon, no alteration of the reply packet is necessary.


## Usage

The proxy script includes built-in help:

```
$ python3 flexlm-logging-proxy.py --help
usage: flexlm-logging-proxy.py [-h] [-v] [-b <hostname>|<ip-address>] -l
                               <port>:<host>:<port>
                               [-V [<port>:<host>:<port>]]

FLEXlm logging proxy

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Increase the amount of information logged by the proxy
  -b <hostname>|<ip-address>, --bind-host <hostname>|<ip-address>
                        Bind proxy listening ports to this host/IP address. By
                        default the proxy is bound to all local interfaces.
  -l <port>:<host>:<port>, --lmgrd <port>:<host>:<port>
                        The local TCP port, remote hostname, and remote TCP
                        port of the FLEXlm base daemon (lmgrd) proxy
  -V [<port>:<host>:<port>], --vendor [<port>:<host>:<port>]
                        The local TCP port, remote hostname, and remote TCP
                        port of the FLEXlm vendor daemon proxy
```

The `--lmgrd` option is mandatory, but the `--vendor` is optional — if not provided, no vendor daemon proxy will be run.


### Example

Here we will proxy access to our campus Matlab server to intercept and log the IP and client idenfication information.

```
$ python3 flexlm-logging-proxy.py --lmgrd 1726:matlab.lm.udel.edu:1726 --verbose
[20240201T145924-0500] Using selector: EpollSelector
[20240201T145924-0500] lmgrd proxy created for :1726 => matlab.lm.udel.edu:1726
[20240201T145924-0500] lmgrd proxy registered with runloop
[20240201T145924-0500] entering runloop
[20240201T145954-0500] [127.0.0.1:52274] lmgrd connection open
[20240201T145954-0500] 0000  68 38 31 33 66 72 65 79 00 00 00 00 00 00 00 00   h813frey........
[20240201T145954-0500] 0010  00 00 00 00 00 00 00 00 00 6c 6f 67 69 6e 30 31   .........login01
[20240201T145954-0500] 0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
[20240201T145954-0500] 0030  00 00 00 00 00 00 00 00 00 00 4d 4c 4d 00 00 00   ..........MLM...
[20240201T145954-0500] 0040  00 00 00 00 00 2f 64 65 76 2f 70 74 73 2f 37 33   ...../dev/pts/73
[20240201T145954-0500] 0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
[20240201T145954-0500] 0060  00 00 00 00 00 00 54 00 00 00 00 00 00 00 00 00   ......T.........
[20240201T145954-0500] 0070  00 00 00 33 35 31 37 34 00 00 00 00 00 00 78 36   ...35174......x6
[20240201T145954-0500] 0080  34 5f 6c 73 62 00 00 00 00 00 00 0b 10 37 38 00   4_lsb........78.
[20240201T145954-0500] 0090  31 34 00                                          14.
[20240201T145954-0500] [127.0.0.1:52274] frey|login01|/dev/pts/73|35174
[20240201T145954-0500] 0000  2f 25 12 5a 00 35 01 13 00 00 00 00 41 00 00 00   /%.Z.5......A...
[20240201T145954-0500] 0010  00 00 00 00 6d 61 74 68 77 6f 72 6b 73 2e 6c 6d   ....mathworks.lm
[20240201T145954-0500] 0020  2e 75 64 65 6c 2e 65 64 75 00 00 00 9c 40 00 00   .udel.edu....@..
[20240201T145954-0500] 0030  00 00 00 54 44                                    ...TD
[20240201T145954-0500] [127.0.0.1:52274] lmgrd reply mathworks.lm.udel.edu:40000
[20240201T145954-0500] [127.0.0.1:52274] lmgrd connection closed
```

In verbose mode, a hex dump of the initial client packet and the reply from the license server will be logged.  Without that flag, the output would have looked like:

```
$ python3 flexlm-logging-proxy.py --lmgrd 1726:matlab.lm.udel.edu:1726
[20240201T145924-0500] lmgrd proxy created for :1726 => matlab.lm.udel.edu:1726
[20240201T145924-0500] lmgrd proxy registered with runloop
[20240201T145924-0500] entering runloop
[20240201T145954-0500] [127.0.0.1:52274] frey|login01|/dev/pts/73|35174
[20240201T145954-0500] [127.0.0.1:52274] lmgrd reply mathworks.lm.udel.edu:40000
```

The most important line is the second to last:  the client IP and port are logged with the four FLEXlm client identifiers that will be present in the FLEXlm log files.
