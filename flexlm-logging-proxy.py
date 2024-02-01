#!/usr/bin/env python
#
# Runs a MitM TCP proxy that intercepts FLEXlm communications and
# logs the combination of the FLEXlm user:hostname:display:pid and
# the client's IP address and TCP port.
#
# Can optionally proxy BOTH the lmgrd and vendor daemon.  Originally
# the idea was that we could rewrite the initial lmgrd reply which
# specifies the vendor hostname and TCP port to direct the client to
# this proxy instead of the vendor daemon itself.  Turns out that
# reply includes a proprietary checksum that prevents us from editing
# the content.
#


import socket
import asyncio
import argparse
import logging
import sys, errno


def hexdump(data, length=16):
    """Mimic the hexdump utility and display binary data as an indexed sequence of bytes and corresponding ASCII characters.  Writes to the info level of the default logger."""
    filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    digits = 4 if isinstance(data, str) else 2
    for c in range(0, len(data), length):
        chars = data[c:c+length]
        hex = ' '.join(["%0*x" % (digits, (x)) for x in chars])
        printable = ''.join(["%s" % (((x) <= 127 and filter[(x)]) or '.') for x in chars])
        logging.debug("%04x  %-*s  %s", c, length*3, hex, printable)



async def forward_proxy_pipe(rstream, wstream):
    """Accepts data written to this proxy by the client (on rstream) and forwards to the actual license server (on wstream).  The first packet is decoded and client information is logged."""
    try:
        # The first packet is the one we want to take a peek at:
        in_data = await rstream.read(0x93)
        
        # Expected initial packet is 0x93 (147) bytes long:
        #   00000000  68 01 31 33 66 72 65 79  00 00 00 00 00 00 00 00  |h.13frey........|
        #   00000010  00 00 00 00 00 00 00 00  00 6c 6f 67 69 6e 30 31  |.........login01|
        #   00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        #   00000030  00 00 00 00 00 00 00 00  00 00 4d 4c 4d 00 00 00  |..........MLM...|
        #   00000040  00 00 00 00 00 2f 64 65  76 2f 70 74 73 2f 36 32  |...../dev/pts/62|
        #   00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        #   00000060  00 00 00 00 00 00 54 00  00 00 00 00 00 00 00 00  |......T.........|
        #   00000070  00 00 00 36 32 35 30 00  00 00 00 00 00 00 78 36  |...6250.......x6|
        #   00000080  34 5f 6c 73 62 00 00 00  00 00 00 0b 12 37 38 00  |4_lsb........78.|
        #   00000090  31 34 00                                          |14.|
        remote_user = in_data[4:25].decode('utf-8', 'ignore')
        remote_host = in_data[25:58].decode('utf-8', 'ignore')
        remote_display = in_data[69:102].decode('utf-8', 'ignore')
        remote_pid = in_data[115:126].decode('utf-8', 'ignore')
        remote = rstream._transport.get_extra_info('peername')
        hexdump(in_data)
        logging.info('[{:s}:{:d}] {:s}|{:s}|{:s}|{:s}'.format(remote[0], remote[1], remote_user, remote_host, remote_display, remote_pid))
        
        wstream.write(in_data)
        while not rstream.at_eof():
            in_data = await rstream.read(4096)
            wstream.write(in_data)
    finally:
        wstream.close()
    
    
async def lmgrd_reverse_proxy_pipe(rstream, wstream):
    """Accepts data written to this proxy by the actual license server (on rstream) and forwards to the client (on wstream).  The first packet is decoded and vendor daemon information is logged.  Note that this is where we would have rewritten that packet to send the client to an alternate port."""
    global vendor_proxy
    
    try:
        # The first packet is the one we want to take a peek at:
        in_data = await rstream.read(0x35)
        
        # Expected initial packet is 0x35 (53) bytes long:
        #   00000000  2f 25 12 5a 00 35 01 13  00 00 00 00 41 00 00 00  |/%.Z.5......A...|
        #   00000010  00 00 00 00 6d 61 74 68  77 6f 72 6b 73 2e 6c 6d  |....mathworks.lm|
        #   00000020  2e 75 64 65 6c 2e 65 64  75 00 00 00 9c 40 00 00  |.udel.edu....@..|
        #   00000030  00 00 00 54 44                                    |...TD|
        server_host = in_data[0x14:0x2a].decode('utf-8', 'ignore')
        server_port = int.from_bytes(in_data[0x2a:0x2e], byteorder='big', signed=False)
        remote = wstream._transport.get_extra_info('peername')
        hexdump(in_data)
        logging.info('[{:s}:{:d}] lmgrd reply {:s}:{:d}'.format(remote[0], remote[1], server_host, server_port))
        
        wstream.write(in_data)
        while not rstream.at_eof():
            in_data = await rstream.read(4096)
            hexdump(in_data)
            wstream.write(in_data)
    finally:
        wstream.close()


async def reverse_proxy_pipe(rstream, wstream):
    """Accepts data written to this proxy by the actual license server (on rstream) and forwards to the client (on wstream)."""
    try:
        while not rstream.at_eof():
            in_data = await rstream.read(4096)
            hexdump(in_data)
            wstream.write(in_data)
    finally:
        wstream.close()
        
    
async def proxy_lmgrd(local_rstream, local_wstream):
    """Handles connections made to the lmgrd proxy port.  Connects to the actual license server lmgrd and sets up bi-directional forwarding of data between the client and it."""
    global lmgrd_proxy
    
    remote = local_rstream._transport.get_extra_info('peername')
    logging.debug('[{:s}:{:d}] lmgrd connection open'.format(remote[0], remote[1]))
    try:
        # Connect to the actual license server:
        remote_rstream, remote_wstream = await asyncio.open_connection(host=lmgrd_proxy[1][0], port=lmgrd_proxy[1][1])
        
        # Setup the data-forwarding callbacks:
        pipe1 = forward_proxy_pipe(local_rstream, remote_wstream)
        pipe2 = lmgrd_reverse_proxy_pipe(remote_rstream, local_wstream)
        await asyncio.gather(pipe1, pipe2)
    finally:
        local_wstream.close()
    logging.debug('[{:s}:{:d}] lmgrd connection closed'.format(remote[0], remote[1]))
        
    
async def proxy_vendor(local_rstream, local_wstream):
    """Handles connections made to the vendor proxy port.  Connects to the actual license server vendor daemon and sets up bi-directional forwarding of data between the client and it."""
    global vendor_proxy
    
    remote = local_rstream._transport.get_extra_info('peername')
    logging.debug('[{:s}:{:d}] vendor daemon connection open'.format(remote[0], remote[1]))
    try:
        # Connect to the actual license server:
        remote_rstream, remote_wstream = await asyncio.open_connection(host=vendor_proxy[1][0], port=vendor_proxy[1][1])
        
        # Setup the data-forwarding callbacks:
        pipe1 = forward_proxy_pipe(local_rstream, remote_wstream)
        pipe2 = reverse_proxy_pipe(remote_rstream, local_wstream)
        await asyncio.gather(pipe1, pipe2)
    finally:
        local_wstream.close()
    logging.debug('[{:s}:{:d}] vendor connection closed'.format(remote[0], remote[1]))



cli_parser = argparse.ArgumentParser(description='FLEXlm logging proxy')
cli_parser.add_argument('-v', '--verbose',
        dest='is_verbose',
        default=False,
        action='store_true',
        help='Increase the amount of information logged by the proxy')
cli_parser.add_argument('-b', '--bind-host', metavar='<hostname>|<ip-address>',
        dest='bind_host',
        default=None,
        help='Bind proxy listening ports to this host/IP address.  By default the proxy is bound to all local interfaces.')
cli_parser.add_argument('-l', '--lmgrd', metavar='<port>:<host>:<port>',
        dest='lmgrd',
        required=True,
        help='The local TCP port, remote hostname, and remote TCP port of the FLEXlm base daemon (lmgrd) proxy')
cli_parser.add_argument('-V', '--vendor', metavar='<port>:<host>:<port>',
        dest='vendor',
        nargs='?',
        help='The local TCP port, remote hostname, and remote TCP port of the FLEXlm vendor daemon proxy')

cli_args = cli_parser.parse_args()

logging.basicConfig(
        format='[%(asctime)s] %(message)s',
        datefmt='%Y%m%dT%H%M%S%z',
        level=(logging.DEBUG if cli_args.is_verbose else logging.INFO))

# Validate and configure the FLEXlm daemon:
port_and_target = cli_args.lmgrd.split(':')
if len(port_and_target) != 3:
    logging.error('Invalid FLEXlm lmgrd argument: %s', cli_args.lmgrd)
    sys.exit(errno.EINVAL)
lmgrd_proxy = ((cli_args.bind_host, int(port_and_target[0])), (port_and_target[1], int(port_and_target[2])))

# Validate and configure the vendor daemon:
if cli_args.vendor:
    port_and_target = cli_args.vendor.split(':')
    if len(port_and_target) != 3:
        logging.error('Invalid FLEXlm vendor argument: %s', cli_args.vendor)
        sys.exit(errno.EINVAL)
    vendor_proxy = ((cli_args.bind_host, int(port_and_target[0])), (port_and_target[1], int(port_and_target[2])))
else:
    vendor_proxy = None

# Schedule the servers on the main event loop:
eloop = asyncio.get_event_loop()

servers = []

# The base port lmgrd server:
lmgrd_coroutine = asyncio.start_server(proxy_lmgrd, host=lmgrd_proxy[0][0], port=lmgrd_proxy[0][1])
logging.info('lmgrd proxy created for %s:%d => %s:%d', lmgrd_proxy[0][0] if lmgrd_proxy[0][0] else '', lmgrd_proxy[0][1], lmgrd_proxy[1][0], lmgrd_proxy[1][1])
servers.append(eloop.run_until_complete(lmgrd_coroutine))
logging.info('lmgrd proxy registered with runloop')

if vendor_proxy:
    # The vendor daemon port server:
    vendor_coroutine = asyncio.start_server(proxy_vendor, host=vendor_proxy[0][0], port=vendor_proxy[0][1])
    logging.info('vendor proxy created for %s:%d => %s:%d', vendor_proxy[0][0] if vendor_proxy[0][0] else '', vendor_proxy[0][1], vendor_proxy[1][0], vendor_proxy[1][1])
    servers.append(eloop.run_until_complete(vendor_coroutine))
    logging.info('vendor proxy registered with runloop')

# Yield to the main event loop, exit on Ctrl-C:
try:
    logging.info('entering runloop')
    eloop.run_forever()
except KeyboardInterrupt:
    pass
logging.info('exited runloop')

# Close server listening ports:
logging.info('closing all servers')
for server in servers:
    server.close()
    
# Yield to the main event loop until all open connections are cleaned-up:
logging.info('completing cleanup of all servers')
for server in servers:
    eloop.run_until_complete(server.wait_closed())
eloop.close()
