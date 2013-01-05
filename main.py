# -*- coding: utf-8 -*-
"""main.py

Main function that control the whole program.

This program is quite easy so that I don't need to use any special
techniques. Plain serial coding is enough.

This program accept arguments for detailed controlling.

"""

import socket
import argparse

def init_argparse():
	parse = argparse.ArgumentParser(description="Python traceroute.", 
		prog='python_traceroute', epilog="This traceroute will only\
		use UDP to probe. ICMP or TCP SYN are not implemented here.")
	parse.add_argument('-m', metavar='max_ttl', default=30, type=int,
		help="Maximum number of hops (max time-to-live value). The\
		default is 30.")
	parse.add_argument('-p', metavar='port', default=33434, type=int,
		help="For UDP tracing, specifies the destination port.")
	parse.add_argument('-w', metavar='waittime', default=5, type=int,
		help="Set the time (in seconds) to wait for a response to a\
		probe (default 5.0 sec).")
	parse.add_argument('-f', metavar='first_ttl', default=1, type=int,
		help="Specifies with what TTL to start. Defaults to 1")
	
	return parse.parse_args()

def main(dest_name):
	args = init_argparse()
	args = vars(args)

	# Default port is 33434.
	port = args['p'] 
	# Default max hops (TTL) is 30.
	max_hops = args['m']
	# Default begin ttl is 1.
	ttl = args['f']

	dest_addr = socket.gethostbyname(dest_name)

	# Infinite loop until reach destination or TTL reach maximum.
	while True:
		recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
			socket.IPPROTO_ICMP)
		send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
			socket.IPPROTO_UDP)

		send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
		recv_socket.bind(("", port))
		send_socket.sendto("", (dest_addr, port))
		route_addr = None
		route_name = None
		try:
			# Default timeout is 5 seconds.
			recv_socket.settimeout(args['w'])
			route_addr = recv_socket.recvfrom(512)[1]
			route_addr = route_addr[0]
			try:
				route_name = socket.gethostbyaddr(route_addr)[0]
			except socket.error:
				route_name = route_addr
		except socket.error:
			pass

		send_socket.close()
		recv_socket.close()

		if route_addr is not None:
			route_host = "%s (%s)" % (route_name, route_addr)
		else:
			route_host = "*"
		print "%d\t%s" % (ttl, route_host)

		ttl += 1
		port += 1
		if route_addr == dest_addr or ttl > max_hops:
			break

if __name__ == "__main__":
	main('google.com')

