#!/usr/bin/python

import socket
import sys

RDEF_PT_DUMPER_IP = "127.0.0.1"
RDEF_PT_DUMPER_PORT = 0x2DEF

def send2ctroller(cmd_arg_str):
	cl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
	cl_socket.settimeout(5.0)
	try:
        	cl_socket.connect((RDEF_PT_DUMPER_IP, RDEF_PT_DUMPER_PORT))
	        cl_socket.send(cmd_arg_str)
		print "Sent : " + cmd_arg_str
	except socket.timeout:
        	print "Timeout"

if __name__ == "__main__":
	send2ctroller(' '.join(sys.argv[1:]))
