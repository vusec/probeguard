#!/usr/bin/python

import socket
from multiprocessing import Process, Manager
import os
import re
import signal
import sys
from util import *
import time

class Constants:
	BUFFER_SIZE = 250;
	PATH_SRV_HOME_DIR = os.environ["HOME"] + r'/scratchspace/rdef-server'
	PATH_RDF_ROOT = os.environ["HOME"] + "/repositories/reactive-defense"
	SINGLE_INSTANCE_FILE = PATH_SRV_HOME_DIR + r'/.rdefsrv.running.stat'
	BASELINE_MODE = 0

def single_instance_check():
	if os.path.isfile(Constants.SINGLE_INSTANCE_FILE):
		return False
	open(Constants.SINGLE_INSTANCE_FILE, 'a').close()
	return True

def clean_exit(signum, frame=None):
	if signum == signal.SIGUSR1:
		exit(0)	# Upon exit, all child daemons are tried to be killed

class PTController:
	PATH_PT_SCRIPT_READ_AUX = Constants.PATH_RDF_ROOT + "/external/processor-trace/script/perf-read-aux.bash"
	PATH_PT_SCRIPT_READ_IMAGE = Constants.PATH_RDF_ROOT + "/external/processor-trace/script/perf-read-image.bash"
	PERF_CMD_RECORD ="record --snapshot=16777216 -e intel_pt//u --per-thread -p %s sleep infinity"
        PERF_CMD_DUMP ="kill -SIGUSR2 %s"
	PERF_CMD_TERMINATE = "kill -SIGINT %s"
	PERF_PID = 0
	reinitiating = 0
	perf_pids = None	# Shared dict
	m_manager = None

	def __init__(self):
		self.m_manager = Manager()
		self.perf_pids = self.m_manager.dict({});

	def start_pt(self, pid):
		if Constants.BASELINE_MODE == 1:
			return "ACK"

		# Prepare
		pid_dir = os.path.join(Constants.PATH_SRV_HOME_DIR, str(pid))
		if os.path.isdir(pid_dir) and (not self.reinitiating):
	                print "Info: pid_dir: %s exists. Removing it." % pid_dir
        	        runcmd("rm -rf %s" % pid, cwd=Constants.PATH_SRV_HOME_DIR)
       		runcmd("mkdir -p %s" % pid_dir, cwd=Constants.PATH_SRV_HOME_DIR)
		self.reinitiating = False

		# Start recording
		if not does_pid_exist(pid):
			return "NIL"

		perf_pid = runbg("perf", args=self.PERF_CMD_RECORD % pid, wait=False, 
				cwd=pid_dir)
		self.perf_pids[pid] = perf_pid

		# Dump the first bits of recording to disk
		time.sleep(2)
        	runcmd(self.PERF_CMD_DUMP % perf_pid, cwd=pid_dir)
	        print "perf recording with PT started. PID of the 'perf record' process: %d" % perf_pid
	        return "ACK"

	def on_crash(self, pid):
		CMD_CREATE_PTDUMP_FROM_PERF_DATA = self.PATH_PT_SCRIPT_READ_AUX
	        CMD_INVOKE_DIAGNOSER = Constants.PATH_RDF_ROOT + "/analyzer/diagnoser/diagnoser %s %s %s"
        	CMD_ELFER = self.PATH_PT_SCRIPT_READ_IMAGE

		print "on_crash()...\n"
	        pid_dir=cmdToOut("find %s -name %s -type d" % (Constants.PATH_SRV_HOME_DIR, str(pid)))
		perf_pid = self.perf_pids[pid]
		if None == perf_pid:
			print "No perf recording process found for pid: " + str(pid)
			return "NIL"

        	if (os.path.isdir(pid_dir) and os.path.isfile("%s/perf.data" % pid_dir)):
			runcmd(self.PERF_CMD_DUMP % perf_pid, cwd=pid_dir, silent=True)
			runcmd(self.PERF_CMD_TERMINATE % perf_pid, cwd=pid_dir, silent=True)
			del self.perf_pids[pid]

			# Run script to extract PT dump from perf.data
			time.sleep(5)
                	runcmd(CMD_CREATE_PTDUMP_FROM_PERF_DATA, cwd=pid_dir)
	        else:
        	        return "No recording for process %s" % pid

		print "CMD_ELFER: " + CMD_ELFER + " ( " + pid_dir + " ) "
	        elves = cmdToOut(CMD_ELFER, cwd=pid_dir)
		if elves:
	        	prog_filepath = (elves.split("--elf")[1]).split(":")[0]
		        print "Program file path: %s" % prog_filepath
		else:
			exit(1)
		ptdump_filepath = ""
		ptdump_filepath = cmdToOut("find %s -name \"perf.data*.bin\" -type f | sort | tail -1" % pid_dir, cwd=pid_dir)
		if "" == ptdump_filepath:
	        	runcmd(self.PATH_PT_SCRIPT_READ_AUX, cwd=pid_dir)
        	print "PT dump file path: %s" % ptdump_filepath
		if "" == ptdump_filepath:
			print "ptdump file not found. Exiting"
			exit(0)

		# Run our Diagnoser to retrieve last llvm_id
	        elf_files_addendum = elves
        	dataLines = cmdToOutLines(CMD_INVOKE_DIAGNOSER % (prog_filepath, ptdump_filepath, elf_files_addendum), cwd=pid_dir)
		llvm_id = "0"  # Invalid
		for l in dataLines:
			if "Last LLVM ID found:" in l:
				llvmid_extract = re.search(".*found: ([0-9]+).*", l)
				if llvmid_extract:
					llvm_id = llvmid_extract.group(1)

		# Run perf again for future recording
		self.reinitiating = True
		runcmd("rm -rf *.bin", cwd=pid_dir)
		self.start_pt(pid)
        	return llvm_id

class RDEFServer:
	RDEF_PT_DUMPER_IP = "127.0.0.1"
	RDEF_PT_DUMPER_PORT = 0x2DEF
	RDEF_CONTROLLER_IP = "127.0.0.1"
	RDEF_CONTROLLER_PORT = 2017
	UDS_ENDPOINTS = None	# Shared list
	m_srv_socket = None
	m_me = None
	m_pt = None
	m_manager = None

	def init(self):
		self.m_pt = PTController()
		self.m_manager = Manager()
		self.UDS_ENDPOINTS = self.m_manager.list([])

		if not (os.path.isdir(Constants.PATH_SRV_HOME_DIR)):
	                runcmd("mkdir -p %s" % PATH_SRV_HOME_DIR)

		# Create a socket to listen for requests from protected process
		try:
			print "Starting self on " + self.RDEF_PT_DUMPER_IP + " : " + str(self.RDEF_PT_DUMPER_PORT)
			self.m_srv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
			self.m_srv_socket.bind((self.RDEF_PT_DUMPER_IP, self.RDEF_PT_DUMPER_PORT))
			self.m_srv_socket.listen(1)

		except socket.error as e:
			print "ERROR: Server initialization failed: " + str(e)
        	        exit(1)

		# Set signal handler for a clean exit
		signal.signal(signal.SIGUSR1, clean_exit)

		# Start accepting connections
		try:
			while True:
				conxn, cl_addr = self.m_srv_socket.accept()
				print "Accepted connection from %s" % str(cl_addr)
				c_process = Process(target=self.handle_request, 
						    args=(conxn, cl_addr))
				c_process.start()

				# Clean-up UDS_ENDPOINTS as well
				curr_uds_endpts = self.UDS_ENDPOINTS[:]
				for u in curr_uds_endpts:
					if not os.path.exists(u):
						self.UDS_ENDPOINTS.remove(u)
				curr_uds_endpts = None

		except socket.error as e:
			print "Error: Failed accepting connection: " + str(e)
			
		except Exception as fe:
			print "Error: Fatal exception: " + str(fe)
			if self.m_srv_socket:
				self.m_srv_socket.close()

		# Shutdown
		print "Shutting down RDEFServer"
		exit(1)

	def start(self):
		self.m_me = Process(target=self.init)
		self.m_me.start()
		print "started rdefsrv process: " + str(self.m_me.pid)

	def stop(self):
		ppid = os.getppid()
		print "Shutting down RDEF Server : " + str(ppid)
		if os.path.isfile(Constants.SINGLE_INSTANCE_FILE):
			os.remove(Constants.SINGLE_INSTANCE_FILE)
		os.kill(ppid, signal.SIGUSR1)

	def handle_request(self, cl_conn, cl_addr):
		while True:
			request = cl_conn.recv(Constants.BUFFER_SIZE)
			if not request:
				break		# Connection broke. Nothing more to do here.

			print "handling request: " + str(request)
			tokens = request.split(' ');
			req_cmd = tokens[0]
			res = "NIL"
			if len(tokens) >= 2:
				if "trace" == req_cmd:
					pid = tokens[1]
					print "Starting tracing..."
					res = self.m_pt.start_pt(pid)

				elif "crashed" == req_cmd:
					pid = tokens[1]
					print "crashed: pid: " + str(pid)
					res = self.m_pt.on_crash(pid)

				elif "ctl" == req_cmd:
					res, uds_addr = self.switchboard_ctl(tokens[1:])

				else:
					print "Unknown request: " + request
			else:
				if "stop" == req_cmd:
					self.stop()
					res = "EXIT"
				else:
					print "Invalid request: " + request

			print "Processed request. result: " + res
			if "EXIT" == res:
				break

#			if "ACK" != res:
#				continue
			cl_conn.send(res)

		print "Done handling request. Ending this process (%d)" % os.getpid()
		return

	def switchboard_ctl(self, args):
		cmd = args[0]
		print "Switchboard control [ cmd: %s ]" % cmd
		res = "NIL"
		uds_addr = ""

		try:
			if cmd == "init":
				uds_endpt = str(args[1])
				time.sleep(2)
				if os.path.exists(uds_endpt):
					if uds_endpt not in self.UDS_ENDPOINTS:
						print str(self.UDS_ENDPOINTS)
						self.UDS_ENDPOINTS.append(uds_endpt)
						print "Added UDS endpoint: " + uds_endpt
						uds_addr = uds_endpt

					res = "ACK"
				else:
					print "Exiting : %s does not exist." % self.UDS_ENDPOINTS
					# close the connection and end this process
					exit(1)

			elif cmd == "enable_one":
				print "Number of UDS connections: %d" % len(self.UDS_ENDPOINTS)
				print str(self.UDS_ENDPOINTS)

				dead_uds_eps = []
				for ep in self.UDS_ENDPOINTS:
					if not os.path.exists(ep):
						print "UDS endpoint: %s does not exist anymore." % ep
						dead_uds_eps.append(ep)
						continue

					print "\nConnecting to uds: " + ep
	                                uds_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        	                        uds_socket.connect(ep)

                	                print "Resetting all defenses"
                        	        uds_socket.send("rdef_reset_defenses ")
					res = uds_socket.recv(Constants.BUFFER_SIZE)
	                                if res != "ACK":
        	                                print "Received NON-ACK: %s" % res
						self.uds_close(uds_socket)
						continue
					self.uds_close(uds_socket)

					print "Connecting again to uds: " + ep
					uds_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
					uds_socket.connect(ep)

                	                print "Enabling function: %d" % int(args[1])
                        	        uds_socket.send("rdef_activate_defense " + args[1])
	                                res = uds_socket.recv(Constants.BUFFER_SIZE)
        	                        if res != "ACK":
                	                        print "Received NON-ACK: %s" % res
						self.uds_close(uds_socket)
						continue
					self.uds_close(uds_socket)

				for ep in dead_uds_eps:
					self.UDS_ENDPOINTS.remove(ep)

			elif cmd == "reset":
				print "Number of UDS connections: %d" % len(self.UDS_ENDPOINTS)

				for ep in self.UDS_ENDPOINTS:
					if not os.path.exists(ep):
						print "UDS endpoint: %s does not exist anymore." % ep
						self.UDS_ENDPOINTS.remove(ep)
						continue

					print "\n Connecting to uds: " + ep
	                                uds_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        	                        uds_socket.connect(ep)

                	                print "Resetting all defenses"
                        	        uds_socket.send("rdef_reset_defenses ")
	                                res = uds_socket.recv(Constants.BUFFER_SIZE)
        	                        if res != "ACK":
                	                        print "Received NON-ACK: %s" % res
						self.uds_close(uds_socket)
						continue
					
					self.uds_close(uds_socket)

			else:
				print "Invalid command: " + cmd

		except socket.error as se:
			print "Error: UDS socket error: " + str(se)

		if 0 == len(self.UDS_ENDPOINTS):
			print "No active UDS connections."
			res = "EXIT"

		return res, uds_addr

	def uds_close(self, s):
		s.shutdown(socket.SHUT_RDWR)
		s.close()

if __name__ == "__main__":

	if not single_instance_check():
		print "Instance already running. Exiting"
		exit(1)

	rdefServer = RDEFServer()
	rdefServer.start()

