# ***********************************************#
# Utility routines that Kombit uses.
#
# Author:   Koustubha Bhat
# Date  :   8-June-2016
# Vrije Universiteit, Amsterdam, The Netherlands
# ***********************************************#

import subprocess
import os

class CmdExecutionError(Exception):
	pass

def llvmDis(application):
	file_types = [".bc", ".bcl"]
	files = []
	for e in file_types:
		bitcodes = cmdToOutLines("find %s -name \*%s" % (application.install_path, e))
                for b in bitcodes:
                        if b != '':
                                files.append(str(b))
	for f in files:
		runcmd("llvm-dis %s" % (f), silent=True)
	return

def grepInFile(targetFile, searchString, cwd=None):
	cmdline="grep %s %s" % (searchString, targetFile)
	handle=subprocess.Popen(cmdline, stdout=subprocess.PIPE, shell=True, cwd=cwd)
	data=handle.communicate()[0].rstrip().split(os.linesep)
	return handle.returncode, data;

def cmdToOut(cmdline, cwd=None):
	print "[cmd] %s\n[cwd: %s]" % (cmdline, cwd)
	handle=subprocess.Popen(cmdline, stdout=subprocess.PIPE, shell=True, cwd=cwd)
	data=handle.communicate()[0].rstrip()
	if handle.returncode != 0:
		raise Exception("Utility command returned error: " + cmdline)
	return data

def cmdToOutLines(cmdline, cwd=None):
	print "[cmd] %s\n[cwd: %s]" % (cmdline, cwd)
	return cmdToOut(cmdline, cwd=cwd).split(os.linesep)

def runcmd(cmdline, env=None, cwd=None, stdout=None, stderr=None, silent=False, wait=True):
	print "[cmd] bash -c %s\n[cwd: %s]" % (cmdline, cwd)
	shell = subprocess.Popen(["/bin/bash", "-c", cmdline], stdout=stdout, stderr=stderr, cwd=cwd)
	if not wait:
		return 0
	shell.wait()
	result = shell.returncode
	if False == silent:
		if result != 0:
			raise CmdExecutionError("exit code: %d" % (result))
	else:
		return result

def runbg(prog, args="", env=None, cwd=None, stdout=None, stderr=None, silent=False, wait=False):
	print "[bg] %s %s\n[cwd: %s]" % (prog, args, cwd)
	args_list = args.split(" ")
	shell = subprocess.Popen([prog,] + args_list, shell=False, stdout=stdout, stderr=stderr, cwd=cwd)
	thePid = shell.pid
	if not wait:
		return thePid
	shell.wait()
	result = shell.returncode
	if False == silent:
		if result != 0:
			raise CmdExecutionError("exit code: %d" % (result))
	else:
		return result

def does_pid_exist(pid):
	try:
		os.kill(int(pid), 0)
		return True
	except OSError:
		return False

def str2dict(str, delim=',', assoc='='):
	ret_dict = {}
	entries = str.split(delim)
	for e in entries:
		if not e:
			continue
		key_value_pair = e.split(assoc)
		ret_dict[key_value_pair[0]]=key_value_pair[1]
	return ret_dict

def getDictFromConfig(config_parser, section, key):
	env_string = config_parser.get(section, key)
	env_dict = str2dict(env_string)
	return env_dict

def getModuleNameAndClassName(modulenames_value, full_class_name):
	modulenames = modulenames_value.split(',')
	for m in modulenames:
        	__import__(m)
	if "." in full_class_name:
		mname = classname.split(".")[0]
		cname = classname.split(".")[1]
		return {'module':mname, 'class':cname}
	else:
		return {'module':modulenames[0], 'class':full_class_name}
