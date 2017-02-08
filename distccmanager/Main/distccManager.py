#!/usr/bin/env python3.3
#
# cross platform distcc management tool

#  Copyright (c) 2013 Adobe Systems Inc. All rights reserved.
#  Use of this source code is governed by a BSD-style license that can be
#  found in the LICENSE file.

import os, sys, argparse, select, socket, shutil, glob, tempfile, time, subprocess, filecmp
import json, re, copy
import Pyro4
import threading, datetime, psutil, hashlib

Pyro4.config.HMAC_KEY = b'b7523331524a1df52e0b45aaf507cae6a07f06c4c7e2c070a74670d89e785585'
Pyro4.config.SOCK_REUSE = True # don't wait 30s to release port on restart

#Pyro4.config.COMMTIMEOUT = 10
VERSION = "1.1.53"

# Setup to run this script
# ------------------------
# install python3.3: sudo port install python33
# install modules python complains are missing after running this script (see below)

# How to install any module for any python version
# --------------------------------------------------
# curl -O http://python-distribute.org/distribute_setup.py
# python3.3 distribute_setup.py
# sudo python3.3 -m easy_install [module name]

# How to use NFS on windows
# - enable: go to add/remove programs->enable features->nfs client
# - to mount: mount -o mtype=hard machine.ip:[/share/folder] [drive letter]
# - to unmount: umount [drive letter]
# - to list mounts: showmount -e [machine ip]

# How to enable NFS on mac
# - start: sudo nfsd restart
# - list of mounts: /etc/exports
#   - format: /Applications/Xcode.app	-ro -alldirs -mapall=nobody
# - mount: mount -t nfs [machine IP]:/[share path] [target mount path]
# - unmount: umount [target mount path]

# How to use this script:
# -----------------------

# This single script is three things: client, server, compiler-redirect
# There are no databases, yay!  Clients + servers communicate over pyro4

# - Setup server
#   - edit SERVER_LIST to include machines that will run this script as server (just need one, can have back-ups)
#   - run server on any machine: distccTool.py -mode server -tools_path /Volumes/distcc-toolwhip
#   - tools contains pump + distcc + distccd and related files

# - Setup client
#   - run client on machine you're compiling from: distccTool.py -mode client -compiler_root ~/Downloads/android-ndk-r5b
#     - it can auto-discover XCode, however you need to use compiler_root for compilers which can be in variable locations.
#       Update COMPILER_ROOTS to specify toolchain roots based off compiler_root parameter

# when you compile as long as your compiler was detected it will now be re-directed to all available machines which have available
# processing slots based on memory + cpu available. It even starts + stops pump for you :)

# TODOS
#  - override for number of local compiles
#  - better handling of server/client going down
#  - better exception handling
#  - have server GC machines that haven't been updated in a long time
#  - server flask UI? http://flask.pocoo.org/docs/
#  - figure out how to run on OSX with firewall enabled (blocks distccd even with it specified as allowed)
#      - when firewall enabled, something weird happens with the tools mount, ends up getting mounted as root in wrong place messing things up

SERVER_LIST = [ "drm-mac.corp.adobe.com", "drm.corp.adobe.com" ]

# Globals
# -------
# format: toolchainRoot (compiler->script replacement) : toolchainShareRoot
# FYI: if a directory has a space it may not work over NFS :(
COMPILER_ROOTS = { }
COMPILER_ROOTS["darwin"] = {
	# XCode 3.x
	"/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin" : "/Developer/Platforms/iPhoneOS.platform/Developer/usr",
	"/Developer/usr/bin" : "/Developer/usr", # iPhoneSimulator uses this compiler
	
	# Android NDK - r5b + r8c have same path but different binaries
	"toolchains/arm-linux-androideabi-4.4.3/prebuilt/darwin-x86/bin" : "toolchains/arm-linux-androideabi-4.4.3/prebuilt/darwin-x86",
	
	# XCode 4.x
	"/Applications/Xcode.app/Contents/Developer/usr/bin" : "/Applications/Xcode.app/Contents/Developer/usr",
	"/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin" : "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr",
}
	
COMPILER_ROOTS = COMPILER_ROOTS[sys.platform]
DISTCCTOOL_FOLDER_PATH = os.path.join(os.path.expanduser("~"), ".distccTool")
DISTCCTOOL_PREFS_PATH = os.path.join(DISTCCTOOL_FOLDER_PATH, ".prefs")
DISTCCTOOL_MOUNTS_PATH = os.path.join(DISTCCTOOL_FOLDER_PATH, "mounts")

# relative paths are not supported by distcc :(
DISTCCTOOL_TOOLCHAINS_PATH = "/private/tmp/distccTool/toolchains"

DISTCCTOOL_TOOLS_PATH = os.path.join(DISTCCTOOL_MOUNTS_PATH, "tools")

DISTCCTOOL_DISTCC_PATH = os.path.join(DISTCCTOOL_TOOLS_PATH, "distcc")
DISTCCTOOL_DISTCCD_PATH = os.path.join(DISTCCTOOL_TOOLS_PATH, "distccd")
DISTCCTOOL_PUMP_PATH = os.path.join(DISTCCTOOL_TOOLS_PATH, "pump")

PREFS_DEFAULT = { }

# TODO: get rid of ARGS global
ARGS = None
VERBOSE = False

def runCMD(args, shell=False, cwd=None, env=None, throwOnError=True, verbose=False):
	extra = "" # " env:" + str(env)
	if verbose: print("executing:" + str(args) + extra)
	
	p = subprocess.Popen(args, shell=shell, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	po, pe = p.communicate()
	
	if VERBOSE: 
		if po: print("po: ", po)
		if pe: print("po: ", pe)
		print("rc:" + str(p.returncode))

	if p.returncode != 0 and throwOnError:
		raise Exception(p.returncode)
		
	if len(pe) and throwOnError:
		raise Exception(pe)
		
	return po
	
def connectToProxy(name, host, port):
	proxy = None
	try:
		uri = "PYRO:" + name + "@" + host + ":" + port
		if VERBOSE: print("Attempting to contact: " + uri)
		proxy = Pyro4.Proxy(uri)
		proxy._pyroTimeout = 5
		proxy.ping()
		proxy._pyroTimeout = None
	except:
		print("  unable to contact:" + uri)
		proxy = None
		pass
	
	return proxy

def getServerProxy():
	for hostName in SERVER_LIST:
		serverProxy = connectToProxy("distccServer", hostName, "9090")
		if serverProxy is not None: return (hostName, serverProxy)

	return (None, None)

def getShareSHA1(host, path):
	h = hashlib.sha1()
	h.update(host.encode('utf-8'))
	h.update(path.encode('utf-8'))
	return h.hexdigest()
	
def callPyroMethod(proxy, methodName, args, kwargs):
	if VERBOSE: print("calling:" + methodName + " on:" + str(proxy))
	try:
		return proxy._pyroInvoke(methodName, args, kwargs)
	except:
		print("".join(Pyro4.util.getPyroTraceback()))
		raise
	finally:
		if VERBOSE: print("called:" + methodName)

def callPyroMethod2(proxy, methodName, *args, **kwargs):
	return callPyroMethod(proxy, methodName, args, kwargs)

def setXCodeParallelTasks(num):
	if num is None:
		runCMD(["defaults", "delete", "com.apple.Xcode", "PBXNumberOfParallelBuildSubtasks"], throwOnError=False)
		runCMD(["defaults", "delete", "com.apple.dt.Xcode", "IDEBuildOperationMaxNumberOfConcurrentCompileTasks"], throwOnError=False)
	else:
		runCMD(["defaults", "write", "com.apple.Xcode", "PBXNumberOfParallelBuildSubtasks", str(num)], throwOnError=False)
		runCMD(["defaults", "write", "com.apple.dt.Xcode", "IDEBuildOperationMaxNumberOfConcurrentCompileTasks", str(num)], throwOnError=False)


	
class DistCCDaemon(Pyro4.threadutil.Thread):
	def __init__(self, bindip, port, name):
		Pyro4.threadutil.Thread.__init__(self)
	
		while True:
			try:
				print("binding server to: " + bindip + ":" + str(port))
				self.pyrodaemon = Pyro4.Daemon(host=bindip, port=port)
				break
			except OSError as e:
				if e.errno != 48: raise # Address already in use
				print("Address in use, trying again after sleeping 5 seconds")
				time.sleep(5)
		
		self.uri = self.pyrodaemon.register(self, name)	
		self.setDaemon(1)
		
	def start(self):
		Pyro4.threadutil.Thread.start(self)
		rc = -1
		try:
			self.join()
		except KeyboardInterrupt:
			rc = 0
		finally:
			self.pyrodaemon.unregister(self)
			self.pyrodaemon.shutdown()
			self.shutdown()
			self.pyrodaemon.close()
			exit(rc)
		
	def run(self):
		try:
			self.pyrodaemon.requestLoop()
		except:
			print("".join(Pyro4.util.getPyroTraceback()))
					
class DistCCToolServer(DistCCDaemon):
	def __init__(self, bindip):
		DistCCDaemon.__init__(self, bindip, 9090, "distccServer")
		self.machines = { }
		self.lock = threading.RLock()
		self.isShutdown = False
		self.timer = None
		print("starting server...")
		shareNFSFolder(ARGS.tools_path)
		self.startTimer();

	def shutdown(self):
		with self.lock: 
			self.isShutdown = True
			if self.timer is not None: self.timer.cancel()
			
			for (ip, mi) in self.machines.items():
				clientMachine = self.machines[ip]
				if not 'proxy' in clientMachine: continue
				clientMachine['proxy']._pyroRelease()
				del clientMachine['proxy']

		unmountNFSFolder(DISTCCTOOL_TOOLS_PATH)
		unshareNFSFolder(ARGS.tools_path)
		enablePump(False)
		
	def startTimer(self):
		with self.lock:
			if self.timer is not None: self.timer.cancel()
			self.timer = None

			if self.isShutdown:
				return
			
			self.timer = threading.Timer(30, self.timerCB)
			self.timer.start()
		
	def timerCB(self):
		ips = []
		with self.lock:
			ips = self.machines.keys()
						
		if len(ips):
			# check if machine is responding	
			args = [os.path.join(ARGS.tools_path, "lsdistcc"), "-l", "-P3"]
			args.extend(ips)
			try:
				machinePings = { }
				lines = runCMD(args, verbose=VERBOSE).decode("utf-8").splitlines()
				for line in lines:
					arr = line.split(" ")
					arr2 = arr[0].split(",")
					
					machinePings[arr2[0]] = int(arr[1])

				with self.lock:
					for (ip, mi) in self.machines.items():
						if ip in machinePings:
							mi['ping'] = machinePings[ip]
							mi['status'] = 'ok'
						else:
							mi['ping'] = -1
							mi['status'] = 'unreachable'

			except: pass
		
		self.startTimer()
		
	def callClientMethod(self, hostname, methodName, *args, **kwargs):
		proxy = None
		with self.lock:
			clientMachine = self.machines[hostname]
			if not 'proxy' in clientMachine: 
				proxy = connectToProxy("distccClient", hostname, "8080")
				clientMachine['proxy'] = proxy
			else:
				proxy = clientMachine['proxy']
		
		return callPyroMethod(proxy, methodName, args=args, kwargs=kwargs)
		
	def ping(self): pass
	def version(self): return VERSION
	
	def getToolsFolder(self): return ARGS.tools_path
	
	def getJobsAvailable(self):
		num = 0
		with self.lock:
			for (hostName, mi) in self.machines.items():
				num += mi["numJobs"]
				
		return num
	
	def status(self):
		status = ""
		totalJobsAvailable = 0
		with self.lock:
			for (hostName, mi) in self.machines.items():
				machine = self.machines[hostName]
				totalJobsAvailable += machine["numJobs"]
				status += hostName + " status:" + machine['status'] + " jobsAvailable:" + str(machine['numJobs']) + os.linesep
				
			status += "total jobs available:" + str(totalJobsAvailable)
		return status
	
	def startCompile(self, compileHost, sharedCompilerPath):
		hosts = []
		
		availableHosts = { }
		with self.lock:
			compileMachine = self.machines[compileHost]
			compileMachine['mountCount'] += 1
			
			for (hostName, mi) in self.machines.items():
				if mi["status"] != "ok" or mi["numJobs"] < 1: continue
				availableHosts[hostName] = mi["numJobs"]
				
				
		for (hostName, numJobs) in availableHosts.items():
			try:
				with self.lock:
					mounted = self.machines[compileHost]['mountCount'] > 1
				
				if not mounted:
					mounted = self.callClientMethod(hostName, "mountShare", compileHost, sharedCompilerPath)
						
				if mounted:
					if hostName == compileHost: hostName = "localhost"
					hosts.append(hostName + "/" + str(numJobs) + ",cpp,lzo")
			except:
				if VERBOSE: print("".join(Pyro4.util.getPyroTraceback()))
				pass
		
		return hosts
		
	def finishCompile(self, compileHost, sharedCompilerPath):	
		with self.lock:
			compileMachine = self.machines[compileHost]
			#compileMachine['mountCount'] -= 1
			
			if compileMachine['mountCount'] == 0: pass
			# todo unmount shares?  send unmount to all clients
	
	def registerClient(self, hostname, machineInfo):
		with self.lock:
			if not hostname in self.machines:
				self.machines[hostname] = { }
			
			machine = self.machines[hostname]			
			machine['status'] = 'unknown'
			machine['lastUpdate'] = datetime.datetime.now()
			machine['mountCount'] = 0
			
		self.timerCB() # update ping/distccd
		self.updateMachine(hostname, machineInfo)
		if VERBOSE: print("machineRegistered:" + str(machine))
			
	def updateMachine(self, hostname, machineInfo):
		with self.lock:
			if not hostname in self.machines:
				self.machines[hostname] = { }
				
			machine = self.machines[hostname]
			for (name,value) in machineInfo.items():
				machine[name] = value
		
		if VERBOSE: print("machine updated:" + hostname + ":" + str(machine))
		
	def removeClient(self, hostname):
		if VERBOSE: print("removing client:" + hostname)
		with self.lock:
			if hostname in self.machines: del self.machines[hostname]
			
class DistCCToolClient(DistCCDaemon):
	def __init__(self, bindip):
		DistCCDaemon.__init__(self, bindip, 8080, "distccClient")
		self.serverProxy = None
		self.lock = threading.RLock()
		self.mountedToolchains = []
		self.compiles = 0
		self.timer = None
		self.disconnected = False
		self.localCompilers = None
		self.pumpEnv = None
		self.isShutdown = False
		self.bindip = bindip
		
		print("starting client...")
		
		vmem = psutil.virtual_memory()
		self.machineInfo = {
			'totalRAM' : vmem.total/1024/1024,
			'numCPUs': psutil.NUM_CPUS,
			'numJobs': 0,
		}
		
		self.prefs = loadPrefs()
		
		if 'serverName' in self.prefs:
			self.serverName = self.prefs['serverName']
			self.serverProxy = connectToProxy("distccServer", self.serverName , "9090")
		else:		
			(self.serverName, self.serverProxy) = getServerProxy()
				
		if self.serverProxy is None:
			print("Unable to contact any server. Exiting...")
			exit(-1)
		
		self.prefs['serverName'] = self.serverName
		
		mountNFSFolder(self.serverName, self.callServerMethod("getToolsFolder"), DISTCCTOOL_TOOLS_PATH)
		self.doVersionCheck()
		
		# localCompilers is a one shot if we're re-loading the script due to update
		if 'localCompilers' in self.prefs:
			self.localCompilers = self.prefs['localCompilers']
			del self.prefs['localCompilers']
		else:
			self.localCompilers = shareLocalCompilers()	
		
		self.startTimer();
		enableDistccd(True)
		writePrefs(self.prefs)
		enablePump(False)
		
		if ARGS.xcode_tasks is not None:
			setXCodeParallelTasks(ARGS.xcode_tasks)

		self.updateMachineInfo(False)
		self.callServerMethod("registerClient", bindip, self.machineInfo)
	
	def log(self, str):
		print(str)
		
	def doVersionCheck(self):
		if self.serverProxy.version() != VERSION:
			print("client outdated, updating...")
			scriptName = os.path.basename(sys.argv[0])
			src = os.path.join(DISTCCTOOL_TOOLS_PATH, scriptName)
			print("attempting to copy:" + src + " to:" + sys.argv[0])
			if os.path.exists(src):
				if filecmp.cmp(src, sys.argv[0]):
					print("files already same, re-loading")
				else:
					shutil.copyfile(src, sys.argv[0])
					print("copied")
				
				if self.localCompilers is not None:
					self.prefs['localCompilers'] = self.localCompilers
				
				self.shutdown(False)
				print("attempting to execute:" + str(sys.argv))
				os.execl(sys.executable, *([sys.executable]+sys.argv))
			
	def mountShare(self, compileHost, sharedCompilerPath):
		with self.lock:
			targetPath = os.path.join(DISTCCTOOL_TOOLCHAINS_PATH, getShareSHA1(compileHost, sharedCompilerPath))
		
			with self.lock:
				if targetPath in self.mountedToolchains: return True

				try:
					if mountNFSFolder(compileHost, sharedCompilerPath, targetPath):
						self.mountedToolchains.append(targetPath)
				except:
					return False
				
			return True
	
	def shutdown(self, unmountToolchains=True):
		print("exiting client...")
		
		with self.lock:
			self.isShutdown = True
			if self.timer is not None: self.timer.cancel()
			writePrefs(self.prefs)
		
		if self.serverProxy is not None:
			try:
				self.callServerMethod("removeClient", self.bindip)
			except: pass
			
		for mountedPath in self.mountedToolchains:
			unmountNFSFolder(mountedPath)
		
		enableDistccd(False)
		unmountNFSFolder(DISTCCTOOL_TOOLS_PATH)
		
		if unmountToolchains:
			unshareLocalCompilers(self.localCompilers)
		
		enablePump(False)
		if ARGS.xcode_tasks is not None:
			setXCodeParallelTasks(None)

	def ping(self): pass

	def callServerMethod(self, methodName, *args, **kwargs):
		return callPyroMethod(self.serverProxy, methodName, args=args, kwargs=kwargs)
		
	def getSharedCompilerPath(self, compilerPath):
		with self.lock:
			for (localPath, localRoot) in self.localCompilers.items():
				if not compilerPath.startswith(localPath): continue
			
				return localRoot
		return None
	
	def startCompile(self, compilerPath):
		sharedCompilerPath = self.getSharedCompilerPath(compilerPath)
		
		hosts = self.callServerMethod("startCompile", self.bindip, sharedCompilerPath)
		pumpEnv = None
		with self.lock:
			self.compiles += 1
			if VERBOSE: print("compiles:" + str(self.compiles))
			if self.pumpEnv is None: self.pumpEnv = enablePump(True, hosts)
			pumpEnv = self.pumpEnv
			
		sharedSHA1Name = getShareSHA1(self.bindip, sharedCompilerPath)
		distccToolchainPath = sharedSHA1Name + compilerPath[len(sharedCompilerPath):]
		return (hosts, distccToolchainPath, pumpEnv)
		
	def finishCompile(self, compilerPath):
		with self.lock: 
			self.compiles -= 1
			if VERBOSE: print("compiles:" + str(self.compiles))
			
		sharedCompilerPath = self.getSharedCompilerPath(compilerPath)
		return self.callServerMethod("finishCompile", self.bindip, sharedCompilerPath)
	
	def updateMachineInfo(self, updateServer=True):
		numCPUs = psutil.NUM_CPUS
		vmem = psutil.virtual_memory()
		availableRAM = round(vmem.available/1024/1024)
		totalRAM = round(vmem.total/1024/1024)
		cpuUsage = psutil.cpu_percent()
		
		numJobs = 0
		# first limit by RAM
		if totalRAM <= 2048:
			numJobs = min(numCPUs, 2)
		else:
			numJobs = min(numCPUs,  (totalRAM-2000) / 430) # OSX_BASE_REQUIRED/GCC_MIN_REQUIRED
			
		# second limit by CPU usage
		
		mi = None
		with self.lock:
			self.machineInfo['numJobs'] = max(0, numJobs - int(round((cpuUsage/100.0) * numCPUs)))
			self.machineInfo['usageCPU'] = cpuUsage
			self.machineInfo['availableRAM'] = availableRAM
			mi = copy.deepcopy(self.machineInfo)
		
		# not going through callServerMethod to avoid extra logging
		if updateServer: self.serverProxy.updateMachine(self.bindip, mi)
		
	def startTimer(self, timeout=5):
		with self.lock:
			if self.timer is not None: self.timer.cancel()
			self.timer = None

			if self.isShutdown:
				return
			
			self.timer = threading.Timer(timeout, self.timerCB)
			self.timer.start()
		
	def timerCB(self):
		timeout = 5
		
		with self.lock:
			if self.compiles == 0:
				enablePump(False)
				self.pumpEnv = None
				
		try:
			if self.disconnected:
				self.serverProxy._pyroBind()
				self.callServerMethod("registerClient", self.bindip, self.machineInfo)
				self.disconnected = False
				print("re-connected to server")
			else:
				self.doVersionCheck()
				self.updateMachineInfo()
				
			timeout = 5
		except:
			self.disconnected = True
			self.serverProxy._pyroRelease()
			print("Unable to communicate with server, timing out 90s")
			timeout = 90
		
		self.startTimer(timeout)
		
def getNFSDStatus():
	for proc in psutil.process_iter():
		if proc.name == "nfsd": return True
		
	return False

def enablePump(enabled = True, hosts=None):
	# shutdown is broken (argh)
	for proc in psutil.process_iter():
		if proc.name.find("Python") == -1: continue
		
		try:  # psutil sometimes throws an exception when getting the process's command-line
			cmdline = " ".join(proc.cmdline)
			if cmdline.find("include_server.py") != -1:
				if enabled:
					return None
				else:
					if VERBOSE: print("killing pid:" + str(proc.pid))
					proc.kill()
		except: pass
		        
	if not enabled: return None
	
	env = None
	if hosts is not None:
		env = os.environ.copy()
		env["DISTCC_HOSTS"] = " ".join(hosts)
	
	args = [DISTCCTOOL_PUMP_PATH, "--startup"]
	lines = runCMD(args, env=env, verbose=VERBOSE).decode("utf-8").splitlines()
	pumpEnv = { }
	for line in lines:
		arr = line.split(" ", 1)
		arr2 = arr[1].split("=", 1)
		pumpEnv[arr2[0]] = arr2[1][1:-1]
		
	return pumpEnv
	
	
def enableDistccd(enabled = True):
	found = False
	
	for proc in psutil.process_iter():
		if proc.name == "distccd": 
			proc.kill()
			if VERBOSE: print("killing pid:" + str(proc.pid))
        	
	if not enabled: return
	
	ip = socket.gethostbyname(ARGS.bindip)
	args = [DISTCCTOOL_DISTCCD_PATH, "--daemon", "--nice", "10", "-j", str(psutil.NUM_CPUS), "--listen", ip, "--allow", "0.0.0.0/0"]
	runCMD(args, verbose=VERBOSE)
	
def hasDistccParent(logFn=print):
	p = psutil.Process(os.getppid())
	while p and p.pid != 0:
		#logFn("ppid:" + str(p.pid) + " " + p.name)
		if p.name == "distcc" or p.name == "distccd": return True
		p = p.parent
	
	return False
	
def mountNFSFolder(host, sourcePath, targetPath):
	if not os.path.exists(targetPath): os.makedirs(targetPath)
	
	mounted = getMountedNFSShares()
	if host in mounted and sourcePath in mounted[host]: return False
	
	if VERBOSE: print("mounting host:" + str(host) + " sourcePath:" + str(sourcePath) + " targetPath:" + str(targetPath))
	runCMD(["/sbin/mount", "-t", "nfs", host + ":" + sourcePath, targetPath], verbose=VERBOSE)
	return True

def unmountNFSFolder(targetPath):
	runCMD(["/sbin/umount", targetPath], throwOnError=False, verbose=VERBOSE)

# host : { remotePath : localPath
def getMountedNFSShares():
	mounts = { }
	
	try:
		lines = runCMD(["/sbin/mount", "-t", "nfs"], verbose=VERBOSE).decode("utf-8").splitlines()
		for line in lines:
			matches = re.match("(.*):(.*) on (.*) \(nfs.*\)", line)
			if not matches: continue
			ip = str(matches.group(1))
			if not ip in mounts: mounts[ip] = { }
			mounts[ip][matches.group(2)] = matches.group(3)
	except:
		pass

	return mounts

# returns [path] [options]
# does not handle paths with spaces
def getNFSShares():
	dict = { }
	if not os.path.exists("/etc/exports"): return dict
	
	f = open("/etc/exports")
	for line in f:
		arr = line.strip().split(" ", 1)
		if len(arr) != 2: continue
		
		dict[arr[0]] = arr[1].strip()
		
	f.close()
	return dict

def runWithPriv(script, prompt):
	if VERBOSE: print("runWithPriv:" + script)
	tf = tempfile.NamedTemporaryFile(mode="w")
	try:
		tf.write(script)
		tf.flush()

		print(prompt)
		runCMD( [ "/usr/bin/osascript", "-e", "do shell script \"/usr/bin/sudo /bin/sh " + tf.name + "\" with administrator privileges"], verbose=VERBOSE )
	finally:
		if not tf.closed: tf.close()

def unshareNFSFolder(path):
	shares = getNFSShares()
	script = ""
	for (localPath, params) in shares.items():
		if localPath == path: continue
		script += "echo " + localPath + " " + params + ">> /etc/exports" + os.linesep

	script = "#!/bin/sh" + os.linesep + "set -e" + os.linesep + "echo > /etc/exports" + os.linesep + script + "nfsd update" + os.linesep
	runWithPriv(script, "Enter password to remove shared folder:" + path)
	
def shareNFSFolder(path):
	shares = getNFSShares()
	if path in shares: return
	
	running = getNFSDStatus()
	command = "update" if running else "start"
	
	script = "echo " + path + " -ro -alldirs -mapall=nobody >> /etc/exports" + os.linesep
	script = "#!/bin/sh" + os.linesep + "set -e" + os.linesep + script + "nfsd " + command + os.linesep
	runWithPriv(script, "Enter password to share folder:" + path)

# 1) finds compilers
# 2) for found compilers, moves gcc based executables to .orig and replaces with script
# 3) shares local compilers
# 4) returns list of shared compilers
def shareLocalCompilers():
	localCompilers = { }
	
	# 1) finds local compilers
	for (localPath, localRoot) in COMPILER_ROOTS.items():
		if localPath[0] == "/": # absolute path
			if not os.path.exists(localPath): continue
			
			if VERBOSE: print("found compiler: " + localRoot)
			localCompilers[localPath] = localRoot
		else:
			for path in ARGS.compiler_root:
				localPath2 = os.path.join(path, localPath)
				if not os.path.exists(localPath2): continue
				
				if VERBOSE: print("found compiler: " + localRoot)
				localCompilers[localPath2] = os.path.join(path, localRoot)
	
	if not localCompilers: return localCompilers
	
	# figure out which toolchains are already shared
	shares = getNFSShares()

	# generate script to run as administrator which will share the local compilers
	script = ""
	for (localPath, localRoot) in localCompilers.items():
		if localRoot in shares: continue
		script += "echo \"" + localRoot + "\" -ro -alldirs -mapall=nobody >> /etc/exports" + os.linesep
		
		files = glob.glob(os.path.join(localPath, "*"))
		for fileName in files:
			path = os.path.join(localPath, fileName)
			pathOrig = path + ".distccOrig"
			if not os.path.isfile(path) or not re.match(".*(clang|gcc|g\\+\\+)(-\\d+\\.\\d+\\.?\\d*)?$", fileName): continue
			
			if not os.path.exists(pathOrig):
				script += "mv \"" + path + "\" \"" + pathOrig + "\"" + os.linesep
			
			scriptName = os.path.basename(sys.argv[0])
			sharedScriptPath = os.path.join(DISTCCTOOL_TOOLS_PATH, scriptName).replace(os.path.expanduser("~"), "~")
			
			script += "echo \\#\\!/usr/local/bin/python3.3 > " + path + os.linesep
			script += "echo import imp, sys, os >> " + path + os.linesep
			script += "echo i = imp.load_source\\(\\\"i\\\", os.path.expanduser\\(\\\"" + sharedScriptPath + "\\\"\\)\\) >> " + path + os.linesep
			script += "echo i.compile\\(\\\"" + ARGS.bindip + "\\\",  sys.argv, " + str(VERBOSE) + "\\) >> " + path + os.linesep

			script += "chown $(stat -f%u:%g \"" + pathOrig + "\") \"" + path + "\"" + os.linesep
			script += "chmod $(stat -f%p \"" + pathOrig + "\") \"" + path + "\"" + os.linesep
			
			print("found compiler:" + path)
			
	
	if script != "":
		if VERBOSE: print("adding shares...")
		running = getNFSDStatus()
		command = "update" if running else "start"
	
		script = "#!/bin/sh" + os.linesep + "set -e" + os.linesep + script + "nfsd " + command + os.linesep
		runWithPriv(script, "Enter password to share local compilers...")
		
	return localCompilers

def unshareLocalCompilers(localCompilers):
	shares = getNFSShares()
	
	script = ""
	# remove shared folders
	for (localPath, params) in shares.items():
		if localPath in localCompilers.values(): continue
		script += "echo " + localPath + " " + params + ">> /etc/exports" + os.linesep

	# put back re-directed compilers
	for (localPath, localRoot) in localCompilers.items():
		files = glob.glob(os.path.join(localPath, "*"))
		for fileName in files:
			path = os.path.join(localPath, fileName)
			pathOrig = path + ".distccOrig"
			if not os.path.isfile(path) or \
				not re.match(".*(clang|gcc|g\\+\\+)(-\\d+\\.\\d+\\.?\\d*)?$", fileName) or \
				not os.path.exists(pathOrig): continue
			
			script += "mv \"" + pathOrig + "\" \"" + path + "\"" + os.linesep
			
	script = "#!/bin/sh" + os.linesep + "set -e" + os.linesep + "echo > /etc/exports" + os.linesep + script + "nfsd update" + os.linesep
	runWithPriv(script, "Enter password to unshare local compilers...")
	

def loadPrefs():
	if os.path.exists(DISTCCTOOL_PREFS_PATH):
		return json.load(open(DISTCCTOOL_PREFS_PATH, "r"))
	
	return PREFS_DEFAULT

def writePrefs(prefs):
	if not os.path.exists(DISTCCTOOL_FOLDER_PATH):
		os.makedirs(DISTCCTOOL_FOLDER_PATH)
		
	stagedPrefs = DISTCCTOOL_PREFS_PATH + ".new"
	try:
		f = open(stagedPrefs, "w")
		json.dump(prefs, f)
		f.close()
		
		shutil.move(stagedPrefs, DISTCCTOOL_PREFS_PATH)
	except:
		if os.path.exists(stagedPrefs): os.remove(stagedPrefs)
		raise
	
def getIPAddress():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 80))
	ip = s.getsockname()[0]
	s.close()
	return ip

def compile(bindip, args, verbose):
	global VERBOSE
	
	VERBOSE = verbose
	
	# don't distribute if:
	#   1) its being executed from the shared folder path
	#   2) if its the original compiler
	#   3) distcc[d] is executing the command
	if sys.argv[0].startswith(DISTCCTOOL_TOOLCHAINS_PATH) or sys.argv[0].endswith(".distccOrig") or hasDistccParent():
		args[0] += ".distccOrig"
		if verbose: print("directly executing:" + str(args))
		
		# TODO - get execl working to avoid another process being invoked
		#os.execl(sys.executable, *(args))
		p = subprocess.Popen(args, shell=False)
		p.communicate()
		sys.exit(p.returncode)
	
	#if verbose: clientProxy.log(str(os.getpid()) + ": " + "compiling: " + str(" ".join(args)))
	clientProxy = connectToProxy("distccClient", bindip, "8080")
	startedCompile = False
	try:
		compilerPath = args[0]
		if verbose: clientProxy.log("compilerPath:" + compilerPath)
		(hosts, distccToolchainPath, pumpEnv) = callPyroMethod2(clientProxy, "startCompile", compilerPath)
		startedCompile = True
		env = os.environ.copy()
		env["DISTCC_HOSTS"] = " ".join(hosts)
		if verbose: 
			env["DISTCC_VERBOSE"]="1"
			env["DISTCC_FALLBACK"]="0"
			env["DISTCC_SAVE_TEMPS"]="1"
			
		for (name, value) in pumpEnv.items():
			env[name] = value

		# argh, distccd doesn't support relative paths :(
		newargs = [DISTCCTOOL_DISTCC_PATH, DISTCCTOOL_TOOLCHAINS_PATH + os.sep + distccToolchainPath + ".distccOrig"]

		newargs.extend(args[1:])
		extra = " with env:" + str(env)
		if verbose: clientProxy.log("running:" + " ".join(newargs) + extra)
	
		p = subprocess.Popen(newargs, shell=False, env=env)
		p.communicate()

		callPyroMethod2(clientProxy, "finishCompile", compilerPath)
		startedCompile = False
		if verbose: clientProxy.log("compile exitCode:" + str(p.returncode))
		sys.exit(p.returncode)
	except SystemExit:
		raise
	except KeyboardInterrupt:
		if startedCompile: callPyroMethod2(clientProxy, "finishCompile", compilerPath)
		print("terminated compile")
		sys.exit(-1)
	except:
		if verbose: 
			clientProxy.log("Unexpected error:" + str( sys.exc_info()[0]))
			clientProxy.log("".join(Pyro4.util.getPyroTraceback()))
		raise
	#finally:
	#	if verbose: clientProxy.log(str(os.getpid()) + ": " + "finished compiling: " + str(" ".join(args)))

def main():
	global ARGS, VERBOSE
	
	PARSER = argparse.ArgumentParser(description='distcc Tool')
	
	PARSER.add_argument('-compiler_root', default=[], action='append', help="Root to check for compiler. (only for mode=client)")
	PARSER.add_argument('-xcode_tasks', type=int, help="Set number of parallel XCode tasks. (only for mode=client)")
	PARSER.add_argument('-verbose', default=False, action='store_true', help="Verbose output.")
	PARSER.add_argument('-tools_path', help="Path to tools for clients to load (distcc, distccd, pump, lsdistcc) (only for mode=server)")
	PARSER.add_argument('-bindip', default=getIPAddress(), help="IP address to bind to.")
	PARSER.add_argument("-mode", choices=['client', 'server', 'compile', 'status'], required=True, help="compile is internal use only")
	PARSER.add_argument("args", nargs=argparse.REMAINDER, help="Compiler arguments (internal use only)")
	
	ARGS = PARSER.parse_args()
	VERBOSE = ARGS.verbose
	
	if not ARGS.bindip in SERVER_LIST: SERVER_LIST.append(ARGS.bindip)
	for i in range(0, len(ARGS.compiler_root)-1):
		ARGS.compiler_root[i] = os.path.abspath(ARGS.compiler_root[i])
	
	if ARGS.mode == "compile":
		compile(ARGS.bindip, ARGS.args, VERBOSE)
	elif ARGS.mode == "status":
		(hostName, serverProxy) = getServerProxy()
		status = callPyroMethod2(serverProxy, "status")
		print(status)
	elif ARGS.mode == "server":
		if ARGS.tools_path is None:
			print("tools_path is a required parameter")
			sys.exit(-1)
	
		ARGS.tools_path = os.path.abspath(ARGS.tools_path)
		DistCCToolServer(ARGS.bindip).start()
	elif ARGS.mode == "client":
		DistCCToolClient(ARGS.bindip).start()
	
if __name__ == '__main__':
	main()
