import argparse
import os, sys
import json
import multiprocessing
import subprocess
import signal

from server import startServer

def validIPv4(ipv4):
	rets = []
	parts = ipv4.split(".")
	if len(parts) != 4:
		return False
	for p in parts:
		n = int(p)
		if n < 0 or n > 255:	return false
		rets.append(n)
	return ".".join(str(x) for x in rets)


def startVirtServers(data, interface):
	procs=[]
	i=0
	for e in data.get("virtualservers", []):
		# We do a check on the IP (for sanity and also because it's used in the command below)
		ip=validIPv4(e["ip"])
		if ip == False:
			print "Not a valid IP"
			sys.exit(1)

		sdir=e["servedir"]
		port=e["port"]

		subprocess.call("ifconfig " + interface + ":" + str(i) + " " + ip, shell=True)

		p = multiprocessing.Process(target=startServer, args=(ip,port,sdir,))
		procs.append(p)
		p.start()
		i+=1

	try:
		signal.pause()
	except:
		for p in procs:
			p.terminate()

		# Shut down the interfaces
		i=0
		for e in data.get("virtualservers", []):
			subprocess.call("ifconfig " + interface + ":" + str(i) + " down", shell=True)

		sys.exit(0)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Create a web server')
	parser.add_argument("--config", "-c", type=str, help="Config file (json)", required=True)
	parser.add_argument("--interface", "-i", type=str, help="interface to use", required=True)
	args = vars(parser.parse_args())

	data=None
	with open(args["config"], "r") as f:
		data = json.loads(f.read())

	startVirtServers(data, args["interface"])
