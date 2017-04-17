import SimpleHTTPServer
import SocketServer
import argparse
from contextlib import contextmanager
import os

@contextmanager
def cd(newdir):
	prevdir = os.getcwd()
	os.chdir(os.path.expanduser(newdir))
	try:
		yield
	finally:
		os.chdir(prevdir)

def startServer(ip, port, d):
	Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
	SocketServer.TCPServer.allow_reuse_address = True
	httpd = SocketServer.TCPServer((ip, port), Handler)

	with cd(d):
		print "serving at port", port
		try:
			httpd.serve_forever()
		except:
			print "Closing the server."
			httpd.server_close()
			raise


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Create a web server')
	parser.add_argument("--port", "-p", type=int, help="Port to run at", default=80)
	parser.add_argument("--ip", "-i", type=str, help="IP to accept traffic at", required=True)
	parser.add_argument("--dir", "-d", type=str, help="Directory to serve", required=True)
	args = vars(parser.parse_args())

	startServer(args["ip"], args["port"], args["dir"])

