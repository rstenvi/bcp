
import json
import argparse
import sys, socket
import dnslib

#from pprint import pprint

class DNSServer:
	def __init__(self, upstream, override, resolve):
		self.upstream = upstream
		self.port = 53

		self.override = override
		self.resolve = resolve

	def set_questions(self, d, qs, res):
		reverse = {}
		ans = {}

		for i in range(0, len(d.questions)):
			qstr = str(d.questions[i].get_qname())

			# Check if overriden with new hostname
			if qstr[:-1] in qs:
				d.questions[i].set_qname(qs.get(qstr[:-1]) + ".")
				reverse[qs.get(qstr[:-1])] = qstr[:-1]

			# Check if we should resolve it to IP
			elif qstr[:-1] in res:
				ans[qstr[:-1]] = dnslib.RR(
					qstr[:-1],
					rdata=dnslib.A(res[qstr[:-1]])
				)
				
		return (d, reverse, ans)

	def set_responses(self, d, rs, ans):
		for i in range(0, len(d.rr)):
			rstr = str(d.rr[i].get_rname())
			if rstr[:-1] in rs:
				d.rr[i].set_rname(rs.get(rstr[:-1]) + ".")
			if rstr[:-1] in ans:
				d[rr] = ans[rstr[:-1]]
				del ans[rstr[:-1]]

		# Any questions that has not been answered we must answer
		for key, value in ans.items():
			d.add_answer(value)
		return d

	def forward(self, data):
		d = dnslib.DNSRecord.parse(data)

		(d, reverse, ans) = self.set_questions(d, self.override, self.resolve)

		# If all answers have been found we can simply respond
		if len(ans.keys()) == len(d.questions):
			for key, value in ans.items():
				d.add_answer(value)
			return (d.pack(), None)

		# We have some remaining questions we forward to upstream server
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		server = (self.upstream, self.port)
		try:
			sent = sock.sendto(d.pack(), server)
			data, server = sock.recvfrom(4096)
			d = dnslib.DNSRecord.parse(data)
			(d, garbage, garbage2) = self.set_questions(d, reverse, {})
			d = self.set_responses(d, reverse, ans)

		finally:
			sock.close()

		return (d.pack(), server)



def udpServer(ip, port, dns):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_address = (ip, port)

	sock.bind(server_address)
	while True:
		try:
			data, client = sock.recvfrom(4096)
		except:
			print("Closing the connection")
			sock.close()
			break
		if data:
			data, dns_server = dns.forward(data)
			sock.sendto(data, client)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='DNS server')
	parser.add_argument("--port", "-p", type=int, help="Port to run at", default=53)
	parser.add_argument("--ip", "-i", type=str, help="IP to accept traffic at", required=True)
	parser.add_argument("--config", "-c", type=str, help="Config file", required=True)
	args = vars(parser.parse_args())

	with open(args["config"], "r") as f:
		data = json.loads(f.read())
	
	data = data.get("dns", {})
	dns = DNSServer(data.get("upstream", "8.8.8.8"), data.get("redirection", {}), data.get("resolve", {}))
	
	print("Staring DNS server")
	udpServer(args["ip"], args["port"], dns)
