
from bs4 import BeautifulSoup
import argparse
from mitmproxy import ctx

try:
	from mitmproxy.models import HTTPResponse
except ImportError:
	from mitmproxy.http import HTTPResponse

import imp, os
common = imp.load_source('common', os.path.abspath(os.path.join('modules', 'bcp_shared.py')))


class Injection:
	def __init__(self):

		return
	def request(self, flow):
		ll = common.bcpConfig.foundMatch(
				flow.request.headers["host"],
				flow.request.path,
				"inject",
				True
			)
		ll2 = common.bcpConfig.foundMatch(
				flow.request.headers["host"],
				flow.request.path,
				"serve",
				False
			)
		
		# Can only be one response, if multiple we take the first
		res=None
		if len(ll) > 0:
			res = ll[0]
		if len(ll2) > 0:
			res = ll2[0]
		if res != None:
			r = HTTPResponse.make(
				200,
				str(res.get("data", "")),
				res.get("headers", [])
			)
			flow.response = r
		return


	def response(self, flow):
		ll = common.bcpConfig.foundMatch(
				flow.request.headers["host"],
				flow.request.path,
				"inject",
				False
			)
		c = flow.response.content
		html = False
		if flow.response.headers.get("content-type", "").find("html") != -1:
			c = BeautifulSoup(flow.response.content, "html.parser")
			html = True
		
		for l in ll:
			action = l.get("placement",{}).get("action", "")
			ins = l.get("data", "")
			if l.get("content-type", "") == "html":
				ins = BeautifulSoup(l.get("data", ""), "html.parser")

			if action == "replaceAll":
				c = ins
			elif action == "insert" and html:
				tag = l.get("placement", {}).get("tag", "head")
				pos = 0
				where = l.get("placement", {}).get("where", "")
				if where == "last":
					pos = len(c.find(tag))
				cont = c.find(tag)
				if cont != None:
					cont.insert(pos, ins)
					c = BeautifulSoup(str(c), "html.parser")
				else:
					print("NOT FOUND")

		flow.response.text = str(c)
		return

def start():
	parser = argparse.ArgumentParser()
	parser.add_argument("config", type=str)
	args = parser.parse_args()
	if common.bcpConfig.has_initialized() == False:
		common.bcpConfig.init(args.config)
	return Injection()


