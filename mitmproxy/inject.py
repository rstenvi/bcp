
from bs4 import BeautifulSoup
import argparse
from mitmproxy import ctx

try:
	from mitmproxy.models import HTTPResponse
except ImportError:
	from mitmproxy.http import HTTPResponse

import imp, os
common = imp.load_source('common', os.path.abspath(os.path.join('modules', 'bcp_shared.py')))

#from pprint import pprint

class Injection:
	def __init__(self):

		return

	def request(self, flow):
		# This will often cause problems later, so we just remove it
		if "Accept-Encoding" in flow.request.headers:	del flow.request.headers["Accept-Encoding"]

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
				"",
				common.list2headers(res.get("headers", []))
			)
			r.raw_content = res.get("data").encode()
			flow.response = r
		return


	def response(self, flow):
		if flow.response.status_code == 304:	return


		ll = common.bcpConfig.foundMatch(
				flow.request.headers["host"],
				flow.request.path,
				"inject",
				False
			)
		try:
			c = flow.response.content
		except:
			print("Unable to get content")
			return
		html = False
		if flow.response.headers.get("content-type", "").find("html") != -1:
			c = BeautifulSoup(c, "html.parser")
			html = True
		
		for l in ll:
			if flow.response.headers.get("content-type", "").find("html") != -1:
				c = BeautifulSoup(str(c), "html.parser")
			action = l.get("placement",{}).get("action", "")
			ins = l.get("data", "")
			if l.get("content-type", "").find("html") != -1:
				ins = BeautifulSoup(ins, "html.parser")

			if action == "replaceAll":
				c = ins
			elif action == "replace":
				c = str(c).replace(l.get("placement",  {}).get("search",""), str(ins))
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
			elif action == "attribute":
				tag = l.get("placement", {}).get("tag", "html")
				where = l.get("placement", {}).get("where", "test")
				cont = c.find(tag.encode())
				if cont != None:
					print(where)
					print(ins)
					cont[where] = ins
				c = BeautifulSoup(str(c), "html.parser")

		if html == True:
			flow.response.content = str(c).encode()
		else:
			flow.response.content = c
		return

def start():
	parser = argparse.ArgumentParser()
	parser.add_argument("config", type=str)
	args = parser.parse_args()
	if common.bcpConfig.has_initialized() == False:
		common.bcpConfig.init(args.config)
	return Injection()


