

class setCache:
	def response(self, flow):
		code = flow.response.status_code
		if code != 200 and code != 301 and code != 302:	return

		flow.response.headers["Cache-Control"] = "public, max-age=31536000"
		flow.response.headers["Expires"] = "Mon Dec  31 23:59:59 CET 2030"
		if "Pragma" in flow.response.headers: 
			del flow.response.headers["Pragma"]


def start():
	return setCache()

