

class setCache:
	def response(self, flow):
		# We only care about 200 responses
		if flow.response.status_code != 200:	return

		flow.response.headers["Cache-Control"] = "public, max-age=31536000"
		flow.response.headers["Expires"] = "Mon Dec  31 23:59:59 CET 2030"
		if "Pragma" in flow.response.headers: 
			del flow.response.headers["Pragma"]


def start():
	return setCache()

