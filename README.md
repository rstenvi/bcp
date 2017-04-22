# BCP

Tool to help in crafting exploits that take advantage of the browser cache. The
tool is divided into separate scripts that perform its own dedicated task.

## Overview
The following scripts for mitmproxy exist:

1. mitmprox/cache.py - changes the HTTP headers to increase the time period for
caching
2. mitmproxy/sslstrip.py - re-implementation of sslStrip, used to downgrade connection
from HTTPS to HTTP (when connection starts over HTTP).
3. mitmproxt/inject.py - inject content on sites.

In combination, the scripts can be used to change the content of web sites and
have the changed content persist in the user's browser. An example of an attack
is described below:
1. The attacker is able to perform a MITM-attack (using ARPs-poofing, fake WiFi
Hotspot, etc)
2. During the MITM-attack, the attacker inserts invisible <iframes> on every web
site the user visits. The iframes points to a web site the attacker wants to
target. This web site must not use HSTS (HSTS-rule must not be stored in
browser).
3. When the users browser connects to the targeted web site, malicious
JavaScript is inserted. The malicious JS can for example read username and
password when typed in and send it back to the attacker.
4. After the MITM-attack is over, the forged pages will still be stored in the
cache by the browser. If the user attempts to login on the targeted web site,
the malicious JS will execute and the attacker will retrieve the credentials.

The malicious JS can execute in two different scenarios (both during active
MITM-attack and after):
1. When the victim visits one of the web sites that load the targeted web site
as an iframe.
2. When the user navigates to the targeted web site.

This same attack also works on private IPs. During the MITM-attack, the attacker
can insert iframes pointing to private IPs and serve malicious content when the
browser connects. This malicious content will be served when the victim connects
to the web site on a different network. Any malicious JavaScript can then
communicate with the private server.

## Example

An example of inserting JavaScript on a site has been created in the config
file under examples/config/. The following command will insert iframes pointing
to example.com and insert JS when the actual site is loaded.

	mitmdump -p 8080 --host --ignore ':443$' --script mitmproxy/sslstrip.py \
	--script mitmproxy/cache.py  --script 'mitmproxy/inject.py examples/config/example.com.json'

The functionality for creating a virtual IP (only works on Linux) has been put
in a separate script.

	sudo python modules/virtservers.py -c examples/config/virtip.json -i lo

Basic functionality for modifying and providing custom DNS responses also exist

	sudo python3 modules/dns.py --ip 127.0.0.1 --port 53 --config examples/config/dns.json

## TODO

1. Document the various features
2. Implement appcache support - need to create wrapper around existing functionality

