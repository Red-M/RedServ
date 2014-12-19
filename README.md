RedServ
=======

RedServ is a web server built on top of Cherrypy and uses Mako for template rendering.

Requirements:
=============
- Python 2.7+
- Cherrypy3
- PyOpenSSL
- Mako
- Requests

Optional:
=========
- PHP5

Installing:
==========
1. Install Python 2.7 or higher

2. Install Cherrypy3 (python-cherrypy3)

3. Install mako (python-mako)

4. Install PyOpenSSL (python-openssl)

5. Install Requests (python-requests)

6. git clone https://github.com/Red-M/RedServ.git

Optional Install:
=================
- install php5-cli

Running:
========
1. Run ./webserver.py

2. Configure the settings via ./config (config file to be added sometime soon)

3. run ./webserver.py

4. Drop web site files into ./pages

optional:
- Add SSL certs and edit ./config to turn on SSL and to make sure the certs are named the same as in the config

additional:
PHP scripting at the current time is very limited, do not expect full apache support for PHP right now.

RedServ's main purpose is to provide an Apache2 + PHP like experience but with just pure Python (or with php and python).
The main web server file is very small and doesn't require as much work to get going.
The Python scripting will be documented but there will be examples provided for how everything works, for now have fun playing with it.

-Red_M
