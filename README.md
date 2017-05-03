RedServ
=======

RedServ is a web framework built on top of Cherrypy.

RedServ's main purpose is to provide an Apache2 + PHP like experience but with just pure Python (or with php and python).
The main web server file is very small and doesn't require as much work to get going.
The Python scripting will be documented but there will be examples provided for how everything works, for now have fun playing with it.

-Red_M

Requirements:
=============
- Python 2.7+
- Cherrypy
- Requests
- Watchdog

Recommended:
============
- PyOpenSSL

Optional:
=========
- php<version>-fpm

Installing:
==========
1. Install Python 2.7 or higher

2. Install requirements (pip install -r ./requirements.txt)

3. git clone https://bitbucket.org/Red_M/redserv.git


Running:
========
1. Run ./webserver.py

2. Quit ./webserver.py, configure the settings via ./config

3. Run ./webserver.py

4. Drop web site files into ./pages

Optional:
=========
- Add SSL certs into ./certs and edit ./config to turn on HTTPS and to make sure the certs are pathed to properly as set in ./config

Additional:
===========
PHP scripting at the current time is very limited, do not expect full apache support for PHP right now.

