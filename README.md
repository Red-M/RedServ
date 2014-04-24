RedServ
=======

RedServ is a web server built on top of Cherrypy and uses Mako for the template rendering.

Requirements:
- Python 2.7+
- Cherrypy3
- Mako

Installing:
1. Install Python 2.7 or higher
2. Install Cherrypy or Cherrypy3 on ubuntu (python-cherrypy or python-cherrypy3)
3. Install mako (python-mako)
4. git clone https://github.com/Red-M/RedServ.git
5. Run ./webserver.py
6. Configure the setting via ./config (config file to be added sometime soon)
7. run ./webserver.py
8. Drop web site files into ./pages

opitional:
- Add SSL certs and edit ./config to turn on and to make sure the certs are named the same as in the config


RedServ's main purpose is to provide an Apache2 + PHP like experience but with just pure Python.
The main web server file is very small and doesn't require as much work to get going.
The Python scripting will be documented but there will be examples provided for how everything works, for now have fun playing with it.

-Red_M
