#!/usr/bin/env python
import cherrypy
import os
import sys
reload(sys)  # Reload does the trick!
sys.setdefaultencoding('UTF8')
import time
import json
import mimetypes
import socket
import random
import subprocess
import sqlite3
from mako.template import Template
from mako.lookup import TemplateLookup
import ast
import dircache
import urllib2
import urllib
import re
import traceback
from cookielib import CookieJar

global current_dir
current_dir = os.path.dirname(os.path.abspath(__file__))

global bs
bs = ""
if os.name == "posix":
    bs = "/"
if os.name == "nt":
    bs = "\\"

def template_reload(current_dir):
    lookup = TemplateLookup(directories=[current_dir+bs+'templates'])
    return lookup
    
lookup = template_reload(current_dir)
        
def serve_template(tmpl, **kwargs):
    """ loads a template and renders it """
    lookup = template_reload(current_dir)
    tmpl = lookup.get_template(tmpl)
    return tmpl.render(**kwargs)
    
def client(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    try:
        sock.sendall(message)
        data = {}
        data = ast.literal_eval(sock.recv(1024*16).replace("\\%s" % ("\\"), \
                                                                        "\\"))
    finally:
        sock.close()
        return data

global cj
cj = CookieJar()
    
fileext = [
"",
".py",
".html",
".txt",
".png",
".jpg",
".ico",
".css",
".js"
]

folderext = [
"index",
"index.py",
"index.html",
"index.txt",
"index.png",
"index.gif",
"index.jpg"
]

filetypes = {
".txt": "text/txt",
".png": "image/png",
".jpg": "image/jpg",
".ico": "image/vnd.microsoft.icon",
".css": "text/css",
".js": "text/js",
".mp4": "video/mp4"
}

def filepicker(filename,fileext):
    for data in fileext:
        if os.path.exists(filename+data):
            try:
                open(filename+data).read()
                filename = (filename+data)
            except Exception,e:
                filename = (filename+bs+"index"+data)
    return(filename)
    
    
def sysinfo():
    if os.name=="posix":
        (sysname, nodename, release, version, machine) = os.uname()
    else:
        (nodename, v4, v6) = socket.gethostbyaddr(socket.gethostname())
    return(nodename)
    
def sieve(sievedata,sievetype):
    if os.path.exists(os.path.abspath('pages')+bs+"sieve-"+sievetype+".py"):
        execfile(os.path.abspath('pages')+bs+"sieve-"+sievetype+".py",globals(),sievedata)
        return(sievedata)
    return()

def vhosts(virt_host):
    #print(virt_host)
    hosts = os.listdir(os.path.abspath('pages'))
    if ":" in virt_host:
        pos = virt_host.find(":")
        virt_host = virt_host[:pos]
    pos = virt_host.find(".")
    if os.path.exists(os.path.abspath('pages')+bs+virt_host[pos:]):
        data = virt_host[pos:]
        hostlen = len(data)
        return(data+bs+virt_host[:-hostlen])
    else:
        for data in hosts:
            if virt_host.endswith(data):
                hostlen = len(data)
                #print(data)
                logline = str(time.strftime("[%I:%M:%S %p]	Bad vhost: "+data+"	"+virt_host[:-hostlen]+"\n"))
                logging(logline)
                #print("Warning Bad vhost detection used, extra resources used")
                return(data+bs+virt_host[:-hostlen])

    
def notfound(cherrypy,virt_host,paramlines,list,params):
    cherrypy.response.status = 404
    logline = str(time.strftime("[%I:%M:%S %p]	"))+str(cherrypy.request.remote.ip)+"("+str(cherrypy.response.status)+")	["+virt_host+"/"+"/".join(list)+paramlines+"]	"+str(cherrypy.request.headers)+"\n"
    logging(logline)
    (sysname, nodename, release, version, machine) = os.uname()
    #debug = "<br>"+serve_template("debug.mako",sysname="", nodename=nodename, release="", version="", machine="")
    return("404<br>"+str("/"+"/".join(list))+debughandler(params))
    
def notfound2(cherrypy,e,virtloc,params):
    cherrypy.response.status = 404
    (sysname, nodename, release, version, machine) = os.uname()
    #debug = "<br>"+serve_template("debug.mako",sysname="", nodename=nodename, release="", version="", machine="")
    return("404<br>"+str(e).replace(virtloc,"/")+debughandler(params))
    
def debughandler(params):
    if "debug" in params:
        if params["debug"]=="1":
            (sysname, nodename, release, version, machine) = os.uname()
            lowdebuginfo = serve_template("debug.mako",sysname="", nodename=nodename, release="", version="", machine="")
            debuginfo = serve_template("debug.mako",sysname=sysname, nodename=nodename, release=release, version=version, machine=machine)
            if "v" in params:
                if not params["v"] == "1":
                    debuginfo = lowdebuginfo
            else:
                debuginfo = lowdebuginfo
        return(debuginfo)
    return("")
    
def logging(logline):
    nodename = sysinfo()
    logfolder = current_dir+bs+"logs"+bs+nodename+bs+time.strftime("%Y")+bs+time.strftime("%m")
    logfile = logfolder+bs+time.strftime("%d")+".txt"
    if not os.path.exists(logfolder):
        os.makedirs(logfolder)
    if os.path.exists(logfile):
        open(logfile,"a").write(logline)
        open(current_dir+bs+"logs"+bs+"today."+nodename+".log","a").write(logline)
    if not os.path.exists(logfile):
        open(logfile,"a").write(logline)
        open(current_dir+bs+"logs"+bs+"today."+nodename+".log","w").write(logline)
        
class WebInterface:
    """ main web interface class """

    def default(self, *args,**params):
        #print cj
        bad = False
        if "host" in cherrypy.request.headers:
            virt_host = cherrypy.request.headers["host"]
        else:
            cherrypy.response.status = 404
            return("")
        list = []
        for data in args:
            list.append(data)
        paramlines = "?"
        if not params=={}:
            for data in params:
                paramlines = paramlines+data+"="+params[data]+"&"
            paramlines = paramlines[:-1]
        if paramlines=="?":
            paramlines = ""
            
        #vhosts(virt_host)
            
        global lookup
        lookup = template_reload(current_dir)
            
        ###Start
        if os.path.exists(os.path.abspath('pages')+bs+"sieve-in.py"):
            datsieve = ""
            sievedata = {"cherrypy": cherrypy, "page":virt_host+bs+bs.join(list), "data": datsieve, "bad":bad}
            sievedata = sieve(sievedata,"in")
            bad = sievedata['bad']
            global cherrypy
            cherrypy = sievedata['cherrypy']
        if bad == False:
            headers = {}
            responsecode = 200
            try:
                virtloc = os.path.abspath('pages')+bs+vhosts(virt_host)+bs
            except Exception,e:
                cherrypy.response.status = 404
                logline = str(time.strftime("[%I:%M:%S %p]	"))+str(cherrypy.request.remote.ip)+"("+str(cherrypy.response.status)+")	["+virt_host+"/"+"/".join(list)+paramlines+"]	"+str(cherrypy.request.headers)+"\n"
                logging(logline)
                return("")
            if len(list)>=1:
                if str(list[0]).lower()=="static":
                    if not os.path.exists(current_dir+bs+bs.join(list)):
                        return(notfound(cherrypy,virt_host,paramlines,list,params))
                    if cherrypy.response.status==None:
                        cherrypy.response.status = 200
                    logline = str(time.strftime("[%I:%M:%S %p]	"))+str(cherrypy.request.remote.ip)+"("+str(cherrypy.response.status)+")	["+virt_host+"/"+"/".join(list)+paramlines+"]	"+str(cherrypy.request.headers)+"\n"
                    logging(logline)
                    #print(databack.status)
                    return cherrypy.lib.static.serve_file(current_dir+bs+bs.join(list))
            cherrypy.response.headers['X-Best-Pony'] = "Derpy Hooves"
            cherrypy.response.headers['X-Comment'] = "Someone is reading my headers... >_>"
            cherrypy.response.headers["Server"] = "RedServ 1.0"
            #datareturned = ""
            if not os.path.exists(virtloc):
                return("")
            filename = (virtloc+bs.join(list)).replace("..","").replace("//","/")
            #print(filename)
            try:
                bang = os.listdir(filename)
            except Exception,e:
                #print(e)
                bang = ""
                if str(e).startswith("[Errno 2] No such file or directory:"):
                    filename = filepicker(filename,fileext)
                    if not os.path.exists(filename):
                        return(notfound2(cherrypy,e,virtloc,params))
                if str(e).startswith("[Errno 20] Not a directory:"):
                    #print("got")
                    filename = filepicker(filename,fileext)
            if not bang=="":
                filename = filepicker(filename,folderext)
            for data in fileext:
                if filename.endswith(data) and os.path.exists(filename) and (not filename.endswith(".py")):
                    typedat = mimetypes.guess_type(filename)
                    #print(typedat)
                    (cherrypy.response.headers['Content-Type'],nothing) = typedat
            cherrypy.response.headers['Cache-Control'] = 'no-cache'
            datatoreturn = {"params":params,"datareturned":"'","cj":cj,"headers":headers,"response":responsecode,"request":cherrypy.request}
            try:
                if filename.endswith(".py"):
                    execfile(filename,globals(),datatoreturn)
                else:
                    f = open(filename, 'r').read()
                    cherrypy.response.status = 200
                    logline = str(time.strftime("[%I:%M:%S %p]	"))+str(cherrypy.request.remote.ip)+"("+str(cherrypy.response.status)+")	["+virt_host+"/"+"/".join(list)+paramlines+"]	"+str(cherrypy.request.headers)+"\n"
                    logging(logline)
                    return(f+debughandler(params))
            except Exception,e:
                #print(e)
                type_, value_, traceback_ = sys.exc_info()
                ex = traceback.format_exception(type_, value_, traceback_)
                trace = ""
                for data in ex:
                    trace = str(trace+data).replace("\n","<br>")
                cherrypy.response.status = 404
                datatoreturn["datareturned"] = "404<br>"+str(trace).replace(virtloc,"/")
                datatoreturn = sieve_out(datatoreturn)
                return(datatoreturn["datareturned"])
            datatoreturn = sieve(datatoreturn,"out")
            global cj
            cj = datatoreturn['cj']
            #cherrypy.request = datatoreturn['request']
            responsecode = datatoreturn['response']
            cherrypy.response.status = responsecode
            headers = datatoreturn['headers']
            if not (headers==""):
                for data in headers:
                    cherrypy.response.headers[data] = headers[data]
            #print(str(responsecode))
            logline = str(time.strftime("[%I:%M:%S %p]	"))+str(cherrypy.request.remote.ip)+"("+str(cherrypy.response.status)+")	["+virt_host+"/"+"/".join(list)+paramlines+"]	"+str(cherrypy.request.headers)+"\n"
            logging(logline)
            if cherrypy.response.headers['Content-Type']=="":
                cherrypy.response.headers['Content-Type']="charset=utf-8"
            else:
                cherrypy.response.headers['Content-Type']=cherrypy.response.headers['Content-Type']+"; charset=utf-8"
            return(datatoreturn["datareturned"])
        elif bad == True:
             
            logline = str(time.strftime("[%I:%M:%S %p]	"))+str(cherrypy.request.remote.ip)+"("+str(cherrypy.response.status)+")	["+virt_host+"/"+"/".join(list)+paramlines+"]	"+str(cherrypy.request.headers)+"\n"
            logging(logline)
            #cherrypy.response.timed_out = True
            return("")
      
    default.exposed = True
        

def web_init():
    print "Initalising web server..."
    global input
    input = {}
    if os.name=="posix":
        (sysname, nodename, release, version, machine) = os.uname()
    else:
        (nodename, v4, v6) = socket.gethostbyaddr(socket.gethostname())
    print nodename
    global_conf = {
        'global': { 'engine.autoreload.on': False,
#        'server.socket_host': '0.0.0.0',
#        'server.socket_port': 8081,
        'log.error_file': 'site.'+nodename+'.log',
        'log.screen': False,
        'gzipfilter.on':True,
        'tools.gzip.mime_types':['text/html', 'text/plain', 'text/css', 'text/*'],
        'tools.gzip.on':True,
        'tools.encode.on':True,
        'tools.decode.on':True
    }}
    application_conf = {
        #'/static': {
        #'tools.staticdir.on': True,
        #'tools.staticdir.dir': os.path.join(current_dir,
        #'static'),
        #},
        "/favicon.ico": {
        'tools.staticfile.on' : True,
        'tools.staticfile.filename' : os.path.join(current_dir,
        'static')+"/favicon.ico",
        }
    }
    cherrypy.config.update(global_conf)
    web_interface = WebInterface()
    cherrypy.tree.mount(web_interface, '/', config = application_conf)

    cherrypy.server.unsubscribe()

    server1 = cherrypy._cpserver.Server()
    server1.socket_port=8082
    server1._socket_host='0.0.0.0'
    server1.thread_pool=30
    server1.ssl_module = 'builtin'
    server1.ssl_certificate = os.path.join(current_dir,'cert.pem')
    #print(os.path.join(current_dir,'privkey.pem'))
    server1.ssl_private_key = os.path.join(current_dir,'privkey.pem')
    server1.ssl_certificate_chain = os.path.join(current_dir,'ca.pem')
    server1.subscribe()

    server2 = cherrypy._cpserver.Server()
    server2.socket_port=8081
    server2._socket_host="0.0.0.0"
    server2.thread_pool=30
    server2.subscribe()
    
    print("Web server started\nHTTP on port: "+str(server2.socket_port)+"\nHTTPS on port: "+str(server1.socket_port))
    cherrypy.engine.start()
    cherrypy.engine.block()
    #cherrypy.quickstart(web_interface, '/', config = application_conf)

os.chdir(sys.path[0] or '.')
db_loc = os.path.abspath('db')
pathing = [
"db",
"logs",
"pages",
"static",
"templates"
]
for data in pathing:
    if not os.path.exists(os.path.abspath(data)):
        os.mkdir(os.path.abspath(data))

def get_db_connection(name):
    filename = os.path.join(db_loc,name)
    return sqlite3.connect(filename, timeout=10)

web_init()
