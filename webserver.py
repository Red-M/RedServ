#!/usr/bin/env python
import cherrypy
import os
import sys
reload(sys)
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
import inspect
from cookielib import CookieJar

global current_dir
current_dir = os.path.dirname(os.path.abspath(__file__))
site_glo_data = {}

def config_init(configlocation):
    if not os.path.exists(configlocation):
        open(configlocation, 'w').write(inspect.cleandoc(
        r'''{
         "default_404": true,
         "HTTP":{
         "enabled":true,
         "port": 8080
         },
         "HTTPS":{
            "enabled":false,
            "port": 8081
         },
         "log": true
        }''') + '\n')

def config(configlocation):
    try:
        con = json.load(open(configlocation))
        return(con)
    except ValueError, e:
        print 'ERROR: malformed config!', e

def template_reload(current_dir):
    lookup = TemplateLookup(directories=[os.path.join(current_dir,'templates')])
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
                filename = (os.path.join(filename,"index"+data))
    return(filename)
    
    
def sysinfo():
    if os.name=="posix":
        (sysname, nodename, release, version, machine) = os.uname()
    else:
        (nodename, v4, v6) = socket.gethostbyaddr(socket.gethostname())
    return(nodename)
    
def sieve(sievedata):
    sievepath = os.path.join(os.path.abspath('pages'),"sieve.py")
    if os.path.exists(sievepath):
        execfile(sievepath,globals(),sievedata)
    return(sievedata)

def vhosts(virt_host):
    hosts = os.listdir(os.path.abspath('pages'))
    if ":" in virt_host:
        pos = virt_host.find(":")
        virt_host = virt_host[:pos]
    if "." in virt_host:
        pos = virt_host.find(".")+1
        vpath = os.path.join(os.path.abspath('pages'),virt_host[pos:])
        if os.path.exists(vpath):
            data = virt_host[pos:]
            hostlen = len(data)
            return(os.path.join(data,virt_host[:-hostlen-1]))
        else:
            for data in hosts:
                if virt_host.endswith(data):
                    hostlen = len(data)
                    logging("", 2, [data,virt_host,hostlen])
                    return(os.path.join(data,virt_host[:-hostlen]))
    else:
        return(os.path.join(os.path.abspath('pages'),virt_host))

    
def notfound(cherrypy,virt_host,paramlines,list,params):
    cherrypy.response.status = 404
    logging("",1,[cherrypy,virt_host,list,paramlines])
    (sysname, nodename, release, version, machine) = os.uname()
    return("404<br>"+str("/"+"/".join(list))+debughandler(params))
    
def notfound2(cherrypy,e,virtloc,params):
    cherrypy.response.status = 404
    (sysname, nodename, release, version, machine) = os.uname()
    return("404<br>"+str(e).replace(virtloc,"/")+debughandler(params))
    
def debughandler(params):
    if "debug" in params:
        if params["debug"]=="1":
            if "v" in params:
                if not params["v"] == "1":
                    debuginfo = "<br>\n<l>"+sysinfo()+"</l>"
                else:
                    debugtable = []
                    for data in os.uname():
                        debugtable.append(data)
                    debuginfo = "<br>\n<l>"+" ".join(debugtable)+"</l>"
            else:
                debuginfo = "<br>\n<l>"+sysinfo()+"</l>"
            return(debuginfo)
    return("")
    
def logging(logline,logtype,*extra):
    if conf["log"]==True:
        if logline == "":
            if len(extra)==0:
                return
            (extra,) = extra
            if logtype == 1: #general log line for normal requests
                cherrypy = extra[0]
                virt_host = extra[1]
                list = extra[2]
                paramlines = extra[3]
                logline = str(time.strftime("[%I:%M:%S %p]	"))+ \
                str(cherrypy.request.remote.ip)+"("+str(cherrypy.response.status)+\
                ")	["+virt_host+"/"+"/".join(list)+paramlines+"]	"+ \
                str(cherrypy.request.headers)+"\n"
                
            if logtype == 2: #bad vhost log line
                data = extra[0]
                virt_host = extra[1]
                hostlen = extra[2]
                logline = str(time.strftime("[%I:%M:%S %p]	Bad vhost: "+data+ \
                "	"+virt_host[:-hostlen]+"\n"))
                
        nodename = sysinfo()
        todaylog = os.path.join(current_dir,"logs","today."+nodename+".log")
        logfolder = os.path.join(current_dir,"logs",nodename,time.strftime("%Y"), \
        time.strftime("%m"))
        logfile = os.path.join(logfolder,time.strftime("%d")+".txt")
        if not os.path.exists(logfolder):
            os.makedirs(logfolder)
        if os.path.exists(logfile):
            open(logfile,"a").write(logline)
            open(todaylog,"a").write(logline)
        if not os.path.exists(logfile):
            open(logfile,"a").write(logline)
            open(todaylog,"w").write(logline)
        
class WebInterface:
    """ main web interface class """

    def default(self, *args,**params):
        global cj
        global lookup
        global cherrypy
        global site_glo_data
        
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
        if not virt_host in site_glo_data:
            site_glo_data[virt_host] = {}
            
        lookup = template_reload(current_dir) #template refresh
            
    ###Start
        if os.path.exists(os.path.join(os.path.abspath('pages'),"sieve.py")):
            datsieve = ""
            sievedata = {"sievetype":"in", "cherrypy": cherrypy, "page":virt_host+"/"+"/".join(list), "data": datsieve, "bad":bad}
            sievedata = sieve(sievedata) #pre-page render sieve
            bad = sievedata['bad']
            cherrypy = sievedata['cherrypy']
        if bad == False:
            headers = {}
            responsecode = 200
            try:
                virtloc = os.path.join(os.path.abspath('pages'),vhosts(virt_host))+os.sep
            except Exception,e:
                cherrypy.response.status = 404
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                return("")
            if len(list)>=1 and str(list[0]).lower()=="static":
                if str(list[0]).lower()=="static" and len(list)>=2:
                    if not os.path.exists(os.path.join(current_dir,os.sep.join(list))):
                        return(notfound(cherrypy,virt_host,paramlines,list,params))
                    if cherrypy.response.status==None:
                        cherrypy.response.status = 200
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    return cherrypy.lib.static.serve_file(current_dir+os.sep+os.sep.join(list))
                else:
                    cherrypy.response.status = 404
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    return("404")
            cherrypy.response.headers['X-Best-Pony'] = "Derpy Hooves"
            cherrypy.response.headers['X-Comment'] = "Someone is reading my headers... >_>"
            cherrypy.response.headers["Server"] = "RedServ 1.0"
            if not os.path.exists(virtloc):
                return("")
            filename = (virtloc+os.sep.join(list)).replace("..","").replace("//","/")
            try:
                bang = os.listdir(filename)
            except Exception,e:
                bang = ""
                if str(e).startswith("[Errno 2] No such file or directory:"):
                    filename = filepicker(filename,fileext)
                    if not os.path.exists(filename):
                        logging("", 1, [cherrypy,virt_host,list,paramlines])
                        return(notfound2(cherrypy,e,virtloc,params))
                if str(e).startswith("[Errno 20] Not a directory:"):
                    filename = filepicker(filename,fileext)
            if not bang=="":
                filename = filepicker(filename,folderext)
            for data in fileext:
                if filename.endswith(data) and os.path.exists(filename) and (not filename.endswith(".py")):
                    typedat = mimetypes.guess_type(filename)
                    (cherrypy.response.headers['Content-Type'],nothing) = typedat
            cherrypy.response.headers['Cache-Control'] = 'no-cache'
            datatoreturn = {
            "sievetype":"out", 
            "params":params,
            "datareturned":"'",
            "cj":cj,
            "headers":headers,
            "response":responsecode,
            "request":cherrypy.request,
            "filelocation":virtloc+os.sep.join(list),
            "filename":filename.replace(virtloc+os.sep.join(list),""),
            "global_site_data":site_glo_data,
            "site_data":site_glo_data[virt_host],
            "http_port":STDPORT,
            "https_port":SSLPORT
            }
            try:
                if filename.endswith(".py"):
                    execfile(filename,globals(),datatoreturn)
                else:
                    f = open(filename, 'r').read()
                    cherrypy.response.status = 200
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    return(f+debughandler(params))
            except Exception,e:
                type_, value_, traceback_ = sys.exc_info()
                ex = traceback.format_exception(type_, value_, traceback_)
                trace = ""
                for data in ex:
                    trace = str(trace+data).replace("\n","<br>")
                cherrypy.response.status = 404
                datatoreturn["datareturned"] = "404<br>"+str(trace).replace(virtloc,"/")
                datatoreturn = sieve(datatoreturn)
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                return(datatoreturn["datareturned"])
            datatoreturn = sieve(datatoreturn)
            cj = datatoreturn['cj']
            site_glo_data = datatoreturn['global_site_data']
            site_glo_data[virt_host] = datatoreturn['site_data']
            responsecode = datatoreturn['response']
            cherrypy.response.status = responsecode
            headers = datatoreturn['headers']
            if not (headers==""):
                for data in headers:
                    cherrypy.response.headers[data] = headers[data]
            logging("", 1, [cherrypy,virt_host,list,paramlines])
            if cherrypy.response.headers['Content-Type']=="":
                cherrypy.response.headers['Content-Type']="charset=utf-8"
            else:
                cherrypy.response.headers['Content-Type']=cherrypy.response.headers['Content-Type']+"; charset=utf-8"
            return(datatoreturn["datareturned"])
        elif bad == True:
            logging("", 1, [cherrypy,virt_host,list,paramlines])
            return("")
    ###end
      
    default.exposed = True
        

def web_init():
    print "Initalising web server..."
    config_init(os.path.join(current_dir,"config"))
    global conf
    conf = config(os.path.join(current_dir,"config"))
    if conf["HTTPS"]["enabled"]==False and conf["HTTP"]["enabled"]==False:
        print("ERROR::You need to enable one transfer protocol, either HTTP or HTTPS in the config")
        exit()
    global input
    input = {}
    if os.name=="posix":
        (sysname, nodename, release, version, machine) = os.uname()
    else:
        (nodename, v4, v6) = socket.gethostbyaddr(socket.gethostname())
    print nodename
    global_conf = {
        'global': { 'engine.autoreload.on': False,
        'log.error_file': 'site.'+nodename+'.log',
        'log.screen': False,
        'gzipfilter.on':True,
        'tools.gzip.mime_types':['text/html', 'text/plain', 'text/css', 'text/*'],
        'tools.gzip.on':True,
        'tools.encode.on':True,
        'tools.decode.on':True
    }}
    application_conf = {
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

    if conf["HTTPS"]["enabled"]==True:
        server1 = cherrypy._cpserver.Server()
        global SSLPORT
        SSLPORT = conf["HTTPS"]["port"]
        server1.socket_port=SSLPORT
        server1._socket_host='0.0.0.0'
        server1.thread_pool=30
        server1.ssl_module = 'builtin'
        server1.ssl_certificate = os.path.join(current_dir,'cert.pem')
        server1.ssl_private_key = os.path.join(current_dir,'privkey.pem')
        server1.ssl_certificate_chain = os.path.join(current_dir,'ca.pem')
        server1.subscribe()
    if conf["HTTP"]["enabled"]==True:
        server2 = cherrypy._cpserver.Server()
        global STDPORT
        STDPORT = conf["HTTP"]["port"]
        server2.socket_port=STDPORT
        server2._socket_host="0.0.0.0"
        server2.thread_pool=30
        server2.subscribe()
    
    strprnt = "Web server started\n"
    if conf["HTTP"]["enabled"]==True:
        strprnt = strprnt+"HTTP on port: "+str(server2.socket_port)+"\n"
    if conf["HTTPS"]["enabled"]==True:
        strprnt = strprnt+"HTTPS on port: "+str(server1.socket_port)
    print(strprnt)
    cherrypy.engine.start()
    cherrypy.engine.block()

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
