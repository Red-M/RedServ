#!/usr/bin/env python2
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
import cgi
try:
    import OpenSSL
    global SSL_imported
    SSL_imported = True
except Exception,e:
    print("ERROR: Could not load OpenSSL library. Disabling SSL cert generation.")
    SSL_imported = False
try:
    import requests
    global reqcj
    requests.cookie_session = requests.Session()
except Exception,e:
    print("ERROR: Could not load requests library.")
from cookielib import CookieJar

global cj
cj = CookieJar()

os.chdir('.' or sys.path[0])
global current_dir
folders = sys.argv[0].split(os.sep)
proper_path = os.sep.join(folders[0:-1])
current_dir = os.path.join(os.getcwd(),proper_path)
if current_dir.endswith("."):
    current_dir = current_dir[0:-1]
if folders[-1] in os.listdir(current_dir):
    print("INFO: Found webserver path")
else:
    print("INFO: Bad web server path")


global exed
exed = False
if current_dir.endswith(".zip"):
    exed = True
site_glo_data = {}

class RedServer(object):
    def __init__(self):
        self.nologging = []
        self.nologgingstart = []
        self.nologgingend = []
        
        self.staticfileserve = staticfileserve
        
        self.noserving = []
        self.noservingstart = []
        self.noservingend = []
        
        self.basicauth = []
        self.basicauthstart = []
        self.basicauthend = []
        
        #self.server1 = cherrypy._cpserver.Server()
        #self.server2 = cherrypy._cpserver.Server()
        self.http_port = 8080
        self.https_port = 8081
        
        self.lookup = self.template_reload(current_dir)
        os.chdir('.' or sys.path[0])
        self.current_dir = os.path.abspath('.')

    def test(self,out):
        print(out)
        
    def force_https(self,cherrypy,url,redirect=True):
        if redirect==True:
            if not cherrypy.request.local.port==self.https_port:
                if not url.startswith("https://"):
                    url = "https://"+url
                raise(cherrypy.HTTPRedirect(url))
            else:
                return("")
        #add reserv based message saying to use https here.
            
    
    def trace_back(self):
        type_, value_, traceback_ = sys.exc_info()
        ex = traceback.format_exception(type_, value_, traceback_)
        trace = ""
        for data in ex:
            trace = str(trace+data)
        trace = cgi.escape(trace).encode('utf-8', 'xmlcharrefreplace').replace("\n","<br>")
        return(trace)
        
    def TCP_dict_client(self, ip, port, message):
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
            
    def TCP_client(self, ip, port, message, message_size=1024):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        try:
            sock.sendall(message)
            response = sock.recv(message_size)
            sock.close()
            return(response)
        except Expection,e:
            return(e)
        
    def debugger(self,lvl=5,message=""):
        if lvl==0:
            lvl = "FATAL"
        if lvl==1:
            lvl = "CRITICAL"
        if lvl==2:
            lvl = "ERROR"
        if lvl==3:
            lvl = "INFO"
        if lvl==4:
            lvl = "MESSAGE"
        if lvl==5:
            lvl = "DEBUG"
        if "\n" in message:
            message = message.replace("\n","\n"+str(lvl)+": ")
        print(str(lvl)+": "+message)
        
    def cached_config_load(self,name,conf_loc,site_data):
        if not name=="":
            name = "_"+name
        last_config_load = os.path.getmtime(conf_loc)
        if (not "config"+name+"_time" in site_data) or (last_config_load>site_data["config"+name+"_time"]):
            site_data["config"+name] = json.load(open(conf_loc))
            site_data["config"+name+"_time"] = last_config_load
        return(site_data)

    def nolog(self,page=None,domain=None,startingwith=None,endingwith=None):
        if not page==None:
            if not page in self.nologging:
                self.nologging.append(page)
        if not domain==None:
            if not domain in self.nologging:
                self.nologging.append(domain)
        if not startingwith==None:
            if not startingwith in self.nologgingstart:
                self.nologgingstart.append(startingwith)
        if not endingwith==None:
            if not endwith in self.nologgingend:
                self.nologgingend.append(endingwith)
            
    def log(self,page=None,domain=None,startingwith=None,endingwith=None):
        if not page==None:
            if page in self.nologging:
                self.nologging.remove(page)
        if not domain==None:
            if domain in self.nologging:
                self.nologging.remove(domain)
        if not startingwith==None:
            if startingwith in self.nologgingstart:
                self.nologgingstart.remove(startingwith)
        if not endingwith==None:
            if endwith in self.nologgingend:
                self.nologgingend.remove(endingwith)
    
    def serve(self,domain,page):
        virt_page = domain+"/"+page
        if virt_page in self.noserving:
            self.noserving.remove(virt_page)
    
    def noserve(self,domain,page):
        virt_page = domain+"/"+page
        if not virt_page in self.noserving:
            self.noserving.append(virt_page)
            
    def template_reload(self, current_dir):
        lookup = TemplateLookup(directories=[os.path.join(current_dir,'templates')])
        return lookup
            
    def serve_template(self, tmpl, **kwargs):
        """ loads a template and renders it """
        lookup = self.template_reload(current_dir)
        tmpl = lookup.get_template(tmpl)
        return tmpl.render(**kwargs)
        
    def sysinfo(self):
        if os.name=="posix":
            (sysname, nodename, release, version, machine) = os.uname()
        else:
            (nodename, v4, v6) = socket.gethostbyaddr(socket.gethostname())
        return(nodename)
    
    def basic_auth(self, realm, users):
        checkpassword = cherrypy.lib.auth_basic.checkpassword_dict(users)
        cherrypy.response.headers['WWW-Authenticate'] = 'Basic realm="'+realm+'"'
        try:
            cherrypy.lib.auth_basic.basic_auth(realm, checkpassword)
        except Exception,e:
            if type(e)==type(cherrypy.HTTPError(404)):
                status, error = e
                raise(cherrypy.HTTPError(status,error))
        self.loggedinuser = cherrypy.request.login
        return(self.loggedinuser)
        
    def basicauthprotect(self,page=None,domain=None,startingwith=None,endingwith=None):
        if not page==None:
            if not page in self.basicauth:
                self.basicauth.append(page)
        if not domain==None:
            if not domain in self.basicauth:
                self.basicauth.append(domain)
        if not startingwith==None:
            if not startingwith in self.basicauthstart:
                self.basicauthstart.append(startingwith)
        if not endingwith==None:
            if not endwith in self.basicauthend:
                self.basicauthend.append(endingwith)
    
    def serve_static_file(self,virt_host,list,paramlines,filename):
        cherrypy.response.status = 200
        logging("", 1, [cherrypy,virt_host,list,paramlines])
        #caching header so that browsers can cache our content
        cherrypy.response.headers['Last-Modified'] = os.path.getmtime(filename)
        typedat = mimetypes.guess_type(filename)
        if not typedat==(None,None):
            return(cherrypy.lib.static.serve_file(filename))
        else:
            return(cherrypy.lib.static.serve_download(filename))
    
    def static_file_serve(self,cherrypy,filename):
        #caching header so that browsers can cache our content
        cherrypy.response.headers['Last-Modified'] = os.path.getmtime(filename)
        typedat = mimetypes.guess_type(filename)
        if not typedat==(None,None):
            return(self.staticfileserve(cherrypy.lib.static.serve_file(filename)))
        else:
            return(self.staticfileserve(cherrypy.lib.static.serve_download(filename)))

class staticfileserve(Exception):
     def __init__(self, value):
         self.value = value
     def __str__(self):
         return repr(self.value)
 
def config_init(config_location):
    if not os.path.exists(config_location):
        open(config_location, 'w').write(inspect.cleandoc(
        r'''{
         "HTTP":{
         "enabled": true,
         "port": 8080
         },
         "HTTPS":{
            "enabled": false,
            "port": 8081
         },
         "default_404": true,
         "vhosts-enabled": true,
         "vhost-lookup": "domains",
         "sessions": false,
         "php": false,
         "log": true
        }''') + '\n')

def config(config_location):
    try:
        if os.path.getmtime(config_location)>config_cache[1]:
            config_cache[0] = json.load(open(config_location))
            config_cache[1] = os.path.getmtime(config_location)
        return(config_cache[0])
    except ValueError, e:
        print 'ERROR: malformed config!', e
    
def TCP_client(ip, port, message):
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
    
fileext = [
"",
".py",
".php",
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
".py",
"index.php",
".php",
"index.html",
".html",
"index.txt",
".txt",
"index.png",
".png",
"index.gif",
".gif",
"index.jpg",
".jpg"
]


def filepicker(filename,fileext):
    for data in fileext:
        if not data.startswith("."):
            file = os.path.join(filename,data)
        else:
            file = filename+data
        if os.path.exists(file):
            try:
                if os.path.isfile(file):
                    return(file)
            except Exception,e:
                pass
    return(filename)
    
def create_ssl_cert(cert_dir="."):
    CERT_FILE = "cert.pem"
    KEY_FILE = "privkey.key"
    C_F = os.path.join(cert_dir, CERT_FILE)
    K_F = os.path.join(cert_dir, KEY_FILE)
    return(C_F,K_F)
    
def SSL_cert_gen(nodename):
    if SSL_imported==True:
        (C_F,K_F) = create_ssl_cert()
        if not os.path.exists(C_F) or not os.path.exists(K_F):
            k = OpenSSL.crypto.PKey()
            k.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
            cert = OpenSSL.crypto.X509()
            cert.get_subject().C = "na"
            cert.get_subject().ST = "n/a"
            cert.get_subject().L = "n/a"
            cert.get_subject().O = "n/a"
            cert.get_subject().OU = "n/a "+str(time.time())
            cert.get_subject().CN = nodename
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(315360000)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            cert.sign(k, 'sha256')
            open(C_F, "wt").write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            open(K_F, "wt").write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k))
    else:
        exit()

    
def sieve(sievedata,sieve_cache):
    sieves = []
    sieves.append((os.path.join(os.path.abspath('pages'),"sieve.py"),"global"))
    sieves.append((os.path.join(os.path.abspath(sievedata["vhost_location"]),"sieve.py"),sievedata["this_domain"]))
    for data in sieves:
        (sievepath,sievename) = data
        if not sievename in sieve_cache:
            sieve_cache[sievename] = []
        (sievedata,sieve_cache[sievename]) = sieve_exec(sievedata,sieve_cache[sievename],sievepath,sievename)
    return(sievedata,sieve_cache)

def sieve_exec(sievedata,sievecache,sievepath,sievename):
    if os.path.exists(sievepath):
        sievetime = os.path.getmtime(sievepath)
        if not sievename=="global":
            RedServ.noserve(sievedata["this_domain"],"sieve.py")
        if not sievecache==[]:
            if sievecache[1] < sievetime:
                sievecache[0] = compile(open(sievepath,'r').read(),'<string>','exec')
                sievecache[1] = sievetime
        else:
            sievecache.append(compile(open(sievepath,'r').read(),'<string>','exec'))
            sievecache.append(sievetime)
        sievedata.update(globals())
        exec(sievecache[0],sievedata)
    return(sievedata,sievecache)
    
def exec_page_script(filename,datatoreturn,python_page_cache):
    if not filename in python_page_cache:
        python_page_cache[filename] = []
    page_time = os.path.getmtime(filename)
    if not python_page_cache[filename]==[]:
        if python_page_cache[filename][1] < page_time:
            python_page_cache[filename][0] = compile(open(filename,'r').read(),'<string>','exec')
            python_page_cache[filename][1] = page_time
    else:
        python_page_cache[filename].append(compile(open(filename,'r').read(),'<string>','exec'))
        python_page_cache[filename].append(page_time)
    exec(python_page_cache[filename][0],datatoreturn)
    return(datatoreturn)
    
def vhosts(virt_host):
    lookuptypes = [
    "domains",
    "single-hosts",
    "ips",
    "none"
    ]
    global conf
    config_vhost_lookup = conf["vhost-lookup"].lower()
    hosts = os.listdir(os.path.abspath('pages'))
    if ":" in virt_host:
        pos = virt_host.find(":")
        virt_host = virt_host[:pos]
    if config_vhost_lookup=="domains":
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
    if config_vhost_lookup=="single-hosts":
        return(os.path.join(data,virt_host))
    if config_vhost_lookup=="ips":
        split = virt_host.split(".")
        host = split[0]+"."+split[1]+"."+split[2]
        return(os.path.join(os.path.abspath('pages'),host,split[3]))
    if config_vhost_lookup=="none":
        return("")
    
    
    if not config_vhost_lookup in lookuptypes:
        RedServ.debugger(0,"VHOST LOOKUP IS INCORRECTLY SET TO AN INVALID VALUE! PLEASE EDIT THE CONFIG TO FIX THIS!")
        print(conf["vhost-lookup"])
        exit()

    
def notfound(cherrypy,virt_host,paramlines,list,params):
    cherrypy.response.status = 404
    logging("",1,[cherrypy,virt_host,list,paramlines])
    (sysname, nodename, release, version, machine) = os.uname()
    return("404<br>"+str("/"+"/".join(list))+debughandler(params))
    
def notfound2(cherrypy,e,virtloc,params):
    cherrypy.response.status = 404
    (sysname, nodename, release, version, machine) = os.uname()
    return("404<br>"+str(e).replace(virtloc,"/")+debughandler(params))
    
def PHP(path):
    proc = subprocess.check_output(["php",path])
    return(proc)
    
def debughandler(params):
    if "debug" in params:
        if params["debug"]=="1":
            if "v" in params:
                if not params["v"] == "1":
                    debuginfo = "<br>\n<l>"+RedServ.sysinfo()+"</l>"
                else:
                    debugtable = []
                    debuginfo = "<br>\n<l>"+" ".join(os.uname())+"</l>"
            else:
                debuginfo = "<br>\n<l>"+RedServ.sysinfo()+"</l>"
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
                this_page = virt_host+"/"+"/".join(list)
                no_log = False # varible to decide to log or to not to log.
                if len(RedServ.nologgingstart)>0:
                    for data in RedServ.nologgingstart:
                        if data.endswith(".*"):
                            if this_page.startswith(data[:-2]):
                                no_log = True
                if len(RedServ.nologgingend)>0:
                    for data in RedServ.nologgingend:
                        if data.startswith(".*"):
                            if this_page.endswith(data[2:]):
                                no_log = True
                if len(RedServ.nologging)>0:
                    if this_page in RedServ.nologging:
                        no_log = True
                    if virt_host in RedServ.nologging:
                        no_log = True
                if no_log==False:
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
                
        nodename = RedServ.sysinfo()
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
            
def conf_reload(conf):
    global STDPORT
    global SSLPORT
    old_conf = config_cache[0]
    old_time = config_cache[1]
    new_conf = config(os.path.join(current_dir,"config"))
    config_cache[0] = new_conf
    if not old_time==config_cache[1]:
        new_conf["HTTP"]["enabled"] = old_conf["HTTP"]["enabled"]
        new_conf["HTTPS"]["enabled"] = old_conf["HTTPS"]["enabled"]
        if not new_conf["HTTP"]["port"]==old_conf["HTTP"]["port"]:
            print("Please restart RedServ to change port on HTTP to "+str(new_conf["HTTP"]["port"]))
            #RedServ.server1.unsubscribe()
            #RedServ.server1.stop()
            #RedServ.server1.socket_port=new_conf["HTTP"]["port"]
            #RedServ.server1.start()
            #RedServ.server1.subscribe()
            #print(dir(RedServ.server1))
        if not new_conf["HTTPS"]["port"]==old_conf["HTTPS"]["port"]:
            print("Please restart RedServ to change port on HTTPS to "+str(new_conf["HTTPS"]["port"]))
        #new_conf["HTTP"]["port"] = STDPORT
        #new_conf["HTTPS"]["port"] = SSLPORT
        if not new_conf["vhosts-enabled"]==old_conf["vhosts-enabled"]:
            if new_conf["vhosts-enabled"]==True:
                vhoston = "Enabled"
            else:
                vhoston = "Disabled"
            RedServ.debugger(3,"vhosts are now: "+str(vhoston))
        if not new_conf["php"]==old_conf["php"]:
            if new_conf["php"]==True:
                phpon = "Enabled"
            else:
                phpon = "Disabled"
            RedServ.debugger(3,"php is now: "+str(phpon))
        if not new_conf["log"]==old_conf["log"]:
            if new_conf["log"]==True:
                log = "Enabled"
            else:
                log = "Disabled"
            RedServ.debugger(3,"Logging is now "+str(log))
        if not new_conf["vhost-lookup"]==old_conf["vhost-lookup"]:
            RedServ.debugger(3,"Virtual Host look up is now done by "+new_conf["vhost-lookup"])
    return(new_conf)


class WebInterface:
    """ main web interface class """

    def default(self, *args,**params):
        global cj
        global lookup
        global cherrypy
        global site_glo_data
        global conf
        global python_page_cache
        global sieve_cache
        global STDPORT
        global SSLPORT
        conf = conf_reload(conf)
        
        RedServ.http_port = STDPORT
        RedServ.https_port = SSLPORT
        
        bad = False
        list = args
        paramlines = "?"
        if not params=={}:
            for data in params:
                params[data] = params[data].replace("\n","\\n").replace("\r","\\r")
                paramlines = paramlines+data+"="+params[data]+"&"
            paramlines = paramlines[:-1]
        if paramlines=="?":
            paramlines = ""
        if "host" in cherrypy.request.headers:
            virt_host = cherrypy.request.headers["host"]
        else:
            cherrypy.response.status = 404
            logging("", 1, [cherrypy,"No host header",list,paramlines])
            return("")
            
        try:
            if conf["vhosts-enabled"]==True:
                virtloc = os.path.join(os.path.abspath('pages'),vhosts(virt_host))+os.sep
            else:
                virtloc = os.path.abspath('pages')+os.sep
        except Exception,e:
            cherrypy.response.status = 404
            logging("", 1, [cherrypy,virt_host,list,paramlines])
            return("")
        
        if not virt_host in site_glo_data:
            site_glo_data[virt_host] = {}
            db_folders = os.path.join("sites",vhosts(virt_host))
            site_glo_data[virt_host]["db_conn_loc"] = (virt_host,db_folders)
        
        if not str(type(site_glo_data[virt_host]["db_conn_loc"]))=="<type 'tuple'>":
            site_glo_data[virt_host]["db_conn_loc"] = (virt_host,db_folders)
            
        RedServ.lookup = RedServ.template_reload(current_dir) #template refresh
        
    ###Start
        if os.path.exists(os.path.join(os.path.abspath('pages'),"sieve.py")):
            page = virt_host+"/"+"/".join(list)
            datsieve = ""
            sievedata = {
            "sievetype":"in",
            "cherrypy": cherrypy,
            "page":page,
            "this_domain":virt_host,
            "vhost_location":virtloc,
            "data": datsieve,
            "bad":bad,
            "params":params
            }
            try:
                (sievedata,sieve_cache) = sieve(sievedata,sieve_cache) #pre-page render sieve
            except Exception,e:
                if type(e)==type(RedServ.staticfileserve("")):
                    return(e.value)
                if type(e)==type(cherrypy.HTTPRedirect("")):
                    (https_redirect_str,cherrypy.response.status) = e
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    raise(e)
                if type(e)==type(cherrypy.HTTPError(404)):
                    status,error = e
                    cherrypy.response.status = status
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    return(error)
                cherrypy.response.status = 404
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                return("404<br>\n"+RedServ.trace_back().replace("\n","<br>\n"))
            bad = sievedata['bad']
            cherrypy = sievedata['cherrypy']
            
            no_serve_message = "404<br>[Errno 2] No such file or directory: '"+"/"+"/".join(list)+"'"
            if page in RedServ.noserving:
                cherrypy.response.status = 404
                bad = True
                sievedata["data"] = no_serve_message
            #if cherrypy.request.login==None:
            #    if (page in RedServ.basicauth) or (virt_host in RedServ.basicauth):
            #        bad = True
            #        datatoreturn["datareturned"] = "Please login."
            #        cherrypy.response.status = 401
            #   ^ handle basic auth protection requests and make sure to add input of a realm and a user list.    
        cherrypy.response.headers["Server"] = "RedServ 1.5"
        if bad == False:
            headers = {}
            responsecode = 200
            if not os.path.exists(virtloc) and conf["vhosts-enabled"]==True:
                return("")
            filename = (virtloc+os.sep.join(list)).strip("..").replace("//","/")
            if len(list)>=2 and str(list[0]).lower()=="static":
                #cherrypy.response.headers['Cache-Control'] = 'private, max-age=120'
                if str(list[0])=="static":
                    if not os.path.exists(os.path.join(current_dir,os.sep.join(list))):
                        return(notfound(cherrypy,virt_host,paramlines,list,params))
                    if cherrypy.response.status==None:
                        cherrypy.response.status = 200
                    
                    file = current_dir+os.sep+os.sep.join(list)
                    return(RedServ.serve_static_file(virt_host,list,paramlines,file))
                else:
                    if os.path.exists(filename):
                        return(RedServ.serve_static_file(virt_host,list,paramlines,filename))
                    else:
                        cherrypy.response.status = 404
                        logging("", 1, [cherrypy,virt_host,list,paramlines])
                        return("404")
            cherrypy.response.headers['Cache-Control'] = 'no-cache'
            try:
                bang = os.listdir(filename)
            except Exception,e:
                bang = ""
                if str(e).startswith("[Errno 2]"):
                    filename = filepicker(filename,fileext)
                    if not os.path.exists(filename) or filename==None:
                        cherrypy.response.status = 404
                        logging("", 1, [cherrypy,virt_host,list,paramlines])
                        return(notfound2(cherrypy,e,virtloc,params))
                if str(e).startswith("[Errno 20]"):
                    filename = filepicker(filename,fileext)
            if not bang=="":
                try:
                    filename = filepicker(filename,folderext)
                    open(filename, 'r').read()
                except Exception,e:
                    if str(e).startswith("[Errno 21]"):
                        logging("", 1, [cherrypy,virt_host,list,paramlines])
                        return(notfound2(cherrypy,e,virtloc,params))
            if not (filename.endswith(".py") or filename.endswith(".php")):
                typedat = mimetypes.guess_type(filename)
                if not typedat==(None,None):
                    (cherrypy.response.headers['Content-Type'],nothing) = typedat
            datatoreturn = {
            "sievetype":"out", 
            "params":params,
            "datareturned":"'",
            "cj":cj,
            "headers":headers,
            "response":responsecode,
            "request":cherrypy.request,
            "filelocation":virtloc+os.sep.join(list),
            "vhost_location":virtloc,
            "filename":filename.strip(virtloc+os.sep.join(list)),
            "this_page":virt_host+"/"+"/".join(list),
            "this_domain":virt_host,
            "global_site_data":site_glo_data,
            "site_data":site_glo_data[virt_host],
            "http_port":STDPORT,
            "https_port":SSLPORT
            }
            try:
                if (filename.endswith(".php")) and (conf["php"]==True):
                    return(PHP(filename))
                if filename.endswith(".py"):
                    datatoreturn.update(globals())
                    datatoreturn = exec_page_script(filename,datatoreturn,python_page_cache)
                else:
                    datatoreturn["datareturned"] = open(filename, 'r').read()
                    cherrypy.response.status = 200
                    (datatoreturn,sieve_cache) = sieve(datatoreturn,sieve_cache)
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    return(datatoreturn["datareturned"]+debughandler(params))
            except Exception,e:
                if type(e)==type(RedServ.staticfileserve("")):
                    return(e.value)
                if type(e)==type(cherrypy.HTTPRedirect("")):
                    (https_redirect_str,cherrypy.response.status) = e
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    raise(e)
                if type(e)==type(cherrypy.HTTPError(404)):
                    status,error = e
                    cherrypy.response.status = status
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    return(error+debughandler(params))
                type_, value_, traceback_ = sys.exc_info()
                ex = traceback.format_exception(type_, value_, traceback_)
                trace = "<br>\n".join(ex)
                cherrypy.response.status = 404
                datatoreturn["datareturned"] = "404<br>"+str(trace).replace(virtloc,"/")
                (datatoreturn,sieve_cache) = sieve(datatoreturn,sieve_cache)
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                return(datatoreturn["datareturned"]+debughandler(params))
            try:
                (datatoreturn,sieve_cache) = sieve(datatoreturn,sieve_cache)
            except Exception,e:
                if type(e)==type(RedServ.staticfileserve("")):
                    return(e.value)
                if type(e)==type(cherrypy.HTTPRedirect("")):
                    (https_redirect_str,cherrypy.response.status) = e
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    raise(e)
                if type(e)==type(cherrypy.HTTPError(404)):
                    status,error = e
                    cherrypy.response.status = status
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    return(error+debughandler(params))
                cherrypy.response.status = 404
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                return("404<br>\n"+RedServ.trace_back().replace("\n","<br>\n")+debughandler(params))
            cj = datatoreturn['cj']
            site_glo_data = datatoreturn['global_site_data']
            site_glo_data[virt_host] = datatoreturn['site_data']
            responsecode = datatoreturn['response']
            cherrypy.response.status = responsecode
            headers = datatoreturn['headers']
            if not (headers==""):
                cherrypy.response.headers.update(datatoreturn['headers'])
            logging("", 1, [cherrypy,virt_host,list,paramlines])
            if cherrypy.response.headers['Content-Type']=="":
                cherrypy.response.headers['Content-Type']="charset=utf-8"
            else:
                cherrypy.response.headers['Content-Type']=cherrypy.response.headers['Content-Type']+"; charset=utf-8"
            return(str(datatoreturn["datareturned"])+debughandler(params))
        else:
            logging("", 1, [cherrypy,virt_host,list,paramlines])
            return(str(sievedata["data"]))
    ###end
      
    default.exposed = True
        

def web_init(conf,conflocation):
    print("INFO: Initalising web server...")
    global RedServ
    RedServ = RedServer()
    if conf["HTTPS"]["enabled"]==False and conf["HTTP"]["enabled"]==False:
        RedServ.debugger(0,"You need to enable one transfer protocol, either HTTP or HTTPS in the config")
        exit()
    RedServ.debugger(3,"Hostname: "+RedServ.sysinfo())
    global_conf = {
        'global': { 'engine.autoreload.on': False,
        'log.error_file': os.path.join('logs','site','site.'+RedServ.sysinfo()+'.log'),
        'log.screen': False,
        'gzipfilter.on':True,
        'tools.gzip.mime_types':['text/html', 'text/plain', 'text/css', 'text/*'],
        'tools.gzip.on':True,
        'tools.encode.on':True,
        'tools.decode.on':True,
        'tools.sessions.on':conf["sessions"],
        'tools.sessions.secure':conf["sessions"],
        'response.timeout': 300
    }}
    application_conf = {
        "/favicon.ico": {
        'tools.staticfile.on' : True,
        'tools.staticfile.filename' : os.path.join(current_dir,
        'static', "favicon.ico"),
        }
    }
    cherrypy.config.update(global_conf)
    web_interface = WebInterface()
    cherrypy.tree.mount(web_interface, '/', config = application_conf)

    cherrypy.server.unsubscribe()

    global STDPORT
    STDPORT = conf["HTTP"]["port"]
    global SSLPORT
    SSLPORT = conf["HTTPS"]["port"]
    if conf["HTTPS"]["enabled"]==True:
        SSL_cert_gen(RedServ.sysinfo())
        RedServ.server1 = cherrypy._cpserver.Server()
        RedServ.server1.socket_port=SSLPORT
        RedServ.server1._socket_host='0.0.0.0'
        RedServ.server1.thread_pool=50
        RedServ.server1.thread_pool_max=-1
        RedServ.server1.shutdown_timeout=1
        RedServ.server1.statistics=True
        RedServ.server1.ssl_module = 'custom-pyopenssl'
        RedServ.server1.ssl_certificate = os.path.join(current_dir,'cert.pem')
        RedServ.server1.ssl_private_key = os.path.join(current_dir,'privkey.key')
        if os.path.exists(os.path.join(current_dir,'ca.pem')):
            RedServ.server1.ssl_certificate_chain = os.path.join(current_dir,'ca.pem')
        RedServ.server1.subscribe()
    if conf["HTTP"]["enabled"]==True:
        RedServ.server2 = cherrypy._cpserver.Server()
        RedServ.server2.socket_port=STDPORT
        RedServ.server2._socket_host="0.0.0.0"
        RedServ.server2.thread_pool=100
        RedServ.server2.thread_pool_max=-1
        RedServ.server2.shutdown_timeout=1
        RedServ.server2.statistics=True
        RedServ.server2.subscribe()
    
    port_statuses = "Web server started"
    if conf["HTTP"]["enabled"]==True:
        port_statuses = port_statuses+"\nHTTP on port: "+str(RedServ.server2.socket_port)
    if conf["HTTPS"]["enabled"]==True:
        port_statuses = port_statuses+"\nHTTPS on port: "+str(RedServ.server1.socket_port)
    RedServ.debugger(3,port_statuses)
    
    global python_page_cache
    python_page_cache = {}
    
    sievepath = os.path.join(os.path.abspath('pages'),"sieve.py")
    global sieve_cache
    sieve_cache = {}
    sieve_cache["global"] = []
    if os.path.exists(sievepath):
        sieve_cache["global"].append(compile(open(sievepath,'r').read(),'<string>','exec'))
        sieve_cache["global"].append(os.path.getmtime(sievepath))
    if not os.name=="nt":
        cherrypy.engine.signals.subscribe()
    cherrypy.engine.start()
    cherrypy.engine.block()

os.chdir(current_dir)
db_loc = os.path.abspath('db')
pathing = [
"db",
"logs",
os.path.join("logs","site"),
"pages",
"static",
"templates"
]
for data in pathing:
    if not os.path.exists(os.path.abspath(data)):
        os.mkdir(os.path.abspath(data))

global get_db_connection
def get_db_connection(name,folders=None):
    db_loc = os.path.abspath(os.path.join(current_dir,'db'))
    if folders==None:
        filename = os.path.join(db_loc,name)
    else:
        folder_list = folders.split(os.sep)
        for data in folder_list:
            db_loc = os.path.join(db_loc,data)
            if (not os.path.exists(db_loc)) and (not (len(folder_list)-1)==folder_list.index(data)):
                os.mkdir(os.path.abspath(db_loc))
        filename = db_loc
    if not filename.endswith(".db"):
        filename = filename+".db"
    return sqlite3.connect(filename, timeout=10)
    
# Config init and caching, We need this for enabling the SSL changes inside of Cherrypy if SSL is enabled.
conflocation = os.path.join(current_dir,"config")
config_init(conflocation)
config_cache = []
config_cache.append(json.load(open(conflocation)))
config_cache.append(os.path.getmtime(conflocation))
conf = config(conflocation)

# This section of code is to correct SSL issues with Cherrypy until they correct them.
# This section will be removed later.
# Author of original code: http://recollection.saaj.me/article/cherrypy-questions-testing-ssl-and-docker.html#experiment
if conf["HTTPS"]["enabled"]==True:
    import ssl
    from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter
    from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter

    from cherrypy import wsgiserver
    if sys.version_info < (3, 0):
      from cherrypy.wsgiserver.wsgiserver2 import ssl_adapters
    else:
      from cherrypy.wsgiserver.wsgiserver3 import ssl_adapters

    try:
      from OpenSSL import SSL
    except ImportError:
      pass


    ciphers = (
      'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:'
      'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
      'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
      '!eNULL:!EXPORT:!MD5:!DSS:!3DES:!DES:!RC4:!SSLv2:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:'
      '!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:@STRENGTH'
    )

    class BuiltinSsl(BuiltinSSLAdapter):
      '''Vulnerable, on py2 < 2.7.9, py3 < 3.3:
        * POODLE (SSLv3), adding ``!SSLv3`` to cipher list makes it very incompatible
        * can't disable TLS compression (CRIME)
        * supports Secure Client-Initiated Renegotiation (DOS)
        * no Forward Secrecy
      Also session caching doesn't work. Some tweaks are posslbe, but don't really
      change much. For example, it's possible to use ssl.PROTOCOL_TLSv1 instead of
      ssl.PROTOCOL_SSLv23 with little worse compatiblity.
      '''

      def wrap(self, sock):
        """Wrap and return the given socket, plus WSGI environ entries."""
        try:
          s = ssl.wrap_socket(
            sock,
            ciphers = ciphers, # the override is for this line
            do_handshake_on_connect = True,
            server_side = True,
            certfile = self.certificate,
            keyfile = self.private_key,
            ssl_version = ssl.PROTOCOL_SSLv23
          )
        except ssl.SSLError:
          e = sys.exc_info()[1]
          if e.errno == ssl.SSL_ERROR_EOF:
            # This is almost certainly due to the cherrypy engine
            # 'pinging' the socket to assert it's connectable;
            # the 'ping' isn't SSL.
            return None, {}
          elif e.errno == ssl.SSL_ERROR_SSL:
            if e.args[1].endswith('http request'):
              # The client is speaking HTTP to an HTTPS server.
              raise wsgiserver.NoSSLError
            elif e.args[1].endswith('unknown protocol'):
              # The client is speaking some non-HTTP protocol.
              # Drop the conn.
              return None, {}
          raise

        return s, self.get_environ(s)

    ssl_adapters['custom-ssl'] = BuiltinSsl


    class Pyopenssl(pyOpenSSLAdapter):
      '''Mostly fine, except:
        * Secure Client-Initiated Renegotiation
        * no Forward Secrecy, SSL.OP_SINGLE_DH_USE could have helped but it didn't
      '''

      def get_context(self):
        """Return an SSL.Context from self attributes."""
        c = SSL.Context(SSL.SSLv23_METHOD)

        # override:
        c.set_options(SSL.OP_NO_COMPRESSION | SSL.OP_SINGLE_DH_USE | SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        c.set_cipher_list(ciphers)

        c.use_privatekey_file(self.private_key)
        if self.certificate_chain:
            c.load_verify_locations(self.certificate_chain)
        c.use_certificate_file(self.certificate)
        return c

    ssl_adapters['custom-pyopenssl'] = Pyopenssl
# End of SSL fixes


web_init(conf,conflocation)
