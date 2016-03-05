#!/usr/bin/env python2
# RedServ
# Copyright (C) 2016  Red_M ( http://bitbucket.com/Red_M )

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#Help from Luke Rogers

# TODO:
#  - Sieve and page caches need to be replaced with a backgroundtask using: cherrypy.process.plugins.BackgroundTask(interval, function, args=[], kwargs={}, bus=None)
#  - Investigate SSL further and see if we can get an A+ instead of A on SSL labs
#  - Optimize
import cherrypy
import os
import sys
if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('UTF8')
import time
import json
import mimetypes
import socket
import random
import sqlite3
import ast
import urllib,urllib2
import re
import traceback
import cgi
import gc
from watchdog.observers import Observer as watchdog_observer
from watchdog.events import FileSystemEventHandler as watchdog_file_event_handler
try:
    import OpenSSL
    SSL_imported = True
except Exception,e:
    print("ERROR: Could not load OpenSSL library. Disabling SSL cert generation.")
    SSL_imported = False
try:
    import requests
    requests.cookie_session = requests.Session()
except Exception,e:
    print("ERROR: Could not load requests library.")


os.chdir('.' or sys.path[0])
current_dir = os.path.join(os.getcwd(),os.sep.join(sys.argv[0].split(os.sep)[0:-1]))
if current_dir.endswith("."):
    current_dir = current_dir[0:-1]
if sys.argv[0].split(os.sep)[-1] in os.listdir(current_dir):
    print("INFO: Found webserver path")
else:
    print("INFO: Bad web server path")
    exit()


exed = False
if current_dir.endswith(".zip"):
    exed = True
site_glo_data = {}
site_shared_data = {}
python_page_cache = {}
sieve_cache = {}
config_cache = []

class RedServer(object):
    def __init__(self):
        self.nologging = []
        self.nologgingstart = []
        self.nologgingend = []
        
        self.staticfileserve = staticfileserve
        self.error_pages = {}
        self.default_error_pages = {"default":self.default_error_page}
        self.error_template = '%(status)s\n\n%(message)s\n\n%(traceback)s\n\n%(version)s\n'
        
        self.noserving = []
        self.noservingstart = []
        self.noservingend = []
        
        self.basicauth = []
        self.basicauthstart = []
        self.basicauthend = []
        
        self.servers = {}
        self.servers["HTTPS"] = {}
        self.servers["HTTP"] = {}
        
        self.background_services = {}
        
        #self.server1 = cherrypy._cpserver.Server()
        #self.server2 = cherrypy._cpserver.Server()
        self._version_string_ = "1.7.1_beta"
        self._version_ = "RedServ/"+str(self._version_string_)
        self.http_port = 8080
        self.http_ports = []
        self.https_port = 8081
        self.https_ports = []
        self.current_dir = current_dir
    
    def start_background_service(self,service_name,interval,function,args=[],kwargs={},bus=None):
        if not service_name in self.background_services:
            try:
                self.background_services[service_name] = cherrypy.process.plugins.BackgroundTask(interval,function,args,kwargs,bus)
                self.background_services[service_name].start()
                return(self.background_services[service_name])
            except Exception as e:
                RedServ.debugger(1,self.trace_back(False))
                del self.background_services[service_name]
        else:
            return(False)
    
    def stop_background_service(self,service_name):
        if service_name in self.background_services:
            try:
                self.background_services[service_name].cancel()
                return(True)
            except Exception as e:
                RedServ.debugger(1,self.trace_back(False))
        else:
            return(False)
    
    def gc_collect(self):
        #self.debugger(3,str(gc.collect()))
        gc.collect()
        gc.collect()
    
    def test(self,out):
        print(out)
        
    def get_config(self):
        return(conf)
        
    def default_error_page(self,**kwargs):
        cherrypy.response.headers['Content-Type'] = "text/plain"
        result = self.error_template % kwargs
        return(result.replace("\n\n\n","\n"))
    
    def check_https(self,cherrypy):
        if cherrypy.request.local.port in self.https_ports:
            return(True)
        else:
            return(False)
    
    def force_https(self,cherrypy,url,redirect=True):
        if redirect==True:
            if not cherrypy.request.local.port in self.https_ports:
                if not url.startswith("https://"):
                    url = "https://"+url
                raise(cherrypy.HTTPRedirect(url))
            #else:
            #    return("")
        #add reserv based message saying to use https here.
            
    
    def trace_back(self,html=True):
        type_, value_, traceback_ = sys.exc_info()
        ex = traceback.format_exception(type_, value_, traceback_)
        trace = ""
        for data in ex:
            trace = str(trace+data)
        trace = cgi.escape(trace).encode('utf-8', 'xmlcharrefreplace')
        if html==True:
            trace = trace.replace("\n","<br>")
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
        message = str(message)
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

    def sysinfo(self):
        if os.name=="posix":
            (sysname, nodename, release, version, machine) = os.uname()
        else:
            (nodename, v4, v6) = socket.gethostbyaddr(socket.gethostname())
        return(nodename)
    
    def basic_auth(self, realm, users, customcheckpassword=None, password_salt=None):
        if customcheckpassword==None:
            checkpassword = cherrypy.lib.auth_basic.checkpassword_dict(users)
        else:
            if password_salt==None:
                checkpassword = customcheckpassword(users)
            else:
                checkpassword = customcheckpassword(users,password_salt)
        cherrypy.response.headers['WWW-Authenticate'] = 'Basic realm="'+realm+'"'
        try:
            cherrypy.lib.auth_basic.basic_auth(realm, checkpassword)
        except Exception,e:
            if type(e)==type(cherrypy.HTTPError(404)):
                status, error = e
                raise(cherrypy.HTTPError(status,error))
        self.loggedinuser = cherrypy.request.login
        return(self.loggedinuser)
    
    def digest_auth(self, realm, users, key, customcheckpassword=None, password_salt=None):
        if customcheckpassword==None:
            checkpassword = cherrypy.lib.auth_digest.get_ha1_dict_plain(users)
        else:
            if password_salt==None:
                checkpassword = customcheckpassword(users)
            else:
                checkpassword = customcheckpassword(users,password_salt)
        #cherrypy.response.headers['WWW-Authenticate'] = 'Basic realm="'+realm+'"'
        try:
            cherrypy.lib.auth_digest.digest_auth(realm, checkpassword, key)
        except Exception,e:
            if type(e)==type(cherrypy.HTTPError(404)):
                status, error = e
                raise(cherrypy.HTTPError(status,error))
            if str(e).startswith("n must be a native str (got "):
                new_users = {}
                for user in users:
                    new_users[str(user)] = str(users[user])
                key = str(key)
                return(self.digest_auth(realm, new_users, key, customcheckpassword, password_salt))
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
    
    def _serve_static_file(self,virt_host,list,paramlines,filename):
        # internal function, DO NOT use in page scripts.
        cherrypy.response.status = 200
        logging("", 1, [cherrypy,virt_host,list,paramlines])
        #caching header so that browsers can cache our content
        cherrypy.response.headers['Last-Modified'] = os.path.getmtime(filename)
        typedat = mimetypes.guess_type(filename)
        if not typedat==(None,None):
            return(cherrypy.lib.static.serve_file(filename))
        else:
            return(cherrypy.lib.static.serve_download(filename))
    
    def static_file_serve(self,filename,force_type=None,disposition=None,name=None):
        #caching header so that browsers can cache our content
        if name==None:
            name=os.path.basename(filename)
        cherrypy.response.headers['Last-Modified'] = os.path.getmtime(filename)
        typedat = mimetypes.guess_type(filename)
        if not force_type==None:
            return(self.staticfileserve(cherrypy.lib.static.serve_file(filename,force_type,disposition,name)))
        if not typedat==(None,None):
            return(self.staticfileserve(cherrypy.lib.static.serve_file(filename,None,disposition,name)))
        else:
            return(self.staticfileserve(cherrypy.lib.static.serve_download(filename)))

class PageFileEventHandler(object):

    def redo_cache_check(self,event,domain_split):
        if event.src_path.endswith("sieve.py") and (domain_split[-4]=="pages" or (domain_split[-2]=="pages" and domain_split[-1]=="sieve.py")):
            sievepath = event.src_path
            sievetime = os.path.getmtime(sievepath)
            if event.src_path==os.path.join(current_dir,"pages","sieve.py"):
                #global sieve
                sievename = "global"
            else:
                #normal sieve
                this_domain = domain_split[-2]+"."+domain_split[-3]
                #RedServ.noserve(this_domain,"sieve.py")
                sievename = this_domain
            if not sievename in sieve_cache:
                sieve_cache[sievename] = []
            if not sieve_cache[sievename]==[]:
                if sieve_cache[sievename][0] < sievetime:
                    sieve_cache[sievename][0] = sievetime
                    try:
                        sieve_cache[sievename][1] = compile(open(sievepath,'r').read(),sievepath,'exec')
                    except Exception as e:
                        print(RedServ.trace_back(False))
            else:
                sieve_cache[sievename].append(sievetime)
                try:
                    sieve_cache[sievename].append(compile(open(sievepath,'r').read(),sievepath,'exec'))
                except Exception as e:
                    print(RedServ.trace_back(False))
        else:
            filename = event.src_path
            if not filename in python_page_cache:
                python_page_cache[filename] = []
            page_time = os.path.getmtime(filename)
            if not python_page_cache[filename]==[]:
                python_page_cache[filename][0] = page_time
                try:
                    python_page_cache[filename][1] = compile(open(filename,'r').read(),filename,'exec')
                except Exception as e:
                    print(RedServ.trace_back(False))
            else:
                python_page_cache[filename].append(compile(open(filename,'r').read(),filename,'exec'))
                try:
                    python_page_cache[filename].append(page_time)
                except Exception as e:
                    print(RedServ.trace_back(False))


    def on_any_event(self, event):
        """Catch-all event handler.

        :param event:
            The event object representing the file system event.
        :type event:
            :class:`FileSystemEvent`
        """

    def on_moved(self, event):
        what = 'directory' if event.is_directory else 'file'
        if what=='file':
            #RedServ.debugger(3,"Moved: "+event.src_path+" to: "+event.dest_path)
            if event.src_path.endswith(".py") and event.dest_path.endswith(".py"):
                if not os.stat(event.src_path).st_size==0:
                    domain_split = event.src_path.split(os.sep)
                    old_domain_split = event.src_path.split(os.sep)
                    if event.src_path.endswith("sieve.py") and (domain_split[-4]=="pages" or (domain_split[-2]=="pages" and domain_split[-1]=="sieve.py")):
                        sievepath = event.dest_path
                        sievetime = os.path.getmtime(sievepath)
                        if event.dest==os.path.join(current_dir,"pages","sieve.py"):
                            #global sieve
                            sievename = "global"
                        else:
                            #normal sieve
                            this_domain = domain_split[-2]+"."+domain_split[-3]
                            #RedServ.noserve(this_domain,"sieve.py")
                            sievename = this_domain
                            del sieve_cache[old_domain_split[-2]+"."+old_domain_split[-3]]
                        if not sievename in sieve_cache:
                            sieve_cache[sievename] = []
                        if not sieve_cache[sievename]==[]:
                            if sieve_cache[sievename][0] < sievetime:
                                sieve_cache[sievename][0] = sievetime
                                try:
                                    sieve_cache[sievename][1] = compile(open(sievepath,'r').read(),sievepath,'exec')
                                except Exception as e:
                                    print(RedServ.trace_back(False))
                        else:
                            sieve_cache[sievename].append(sievetime)
                            try:
                                sieve_cache[sievename].append(compile(open(sievepath,'r').read(),sievepath,'exec'))
                            except Exception as e:
                                print(RedServ.trace_back(False))
                    else:
                        filename = event.dest_path
                        if not filename in python_page_cache:
                            python_page_cache[filename] = []
                        page_time = os.path.getmtime(filename)
                        if not python_page_cache[filename]==[]:
                            python_page_cache[filename][0] = page_time
                            try:
                                python_page_cache[filename][1] = compile(open(filename,'r').read(),filename,'exec')
                            except Exception as e:
                                print(RedServ.trace_back(False))
                        else:
                            python_page_cache[filename].append(page_time)
                            try:
                                python_page_cache[filename].append(compile(open(filename,'r').read(),filename,'exec'))
                            except Exception as e:
                                print(RedServ.trace_back(False))
                        del python_page_cache[event.src_path]
                else:
                    if event.src_path.endswith(".py") and (not event.dest_path.endswith(".py")):
                        self.on_deleted(event)


    def on_deleted(self, event):
        what = 'directory' if event.is_directory else 'file'
        if what=='file':
            #RedServ.debugger(3,"Deleted: "+event.src_path)
            if event.src_path.endswith(".py"):
                domain_split = event.src_path.split(os.sep)
                if event.src_path.endswith("sieve.py") and (domain_split[-4]=="pages" or (domain_split[-2]=="pages" and domain_split[-1]=="sieve.py")):
                    sievepath = event.src_path
                    if event.src_path==os.path.join(current_dir,"pages","sieve.py"):
                        #global sieve
                        sievename = "global"
                    else:
                        #normal sieve
                        this_domain = domain_split[-2]+"."+domain_split[-3]
                        #RedServ.noserve(this_domain,"sieve.py")
                        sievename = this_domain
                    if sievename in sieve_cache:
                        del sieve_cache[sievename]
                else:
                    filename = event.src_path
                    if filename in python_page_cache:
                        del python_page_cache[filename]

    def on_created(self, event):
        what = 'directory' if event.is_directory else 'file'
        if what=='file':
            #RedServ.debugger(3,"Created: "+event.src_path)
            if event.src_path.endswith(".py"):
                if not os.stat(event.src_path).st_size==0:
                    domain_split = event.src_path.split(os.sep)
                    self.redo_cache_check(event,domain_split)

    def on_modified(self, event):
        what = 'directory' if event.is_directory else 'file'
        if what=='file':
            #RedServ.debugger(3,"Changed: "+event.src_path)
            if event.src_path.endswith(".py"):
                if not os.stat(event.src_path).st_size==0:
                    domain_split = event.src_path.split(os.sep)
                    self.redo_cache_check(event,domain_split)

class ConfigFileEventHandler(object):

    def on_any_event(self, event):
        """Catch-all event handler.

        :param event:
            The event object representing the file system event.
        :type event:
            :class:`FileSystemEvent`
        """

    def on_moved(self, event):
        pass

    def on_created(self, event):
        global conf
        what = 'directory' if event.is_directory else 'file'
        if what=='file':
            if event.src_path.split(os.sep)[-1]=="config":
                #RedServ.debugger(3,"Created: "+event.src_path)
                if not os.stat(event.src_path).st_size==0:
                    conf = conf_reload(conf)

    def on_deleted(self, event):
        pass

    def on_modified(self, event):
        global conf
        what = 'directory' if event.is_directory else 'file'
        if what=='file':
            if event.src_path.split(os.sep)[-1]=="config":
                #RedServ.debugger(3,"Changed: "+event.src_path)
                if not os.stat(event.src_path).st_size==0:
                    conf = conf_reload(conf)

class staticfileserve(Exception):
     def __init__(self, value):
         self.value = value
     def __str__(self):
         return repr(self.value)

def get_config_default():
    config_file_data = {
        "default_404": True,
        "vhosts-enabled": True,
        "vhost-lookup": "domains",
        "sessions": False,
        "php": False,
        "database_connections": False,
        "page_response_check": 1,
        "page_request_timeout": 30,
        "logs_to_screen":False,
        "cherrypy_access_logs":"",
        "log": True
    }
    config_file_data["HTTP"] = {
        "reverse_proxied":False,
        "enabled":False,
        "thread_pool":50,
        "socket_queue":50,
        "ports":[8081]
    }
    config_file_data["HTTPS"] = {
        "reverse_proxied":False,
        "enabled":False,
        "thread_pool":50,
        "socket_queue":50,
        "ports":[8082],
        "CA_cert":"default-ca.pem",
        "cert":"certs/cert.crt",
        "cert_private_key":"certs/privkey.key"
    }
    return(config_file_data)

def config_init(config_location):
    if not os.path.exists(config_location):
        config_file_data = get_config_default()
        open(config_location, 'w').write(json.dumps(config_file_data, sort_keys=True,indent=2, separators=(',', ': ')))

def config(config_location):
    try:
        if os.path.getmtime(config_location)>config_cache[1]:
            config_cache[0] = json.load(open(config_location))
            config_cache[1] = os.path.getmtime(config_location)
        return(config_cache[0])
    except ValueError, e:
        RedServ.debugger(0,'malformed config! '+e)
    
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
    #RedServ.debugger(3,filename)
    for data in fileext:
        if data.startswith("."):
            file = filename+data
        else:
            file = os.path.join(filename,data)
        if os.path.exists(file) and os.path.isfile(file):
            return(file)
    return(filename)
    
def ssl_cert_directory(cert_dir="."):
    CERT_FILE = "cert.crt"
    KEY_FILE = "privkey.key"
    C_F = os.path.join(cert_dir, CERT_FILE)
    K_F = os.path.join(cert_dir, KEY_FILE)
    return(C_F,K_F)
    
def SSL_cert_gen(nodename,dir):
    if SSL_imported==True:
        (C_F,K_F) = ssl_cert_directory(dir)
        if not os.path.exists(C_F) or not os.path.exists(K_F):
            RedServ.debugger(4, "Generating SSL certs")
            k = OpenSSL.crypto.PKey()
            k.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
            cert = OpenSSL.crypto.X509()
            cert.get_subject().C = "na"
            cert.get_subject().ST = "n/a"
            cert.get_subject().L = "n/a"
            cert.get_subject().O = "RedServ"
            cert.get_subject().OU = "RedServ Test Cert Generated: "+str(time.time())
            cert.get_subject().CN = nodename
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(315360000)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            cert.sign(k, 'sha256')
            if sys.version_info < (3, 0):
                file_mode = "wt"
            else:
                file_mode = "wb"
            open(C_F, file_mode).write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            open(K_F, file_mode).write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k))
    else:
        RedServ.debugger(0, "No SSL certs, no SSL support and RedServ has HTTPS turned on. Terminating.")
        exit()

    
def sieve(sievedata,sieve_cache):
    sieves = []
    sieves.append((os.path.join(os.path.abspath('pages'),"sieve.py"),"global"))
    sieves.append((os.path.join(os.path.abspath(sievedata["vhost_location"]),"sieve.py"),sievedata["this_domain"]))
    for data in sieves:
        (sievepath,sievename) = data
        if not sievename in sieve_cache:
            sieve_cache[sievename] = []
        if sievedata['return_after_this']==False:
            (sievedata,sieve_cache[sievename]) = sieve_exec(sievedata,sieve_cache[sievename],sievepath,sievename)
    return(sievedata,sieve_cache)

def sieve_exec(sievedata,sievecache,sievepath,sievename):
    if os.path.exists(sievepath):
        sievetime = os.path.getmtime(sievepath)
        if not sievename=="global":
            RedServ.noserve(sievedata["this_domain"],"sieve.py")
        if not sievecache==[]:
            if sievecache[0] < sievetime:
                sievecache[0] = sievetime
                sievecache[1] = compile(open(sievepath,'r').read(),sievepath,'exec')
        else:
            sievecache.append(sievetime)
            sievecache.append(compile(open(sievepath,'r').read(),sievepath,'exec'))
        sievedata.update(globals())
        exec(sievecache[1],sievedata)
    return(sievedata,sievecache)
    
def exec_page_script(filename,datatoreturn,python_page_cache):
    if not filename in python_page_cache:
        python_page_cache[filename] = []
    page_time = os.path.getmtime(filename)
    if not python_page_cache[filename]==[]:
        if python_page_cache[filename][0] < page_time:
            python_page_cache[filename][0] = page_time
            python_page_cache[filename][1] = compile(open(filename,'r').read(),filename,'exec')
    else:
        python_page_cache[filename].append(page_time)
        python_page_cache[filename].append(compile(open(filename,'r').read(),filename,'exec'))
    exec(python_page_cache[filename][1],datatoreturn)
    return(datatoreturn)

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
    
def vhosts(virt_host,conf):
    lookuptypes = [
    "domains",
    "single-hosts",
    "ips",
    "none"
    ]
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
    cherrypy.response.headers["content-type"] = "text/plain"
    logging("",1,[cherrypy,virt_host,list,paramlines])
    (sysname, nodename, release, version, machine) = os.uname()
    raise(cherrypy.HTTPError(404,str("/"+"/".join(list))+debughandler(params)))
    
def notfound2(cherrypy,e,virtloc,params):
    cherrypy.response.status = 404
    cherrypy.response.headers["content-type"] = "text/plain"
    (sysname, nodename, release, version, machine) = os.uname()
    raise(cherrypy.HTTPError(404,str(e).replace(virtloc,"/")+debughandler(params)))
    
def PHP(path):
    proc = subprocess.check_output(["php",path])
    return(proc)
    
def debughandler(params,debugtable=[]):
    if "redserv-debug" in params:
        if params["redserv-debug"]=="1":
            if "v" in params:
                if not params["v"] == "1":
                    debuginfo = "\n"+RedServ.sysinfo()
                else:
                    debuginfo = "\n".join(debugtable)+"\n"+" ".join(os.uname())+"\n"+RedServ.sysinfo()
            else:
                debuginfo = "\n"+RedServ.sysinfo()
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
                proto = "http"
                if RedServ.check_https(cherrypy)==True:
                    proto = proto+"s"
                proto = proto+"://"
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
                    str(cherrypy.request.remote.ip)+"	["+cherrypy.request.method+"("+str(cherrypy.response.status)+\
                    ")]	["+proto+virt_host+"/"+"/".join(list)+paramlines+"]	"+ \
                    str(cherrypy.request.headers)+"	"+str(cherrypy.request.body.params)+"\n"
                #<"+cherrypy.request.stage+">
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
            
def conf_update_print(new_conf,old_conf):
    options = {
            "vhosts-enabled":"Virtual hosts are now",
            "php":"PHP is now",
            "log":"Logging is now",
            "page_response_check":"Page response checks are now",
            "page_request_timeout":"Page request time outs are now",
            "database_connections":"Database connections are now"
    }
    for data in options:
        if not new_conf[data]==old_conf[data]:
            if new_conf[data]==True:
                on = "enabled."
            else:
                on = "disabled."
            RedServ.debugger(3,options[data]+" "+str(on))
            
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
        if (not new_conf["HTTP"]["ports"]==old_conf["HTTP"]["ports"]) and False: #disabled for now, has issues wherein the entire web server locks up or new ports don't start.
            new_http_ports = ""
            old_http_ports = ""
            for port in RedServ.servers["HTTP"]:
                if not port in new_conf["HTTP"]["ports"]:
                    RedServ.servers["HTTP"][port].stop()
                    old_http_ports = old_http_ports+str(port)+", "
            print("Stopped http on ports: "+old_http_ports[:-2])
            for port in new_conf["HTTP"]["ports"]:
                if not port in old_conf["HTTP"]["ports"]:
                    RedServ.servers["HTTP"][port] = cherrypy._cpserver.Server()
                    RedServ.servers["HTTP"][port].socket_port=port
                    RedServ.servers["HTTP"][port].socket_host='0.0.0.0'
                    RedServ.servers["HTTP"][port].thread_pool=new_conf["HTTP"]["thread_pool"]
                    RedServ.servers["HTTP"][port].socket_queue_size=new_conf["HTTP"]["socket_queue"]
                    RedServ.servers["HTTP"][port].thread_pool_max=-1
                    RedServ.servers["HTTP"][port].shutdown_timeout=1
                    RedServ.servers["HTTP"][port].socket_timeout=3
                    #RedServ.servers["HTTP"][port].statistics=True
                    RedServ.servers["HTTP"][port].subscribe()
                    RedServ.servers["HTTP"][port].start()
                    new_http_ports = new_http_ports+str(port)+", "
            STDPORT = conf["HTTP"]["ports"][0]
            RedServ.http_port = STDPORT
            RedServ.http_ports = conf["HTTP"]["ports"]
            print("Started HTTP on: "+new_http_ports[:-2])
        if (not new_conf["HTTPS"]["ports"]==old_conf["HTTPS"]["ports"]) and False:
            new_https_ports = ""
            old_https_ports = ""
            removed_any_https_ports = False
            for port in RedServ.servers["HTTPS"]:
                if not port in new_conf["HTTPS"]["ports"]:
                    removed_any_https_ports = True
                    RedServ.servers["HTTPS"][port].stop()
                    old_https_ports = old_https_ports+str(port)+", "
            if removed_any_https_ports==True:
                print("Stopped HTTPS on ports: "+old_https_ports[:-2])
            for port in new_conf["HTTPS"]["ports"]:
                if not port in old_conf["HTTPS"]["ports"]:
                    RedServ.servers["HTTPS"][port] = cherrypy._cpserver.Server()
                    RedServ.servers["HTTPS"][port].socket_port=port
                    RedServ.servers["HTTPS"][port].socket_host='0.0.0.0'
                    RedServ.servers["HTTPS"][port].thread_pool=new_conf["HTTPS"]["thread_pool"]
                    RedServ.servers["HTTPS"][port].socket_queue_size=new_conf["HTTPS"]["socket_queue"]
                    RedServ.servers["HTTPS"][port].thread_pool_max=-1
                    RedServ.servers["HTTPS"][port].shutdown_timeout=1
                    RedServ.servers["HTTPS"][port].socket_timeout=3
                    #RedServ.servers["HTTPS"][port].statistics=True
                    RedServ.servers["HTTPS"][port].ssl_module = 'custom-pyopenssl'
                    RedServ.servers["HTTPS"][port].ssl_certificate = os.path.join(current_dir,new_conf["HTTPS"]["cert"])
                    RedServ.servers["HTTPS"][port].ssl_private_key = os.path.join(current_dir,new_conf["HTTPS"]["cert_private_key"])
                    if new_conf["HTTPS"]["CA_cert"]=="default-ca.pem" or new_conf["HTTPS"]["CA_cert"]=="":
                        new_conf["HTTPS"]["CA_cert"] = None
                    if not new_conf["HTTPS"]["CA_cert"]==None:
                        if os.path.exists(os.path.join(current_dir,new_conf["HTTPS"]["CA_cert"])):
                            RedServ.servers["HTTPS"][port].ssl_certificate_chain = str(os.path.join(current_dir,new_conf["HTTPS"]["CA_cert"]))
                    RedServ.servers["HTTPS"][port].subscribe()
                    new_https_ports = new_https_ports+str(port)+", "
            SSLPORT = conf["HTTPS"]["ports"][0]
            RedServ.https_ports = conf["HTTPS"]["ports"]
            RedServ.https_port = SSLPORT
            print("Started HTTPS on: "+new_https_ports[:-2])
        if not new_conf["vhost-lookup"]==old_conf["vhost-lookup"]:
            RedServ.debugger(3,"Virtual Host look up is now done by "+new_conf["vhost-lookup"])
        
        #Update Cherrypy's config
        site_logfolder = os.path.join(current_dir,"logs","site",RedServ.sysinfo(),time.strftime("%Y"), time.strftime("%m"))
        site_logfile = os.path.join(site_logfolder,time.strftime("%d")+".txt")
        if not os.path.exists(site_logfolder):
            os.makedirs(site_logfolder)
        global_conf = {
            'global': { 'engine.autoreload.on': False,
            'environment': 'embedded',
            'log.error_file': site_logfile,
            'log.screen': conf["logs_to_screen"],
            'gzipfilter.on':True,
            'tools.caching.on':False,
            'tools.gzip.mime_types':['text/html', 'text/plain', 'text/css', 'text/*'],
            'tools.gzip.on':True,
            'tools.encode.on':True,
            'tools.decode.on':True,
            'tools.json_in.on': True,
            'tools.json_in.force': False,
            'tools.sessions.on':conf["sessions"],
            'tools.sessions.locking':'explicit',
            #'tools.sessions.secure':conf["sessions"],
            'response.timeout': conf["page_request_timeout"],
            'engine.timeout_monitor.on':True,
            'engine.timeout_monitor.frequency':conf["page_response_check"]
        }}
        if not (os.path.join(current_dir,conf["cherrypy_access_logs"])==current_dir or conf["cherrypy_access_logs"]==""):
            global_conf['global']['log.access_file'] = os.path.join(current_dir,conf["cherrypy_access_logs"])
        cherrypy.config.update(global_conf)
        
        
        conf_update_print(new_conf,old_conf)
    return(new_conf)

def http_response(datatoreturn,params,virt_host,list,paramlines):
    if isinstance(datatoreturn["datareturned"],type("")):
        return(datatoreturn["datareturned"]+debughandler(params))
    if isinstance(datatoreturn["datareturned"],type(RedServ.staticfileserve(""))):
        return(datatoreturn["datareturned"].value)
    if isinstance(datatoreturn["datareturned"],type(cherrypy.HTTPRedirect(""))):
        (https_redirect_str,cherrypy.response.status) = datatoreturn["datareturned"]
        logging("", 1, [cherrypy,virt_host,list,paramlines])
        raise(datatoreturn["datareturned"])
    if isinstance(datatoreturn["datareturned"],type(cherrypy.HTTPError(404))):
        status,error = datatoreturn["datareturned"]
        cherrypy.response.status = status
        cherrypy.response.headers["content-type"] = "text/plain"
        logging("", 1, [cherrypy,virt_host,list,paramlines])
        local_error_pages = datatoreturn["local_error_pages"]
        RedServ.error_pages[virt_host] = local_error_pages
        cherrypy.serving.request.error_page = RedServ.error_pages[virt_host]
        raise(cherrypy.HTTPError(status,str(error)+str(debughandler(params))))
    return(datatoreturn["datareturned"])

class WebInterface:
    """ main web interface class """

    def default(self, *args,**params):
        global lookup
        global cherrypy
        global site_glo_data
        global site_shared_data
        global python_page_cache
        global sieve_cache
        global STDPORT
        global SSLPORT
        #global conf
        #conf = conf_reload(conf)
        
        RedServ.http_port = STDPORT
        RedServ.https_port = SSLPORT
        
        cherrypy.response.headers["Server"] = RedServ._version_
        cherrypy.response.headers['X-Original-Server'] = RedServ._version_
        bad = False
        list = args
        paramlines = ""
        if "json" in dir(cherrypy.request):
            cherrypy.request.body.params.update(cherrypy.request.json)
            params.update(cherrypy.request.json)
        rproxied_test = "X-Forwarded-Host" in cherrypy.request.headers and ((cherrypy.request.local.port==STDPORT and conf["HTTP"]["reverse_proxied"]==True) or (cherrypy.request.local.port==SSLPORT and conf["HTTPS"]["reverse_proxied"]==True))
        if len(cherrypy.request.query_string)>0:
            paramlines = "?"+cherrypy.request.query_string
        if "host" in cherrypy.request.headers or rproxied_test==True:
            if "host" in cherrypy.request.headers:
                virt_host = cherrypy.request.headers["host"].lower()
            if rproxied_test==True:
                virt_host = cherrypy.request.headers["X-Forwarded-Host"].lower()
        else:
            cherrypy.response.status = 404
            logging("", 1, [cherrypy,"No host header",list,paramlines])
            return("")
        if cherrypy.request.local.port==STDPORT:
            if conf["HTTP"]["reverse_proxied"]==True:
                cherrypy.request.remote.ip = cherrypy.request.headers['X-Forwarded-For']
        if cherrypy.request.local.port==SSLPORT:
            if conf["HTTPS"]["reverse_proxied"]==True:
                cherrypy.request.remote.ip = cherrypy.request.headers['X-Forwarded-For']

        if conf["vhosts-enabled"]==True:
            virtloc = os.path.join(os.path.abspath('pages'),vhosts(virt_host,conf))+os.sep
        else:
            virtloc = os.path.abspath('pages')+os.sep
        if not os.path.exists(virtloc):
            cherrypy.response.status = 404
            logging("", 1, [cherrypy,virt_host,list,paramlines])
            return("")
        
        if not virt_host in site_glo_data:
            site_glo_data[virt_host] = {}
            if conf["database_connections"]==True:
                db_folders = os.path.join("sites",vhosts(virt_host,conf))
                site_glo_data[virt_host]["db_conn_loc"] = (virt_host,db_folders)
        
        if not virt_host in RedServ.error_pages:
            RedServ.error_pages[virt_host] = RedServ.default_error_pages
        local_error_pages = RedServ.error_pages[virt_host]
        cherrypy.serving.request.error_page = RedServ.error_pages[virt_host]
        
        if conf["database_connections"]==True:
            if not "db_conn_loc" in site_glo_data[virt_host]:
                db_folders = os.path.join("sites",vhosts(virt_host,conf))
                site_glo_data[virt_host]["db_conn_loc"] = (virt_host,db_folders)
            if not isinstance(site_glo_data[virt_host]["db_conn_loc"], tuple):
                db_folders = os.path.join("sites",vhosts(virt_host,conf))
                site_glo_data[virt_host]["db_conn_loc"] = (virt_host,db_folders)
        
    ###Start
        filename = (virtloc+os.sep.join(list)).strip("..").replace("//","/")
        if os.path.exists(os.path.join(os.path.abspath('pages'),"sieve.py")) or os.path.exists(os.path.join(os.path.abspath(virtloc),"sieve.py")):
            page = virt_host+"/"+"/".join(list)
            datsieve = ""
            sievedata = {
            "sievetype":"in",
            "cherrypy": cherrypy,
            "page":page,
            "URL":page,
            "URI":"/".join(list),
            "file_path":filename,
            "this_domain":virt_host,
            "vhost_location":virtloc,
            "local_error_pages":local_error_pages,
            "data": datsieve,
            "bad":bad,
            "params":params,
            "global_site_data":site_shared_data,
            "return_after_this":False,
            "site_data":site_glo_data[virt_host]
            }
            try:
                (sievedata,sieve_cache) = sieve(sievedata,sieve_cache) #pre-page render sieve
            except Exception,e:
                if isinstance(e,type(RedServ.staticfileserve(""))):
                    return(e.value)
                if isinstance(e,type(cherrypy.HTTPRedirect(""))):
                    (https_redirect_str,cherrypy.response.status) = e
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    raise(e)
                if isinstance(e,type(cherrypy.HTTPError(404))):
                    status,error = e
                    cherrypy.response.status = status
                    cherrypy.response.headers["content-type"] = "text/plain"
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    raise(cherrypy.HTTPError(status,str(error)+str(debughandler(params))))
                cherrypy.response.status = 404
                cherrypy.response.headers["content-type"] = "text/plain"
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                return("404\n"+RedServ.trace_back(False))
            bad = sievedata['bad']
            cherrypy = sievedata['cherrypy']
            filename = sievedata['file_path']
            local_error_pages = sievedata['local_error_pages']
            site_shared_data = sievedata['global_site_data']
            site_glo_data[virt_host] = sievedata['site_data']
            RedServ.error_pages[virt_host] = local_error_pages
            cherrypy.serving.request.error_page = RedServ.error_pages[virt_host]
            list = sievedata['URI'].split("/")
            if isinstance(sievedata['data'],type(RedServ.staticfileserve(""))):
                return(sievedata['data'].value)
            if isinstance(sievedata['data'],type(cherrypy.HTTPRedirect(""))):
                (https_redirect_str,cherrypy.response.status) = sievedata['data']
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                raise(sievedata['data'])
            if isinstance(sievedata['data'],type(cherrypy.HTTPError(404))):
                status,error = sievedata['data']
                cherrypy.response.status = status
                cherrypy.response.headers["content-type"] = "text/plain"
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                raise(cherrypy.HTTPError(status,str(error)+str(debughandler(params))))
            
            no_serve_message = "404\n"+"/"+"/".join(list)
            if page in RedServ.noserving:
                cherrypy.response.headers["content-type"] = "text/plain"
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                raise(cherrypy.HTTPError(404,no_serve_message))
            #if cherrypy.request.login==None:
            #    if (page in RedServ.basicauth) or (virt_host in RedServ.basicauth):
            #        bad = True
            #        datatoreturn["datareturned"] = "Please login."
            #        cherrypy.response.status = 401
            #   ^ handle basic auth protection requests and make sure to add input of a realm and a user list.    
        else:
            sievedata = {
            "return_after_this":False
            }
        if bad == False:
            headers = {}
            responsecode = 200
            if not os.path.exists(virtloc) and conf["vhosts-enabled"]==True:
                return("")
            if len(list)>=2 and str(list[0]).lower()=="static":
                #cherrypy.response.headers['Cache-Control'] = 'private, max-age=120'
                if str(list[0])=="static":
                    if not os.path.exists(os.path.join(current_dir,os.sep.join(list))):
                        return(notfound(cherrypy,virt_host,paramlines,list,params))
                    if cherrypy.response.status==None:
                        cherrypy.response.status = 200
                    
                    file = current_dir+os.sep+os.sep.join(list)
                    return(RedServ._serve_static_file(virt_host,list,paramlines,file))
                else:
                    if os.path.exists(filename):
                        return(RedServ._serve_static_file(virt_host,list,paramlines,filename))
                    else:
                        cherrypy.response.status = 404
                        cherrypy.response.headers["content-type"] = "text/plain"
                        logging("", 1, [cherrypy,virt_host,list,paramlines])
                        return("404")
            cherrypy.response.headers['Cache-Control'] = 'no-cache'
            if os.path.exists(filename):
                if os.path.isfile(filename):
                    filename = filepicker(filename,fileext)
                else:
                    try:
                        filename = filepicker(filename,folderext)
                        open(filename, 'r')
                    except Exception,e:
                        cherrypy.response.status = 404
                        cherrypy.response.headers["content-type"] = "text/plain"
                        logging("", 1, [cherrypy,virt_host,list,paramlines])
                        return(notfound2(cherrypy,e,virtloc,params))
            else:
                filename = filepicker(filename,fileext)
                if not os.path.exists(filename) or filename==None:
                    cherrypy.response.status = 404
                    cherrypy.response.headers["content-type"] = "text/plain"
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    return(notfound2(cherrypy,"File Not Found.",virtloc,params))
            if not (filename.endswith(".py") or filename.endswith(".php")):
                if os.path.exists(filename):
                    return(RedServ._serve_static_file(virt_host,list,paramlines,filename))
                else:
                    if str(list[0]).lower()=="favicon.ico":
                        return(RedServ._serve_static_file(virt_host,list,paramlines,os.path.join(current_dir, 'static', "favicon.ico")))
                    else:
                        cherrypy.response.status = 404
                        cherrypy.response.headers["content-type"] = "text/plain"
                        logging("", 1, [cherrypy,virt_host,list,paramlines])
                        raise(cherrypy.HTTPError(status,""))
            datatoreturn = {
            "sievetype":"out", 
            "params":params,
            "datareturned":"'",
            "headers":headers,
            "response":responsecode,
            "request":cherrypy.request,
            "filelocation":filename,
            "vhost_location":virtloc,
            "local_error_pages":local_error_pages,
            "filename":filename.strip(virtloc+os.sep.join(list)),
            "this_page":virt_host+"/"+"/".join(list),
            "this_domain":virt_host,
            "global_site_data":site_shared_data,
            "return_after_this":sievedata['return_after_this'],
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
                    local_error_pages = datatoreturn["local_error_pages"]
                    RedServ.error_pages[virt_host] = local_error_pages
                    cherrypy.serving.request.error_page = RedServ.error_pages[virt_host]
            except Exception,e:
                if isinstance(e,type(RedServ.staticfileserve(""))):
                    return(e.value)
                if isinstance(e,type(cherrypy.HTTPRedirect(""))):
                    (https_redirect_str,cherrypy.response.status) = e
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    raise(e)
                if isinstance(e,type(cherrypy.HTTPError(404))):
                    status,error = e
                    cherrypy.response.status = status
                    cherrypy.response.headers["content-type"] = "text/plain"
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    cherrypy.serving.request.error_page = RedServ.error_pages[virt_host]
                    raise(cherrypy.HTTPError(status,str(error)+str(debughandler(params))))
                type_, value_, traceback_ = sys.exc_info()
                ex = traceback.format_exception(type_, value_, traceback_)
                trace = "\n".join(ex)
                cherrypy.response.status = 404
                datatoreturn["datareturned"] = "404\n"+str(trace).replace(virtloc,"/")
                (datatoreturn,sieve_cache) = sieve(datatoreturn,sieve_cache)
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                cherrypy.response.headers["content-type"] = "text/plain"
                return(http_response(datatoreturn,params,virt_host,list,paramlines))
            if isinstance(datatoreturn["datareturned"],type(RedServ.staticfileserve(""))):
                return(datatoreturn["datareturned"].value)
            if isinstance(datatoreturn["datareturned"],type(cherrypy.HTTPRedirect(""))):
                (https_redirect_str,cherrypy.response.status) = datatoreturn["datareturned"]
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                raise(datatoreturn["datareturned"])
            if isinstance(datatoreturn["datareturned"],type(cherrypy.HTTPError(404))):
                status,error = datatoreturn["datareturned"]
                cherrypy.response.status = status
                cherrypy.response.headers["content-type"] = "text/plain"
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                cherrypy.serving.request.error_page = RedServ.error_pages[virt_host]
                raise(cherrypy.HTTPError(status,str(error)+str(debughandler(params))))
            try:
                (datatoreturn,sieve_cache) = sieve(datatoreturn,sieve_cache)
            except Exception,e:
                if isinstance(e,type(RedServ.staticfileserve(""))):
                    return(e.value)
                if isinstance(e,type(cherrypy.HTTPRedirect(""))):
                    (https_redirect_str,cherrypy.response.status) = e
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    raise(e)
                if isinstance(e,type(cherrypy.HTTPError(404))):
                    status,error = e
                    cherrypy.response.status = status
                    cherrypy.response.headers["content-type"] = "text/plain"
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    raise(cherrypy.HTTPError(status,str(error)+str(debughandler(params))))
                cherrypy.response.status = 404
                logging("", 1, [cherrypy,virt_host,list,paramlines])
                cherrypy.response.headers["content-type"] = "text/plain"
                cherrypy.serving.request.error_page = RedServ.error_pages[virt_host]
                raise(cherrypy.HTTPError(404,RedServ.trace_back(False)+debughandler(params)))
            site_shared_data = datatoreturn['global_site_data']
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
            return(http_response(datatoreturn,params,virt_host,list,paramlines))
        else:
            logging("", 1, [cherrypy,virt_host,list,paramlines])
            return(str(sievedata["data"]))
    ###end
      
    default.exposed = True
        

def web_init(page_observer,config_observer):
    print("INFO: Initialising web server...")
    from cherrypy._cpnative_server import CPHTTPServer
    cherrypy.server.httpserver = CPHTTPServer(cherrypy.server)
    os.chdir(current_dir)
    db_loc = os.path.abspath('db')
    pathing = [
    "certs",
    "db",
    "logs",
    os.path.join("logs","site"),
    "pages",
    "static",
    "templates",
    "util"
    ]
    for data in pathing:
        if not os.path.exists(os.path.abspath(data)):
            os.mkdir(os.path.abspath(data))
    global RedServ
    RedServ = RedServer()
    page_observer.start()
    config_observer.start()
    RedServ.debugger(3,"Started file watchdogs.")
    RedServ.debugger(3,"CherryPy version: "+cherrypy.__version__+" HTTP server version: "+cherrypy.server.httpserver.version)
    cherrypy.server.httpserver.version = RedServ._version_
    cherrypy.__version__ = RedServ._version_
    RedServ.debugger(3,"Starting RedServ version: "+RedServ._version_string_)
    RedServ.start_background_service("__internal__RedServ__service__mem_clean_up",30,RedServ.gc_collect)
    # Config init and caching, We need this for enabling the SSL changes inside of Cherrypy if SSL is enabled.
    conflocation = os.path.join(current_dir,"config")
    config_init(conflocation)
    config_cache.append(json.load(open(conflocation)))
    config_cache.append(os.path.getmtime(conflocation))
    global conf
    conf = config(conflocation)
    if conf["HTTPS"]["enabled"]==False and conf["HTTP"]["enabled"]==False:
        RedServ.debugger(0,"You need to enable one transfer protocol, either HTTP or HTTPS in the config")
        exit()
    RedServ.debugger(3,"Hostname: "+RedServ.sysinfo())
    site_logfolder = os.path.join(current_dir,"logs","site",RedServ.sysinfo(),time.strftime("%Y"), time.strftime("%m"))
    site_logfile = os.path.join(site_logfolder,time.strftime("%d")+".txt")
    if not os.path.exists(site_logfolder):
        os.makedirs(site_logfolder)
    global_conf = {
        'global': { 'engine.autoreload.on': False,
        'environment': 'embedded',
        'log.error_file': site_logfile,
        'log.screen': conf["logs_to_screen"],
        'gzipfilter.on':True,
        'tools.caching.on':False,
        'tools.gzip.mime_types':['text/html', 'text/plain', 'text/css', 'text/*'],
        'tools.gzip.on':True,
        'tools.encode.on':True,
        'tools.decode.on':True,
        'tools.json_in.on': True,
        'tools.json_in.force': False,
        'tools.sessions.on':conf["sessions"],
        'tools.sessions.locking':'explicit',
        #'tools.sessions.secure':conf["sessions"],
        'response.timeout': conf["page_request_timeout"],
        'engine.timeout_monitor.on':True,
        'engine.timeout_monitor.frequency':conf["page_response_check"]
    }}
    if not (os.path.join(current_dir,conf["cherrypy_access_logs"])==current_dir or conf["cherrypy_access_logs"]==""):
        global_conf['global']['log.access_file'] = os.path.join(current_dir,conf["cherrypy_access_logs"])
    cherrypy.config.update(global_conf)
    web_interface = WebInterface()
    tree_mount = cherrypy.tree.mount(web_interface, '/')
    del tree_mount.root.favicon_ico
    
    cherrypy.server.unsubscribe()
    cherrypy.server.stop()

    global STDPORT
    STDPORT = conf["HTTP"]["ports"][0]
    RedServ.http_port = STDPORT
    RedServ.http_ports = conf["HTTP"]["ports"]
    global SSLPORT
    SSLPORT = conf["HTTPS"]["ports"][0]
    RedServ.https_ports = conf["HTTPS"]["ports"]
    RedServ.https_port = SSLPORT
    if conf["HTTPS"]["enabled"]==True and SSL_imported==True:
        from util import ssl_fix
        if sys.version_info < (3, 0):
            from cherrypy.wsgiserver.wsgiserver2 import ssl_adapters
        else:
            from cherrypy.wsgiserver.wsgiserver3 import ssl_adapters
        ssl_adapters = ssl_fix.fix(ssl_adapters,RedServ)
    if conf["HTTPS"]["enabled"]==True and SSL_imported==True:
        if not (os.path.exists(os.path.join(current_dir,conf["HTTPS"]["cert"])) and os.path.exists(os.path.join(current_dir,conf["HTTPS"]["cert_private_key"]))):
            SSL_cert_gen(RedServ.sysinfo(),os.path.abspath("certs"))
        if conf["HTTPS"]["cert"]=="":
            conf["HTTPS"]["cert"] = os.path.join('certs','cert.pem')
        if conf["HTTPS"]["cert_private_key"]=="":
            conf["HTTPS"]["cert_private_key"] = os.path.join('certs','privkey.pem')
        for port in RedServ.https_ports:
            RedServ.servers["HTTPS"][port] = cherrypy._cpserver.Server()
            RedServ.servers["HTTPS"][port].socket_port=port
            RedServ.servers["HTTPS"][port].socket_host='0.0.0.0'
            RedServ.servers["HTTPS"][port].thread_pool=conf["HTTPS"]["thread_pool"]
            RedServ.servers["HTTPS"][port].socket_queue_size=conf["HTTPS"]["socket_queue"]
            RedServ.servers["HTTPS"][port].thread_pool_max=-1
            RedServ.servers["HTTPS"][port].shutdown_timeout=1
            RedServ.servers["HTTPS"][port].socket_timeout=3
            #RedServ.servers["HTTPS"][port].statistics=True
            RedServ.servers["HTTPS"][port].ssl_module = 'custom-pyopenssl'
            RedServ.servers["HTTPS"][port].ssl_certificate = os.path.join(current_dir,conf["HTTPS"]["cert"])
            RedServ.servers["HTTPS"][port].ssl_private_key = os.path.join(current_dir,conf["HTTPS"]["cert_private_key"])
            if conf["HTTPS"]["CA_cert"]=="default-ca.pem" or conf["HTTPS"]["CA_cert"]=="":
                conf["HTTPS"]["CA_cert"] = None
            if not conf["HTTPS"]["CA_cert"]==None:
                if os.path.exists(os.path.join(current_dir,conf["HTTPS"]["CA_cert"])):
                    RedServ.servers["HTTPS"][port].ssl_certificate_chain = str(os.path.join(current_dir,conf["HTTPS"]["CA_cert"]))
            RedServ.servers["HTTPS"][port].subscribe()
    if conf["HTTP"]["enabled"]==True:
        for port in RedServ.http_ports:
            RedServ.servers["HTTP"][port] = cherrypy._cpserver.Server()
            RedServ.servers["HTTP"][port].socket_port=port
            RedServ.servers["HTTP"][port].socket_host='0.0.0.0'
            RedServ.servers["HTTP"][port].thread_pool=conf["HTTP"]["thread_pool"]
            RedServ.servers["HTTP"][port].socket_queue_size=conf["HTTP"]["socket_queue"]
            RedServ.servers["HTTP"][port].thread_pool_max=-1
            RedServ.servers["HTTP"][port].shutdown_timeout=1
            RedServ.servers["HTTP"][port].socket_timeout=3
            #RedServ.servers["HTTP"][port].statistics=True
            RedServ.servers["HTTP"][port].subscribe()
    
    sievepath = os.path.join(os.path.abspath('pages'),"sieve.py")
    sieve_cache["global"] = []
    if os.path.exists(sievepath):
        sieve_cache["global"].append(os.path.getmtime(sievepath))
        sieve_cache["global"].append(compile(open(sievepath,'r').read(),sievepath,'exec'))
    
    port_statuses = "Web server starting up: "
    if conf["HTTP"]["enabled"]==True:
        port_statuses = port_statuses+"HTTP ports: "
        for port in RedServ.http_ports:
            port_statuses = port_statuses+str(port)+", "
        port_statuses = port_statuses[:-2]+" "
    if conf["HTTPS"]["enabled"]==True and SSL_imported==True:
        port_statuses = port_statuses+"HTTPS ports: "
        for port in RedServ.https_ports:
            port_statuses = port_statuses+str(port)+", "
        port_statuses = port_statuses[:-2]
    RedServ.debugger(3,port_statuses)
    if not os.name=="nt":
        cherrypy.engine.signals.subscribe()
    cherrypy.engine.start()
    RedServ.debugger(3,"Web server init finished\nYou are free for take off!") # yay!
    cherrypy.engine.block()

if __name__ == '__main__':
    watchdog_path = os.path.join(current_dir,"pages")
    page_file_event_handler = PageFileEventHandler()
    page_event_handler = watchdog_file_event_handler()
    page_event_handler.on_any_event = page_file_event_handler.on_any_event
    page_event_handler.on_moved = page_file_event_handler.on_moved
    page_event_handler.on_created = page_file_event_handler.on_created
    page_event_handler.on_deleted = page_file_event_handler.on_deleted
    page_event_handler.on_modified = page_file_event_handler.on_modified
    page_page_observer = watchdog_observer()
    page_observer = watchdog_observer()
    page_observer.schedule(page_event_handler, watchdog_path, recursive=True)

    config_file_event_handler = ConfigFileEventHandler()
    config_event_handler = watchdog_file_event_handler()
    config_event_handler.on_any_event = config_file_event_handler.on_any_event
    config_event_handler.on_moved = config_file_event_handler.on_moved
    config_event_handler.on_created = config_file_event_handler.on_created
    config_event_handler.on_deleted = config_file_event_handler.on_deleted
    config_event_handler.on_modified = config_file_event_handler.on_modified
    config_observer = watchdog_observer()
    config_observer.schedule(config_event_handler, current_dir, recursive=False)
    try:
        web_init(page_observer,config_observer)
    except Exception as e:
        type_, value_, traceback_ = sys.exc_info()
        trace = traceback.format_exception(type_, value_, traceback_)
        print("CRITICAL: "+"\n".join(trace))
    finally:
        page_observer.stop()
        config_observer.stop()
    page_observer.join()
    config_observer.join()
    exit()