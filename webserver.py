#!/usr/bin/env python
import cherrypy
import OpenSSL
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

os.chdir(sys.path[0] or '.')
global current_dir
current_dir = os.path.abspath('.')
global exed
exed = False
if current_dir.endswith(".zip"):
    exed = True
site_glo_data = {}

class RedServer(object):
    def __init__(self):
        self.nologging = []

    def test(self,out):
        print(out)

    def nolog(self,page=None,domain=None):
        if not page==None:
            if not page in self.nologging:
                self.nologging.append(page)
        if not domain==None:
            if not domain in self.nologging:
                self.nologging.append(domain)
            
    def log(self,page=None,domain=None):
        if not page==None:
            if page in self.nologging:
                self.nologging.remove(page)
        if not domain==None:
            if domain in self.nologging:
                self.nologging.remove(domain)

def config_init(configlocation):
    if not os.path.exists(configlocation):
        open(configlocation, 'w').write(inspect.cleandoc(
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

global cj
cj = CookieJar()
    
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
"index.php",
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

fileends = [
'.doc', '.docx', '.log', '.msg', '.odt', '.pages',
'.rtf', '.tex', '.txt', '.wpd', '.wps', '.csv', 
'.dat', '.gbr', '.ged', '.key', '.keychain', '.pps',
'.ppt', '.pptx', '.sdf', '.tar', '.tax2012', '.vcf',
'.xml', '.aif', '.iff', '.m3u', '.m4a', '.mid', '.mp3',
'.mpa', '.ra', '.wav', '.wma', '.3g2', '.3gp', '.asf',
'.asx', '.avi', '.flv', '.m4v', '.mov', '.mp4', '.mpg',
'.rm', '.srt', '.swf', '.vob', '.wmv', '.3dm', '.3ds',
'.max', '.obj', '.bmp', '.dds', '.gif', '.jpg', '.png',
'.psd', '.pspimage', '.tga', '.thm', '.tif', '.tiff',
'.yuv', '.ai', '.eps', '.ps', '.svg', '.indd', '.pct',
'.pdf', '.xlr', '.xls', '.xlsx', '.accdb', '.db', '.dbf',
'.mdb', '.pdb', '.sql', '.apk', '.app', '.bat', '.cgi',
'.com', '.exe', '.gadget', '.jar', '.pif', '.vb', '.wsf',
'.dem', '.gam', '.nes', '.rom', '.sav', '.dwg', '.dxf',
'.gpx', '.kml', '.kmz', '.asp', '.aspx', '.cer', '.cfm',
'.csr', '.css', '.htm', '.html', '.js', '.jsp', '.php',
'.rss', '.xhtml', '.crx', '.plugin', '.fnt', '.fon',
'.otf', '.ttf', '.cab', '.cpl', '.cur', '.deskthemepack',
'.dll', '.dmp', '.drv', '.icns', '.ico', '.lnk', '.sys',
'.cfg', '.ini', '.prf', '.hqx', '.mim', '.uue', '.7z',
'.cbr', '.deb', '.gz', '.pkg', '.rar', '.rpm', '.sitx',
'.bz2', '.zip', '.zipx', '.bin', '.cue', '.dmg', '.iso',
'.mdf', '.toast', '.vcd', '.c', '.class', '.cpp', '.cs',
'.dtd', '.fla', '.h', '.java', '.lua', '.m', '.pl', '.py',
'.sh', '.sln', '.swift', '.vcxproj', '.xcodeproj', '.bak',
'.tmp', '.crdownload', '.ics', '.msi', '.part', '.torrent',
'.webm'
]


def filepicker(filename,fileext):
    for data in fileext:
        if os.path.exists(filename+data):
            try:
                open(filename+data).read()
                filename = (filename+data)
            except Exception,e:
                filename = (os.path.join(filename,"index"+data))
    return(filename)
    
def create_ssl_cert(cert_dir="."):
    CERT_FILE = "cert.pem"
    KEY_FILE = "privkey.pem"
    C_F = os.path.join(cert_dir, CERT_FILE)
    K_F = os.path.join(cert_dir, KEY_FILE)
    return(C_F,K_F)
    
def SSL_cert_gen(nodename):
    (C_F,K_F) = create_ssl_cert()
    if not os.path.exists(C_F) or not os.path.exists(K_F):
        k = OpenSSL.crypto.PKey()
        k.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)
        cert = OpenSSL.crypto.X509()
        cert.get_subject().C = "na"
        cert.get_subject().ST = "n/a"
        cert.get_subject().L = "n/a"
        cert.get_subject().O = "n/a"
        cert.get_subject().OU = "n/a"
        cert.get_subject().CN = nodename
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')
        open(C_F, "wt").write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        open(K_F, "wt").write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k))

    
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
    lookuptypes = [
    "domains",
    "single-host",
    "IPs"
    ]
    global conf
    hosts = os.listdir(os.path.abspath('pages'))
    if ":" in virt_host:
        pos = virt_host.find(":")
        virt_host = virt_host[:pos]
    if conf["vhost-lookup"]=="domains":
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
    if conf["vhost-lookup"]=="single-host":
        return(os.path.join(data,virt_host))
    if conf["vhost-lookup"]=="IPs":
        split = virt_host.split(".")
        host = split[0]+"."+split[1]+"."+split[2]
        return(os.path.join(os.path.abspath('pages'),host,split[3]))
    elif not conf["vhost-lookup"] in lookuptypes:
        print("FATAL: VHOST LOOKUP IS INCORRECTLY SET TO AN INVALID VALUE! PLEASE EDIT THE CONFIG TO FIX THIS!")
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
                this_page = virt_host+"/"+"/".join(list)
                if not this_page in RedServ.nologging and not virt_host in RedServ.nologging:
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
            
def conf_reload(conf):
    global STDPORT
    global SSLPORT
    old_conf = conf
    new_conf = config(os.path.join(current_dir,"config"))
    if not old_conf==new_conf:
        new_conf["HTTP"]["enabled"] = old_conf["HTTP"]["enabled"]
        new_conf["HTTPS"]["enabled"] = old_conf["HTTPS"]["enabled"]
        new_conf["HTTP"]["port"] = STDPORT
        new_conf["HTTPS"]["port"] = SSLPORT
        if not new_conf["vhosts-enabled"]==old_conf["vhosts-enabled"]:
            if new_conf["vhosts-enabled"]==True:
                vhoston = "Enabled"
            else:
                vhoston = "Disabled"
            print("vhosts are now: "+str(vhoston))
        if not new_conf["php"]==old_conf["php"]:
            if new_conf["php"]==True:
                phpon = "Enabled"
            else:
                phpon = "Disabled"
            print("php is now: "+str(phpon))
        if not new_conf["log"]==old_conf["log"]:
            if new_conf["log"]==True:
                log = "Enabled"
            else:
                log = "Disabled"
            print("Logging is now "+str(log))
        if not new_conf["vhost-lookup"]==old_conf["vhost-lookup"]:
            print("Virtual Host look up is now done by "+new_conf["vhost-lookup"])
        return(new_conf)
    else:
        return(old_conf)
        
class WebInterface:
    """ main web interface class """

    def default(self, *args,**params):
        global cj
        global lookup
        global cherrypy
        global site_glo_data
        global conf
        global STDPORT
        global SSLPORT
        conf = conf_reload(conf)
        
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
                params[data] = params[data].replace("\n","\\n").replace("\r","\\r")
                paramlines = paramlines+data+"="+params[data]+"&"
            paramlines = paramlines[:-1]
        if paramlines=="?":
            paramlines = ""
            
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
            
        lookup = template_reload(current_dir) #template refresh
        
    ###Start
        if os.path.exists(os.path.join(os.path.abspath('pages'),"sieve.py")):
            datsieve = ""
            sievedata = {
            "sievetype":"in",
            "cherrypy": cherrypy,
            "page":virt_host+"/"+"/".join(list),
            "data": datsieve,
            "bad":bad,
            "params":params
            }
            sievedata = sieve(sievedata) #pre-page render sieve
            bad = sievedata['bad']
            cherrypy = sievedata['cherrypy']
        if bad == False:
            headers = {}
            responsecode = 200
            if len(list)>=1 and str(list[0]).lower()=="static":
                if str(list[0]).lower()=="static" and len(list)>=2:
                    if not os.path.exists(os.path.join(current_dir,os.sep.join(list))):
                        return(notfound(cherrypy,virt_host,paramlines,list,params))
                    if cherrypy.response.status==None:
                        cherrypy.response.status = 200
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    file = current_dir+os.sep+os.sep.join(list)
                    fileserve = True
                    for data in fileends:
                        if file.endswith(data) and fileserve:
                            fileserve = False
                            return(cherrypy.lib.static.serve_file(file))
                    if fileserve==True:
                        return(cherrypy.lib.static.serve_download(file))
                else:
                    cherrypy.response.status = 404
                    logging("", 1, [cherrypy,virt_host,list,paramlines])
                    return("404")
            cherrypy.response.headers['X-Best-Pony'] = "Derpy Hooves"
            cherrypy.response.headers['X-Comment'] = "Someone is reading my headers... >_>"
            cherrypy.response.headers["Server"] = "RedServ 1.0"
            if not os.path.exists(virtloc) and conf["vhosts-enabled"]==True:
                return("")
            filename = (virtloc+os.sep.join(list)).replace("..","").replace("//","/")
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
            for data in fileext:
                if filename.endswith(data) and os.path.exists(filename) and (not (filename.endswith(".py") or filename.endswith(".php"))):
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
            return(str(datatoreturn["datareturned"]))
        elif bad == True:
            logging("", 1, [cherrypy,virt_host,list,paramlines])
            return(str(sievedata["data"]))
    ###end
      
    default.exposed = True
        

def web_init():
    print "Initalising web server..."
    config_init(os.path.join(current_dir,"config"))
    global conf
    conf = config(os.path.join(current_dir,"config"))
    global RedServ
    RedServ = RedServer()
    if conf["HTTPS"]["enabled"]==False and conf["HTTP"]["enabled"]==False:
        print("ERROR::You need to enable one transfer protocol, either HTTP or HTTPS in the config")
        exit()
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
        'tools.decode.on':True,
        'tools.sessions.on':conf["sessions"]
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

    global STDPORT
    STDPORT = conf["HTTP"]["port"]
    global SSLPORT
    SSLPORT = conf["HTTPS"]["port"]
    if conf["HTTPS"]["enabled"]==True:
        SSL_cert_gen(nodename)
        server1 = cherrypy._cpserver.Server()
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

os.chdir(current_dir)
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

web_init()
