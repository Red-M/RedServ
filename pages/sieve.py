def sievein(cherrypy,page,data,bad):
    if "host" in cherrypy.request.headers:
        if cherrypy.request.headers['Host'] == "host":
            cherrypy.response.status = 404
            bad = True
        if ":" in cherrypy.request.headers["host"]:
            cherrypy.request.headers["host"] = cherrypy.request.headers["host"].split(":")[0]
    cherrypy.response.headers["Server"] = "RedServ 1.0"
    if "User-Agent" in cherrypy.request.headers:
        if "Baiduspider" in cherrypy.request.headers["User-Agent"]:
            cherrypy.response.status = 404
            bad = True
        if 'curl' in cherrypy.request.headers["User-Agent"]:
            cherrypy.response.status = 404
            bad = True
        if 'bot' in cherrypy.request.headers["User-Agent"]:
            cherrypy.response.status = 404
            bad = True
    if "Host" in cherrypy.request.headers:
        if cherrypy.request.headers['Host'] == "HOST":
            cherrypy.response.status = 404
            bad = True
    if "Accept-Language" in cherrypy.request.headers:
        if "zh-cn" in cherrypy.request.headers["Accept-Language"].lower():
            cherrypy.response.status = 404
            bad = True
    if 'Connection' in cherrypy.request.headers:
        if 'close' in cherrypy.request.headers['Connection']:
            cherrypy.response.status = 404
            bad = True
    else:
        if "Host" in cherrypy.request.headers:
            if cherrypy.request.headers['Host'] == "HOST2":
                cherrypy.response.status = 404
                bad = True
    return(cherrypy,page,data,bad)

def sieveout(params,datareturned,cj,headers,response,request):
    virthost = request.headers["host"]
    datareturned = str(datareturned).replace(os.path.join(os.path.abspath('pages'),virthost),"")
    datareturned = str(datareturned).replace(os.path.abspath('pages'),"")
    datareturned = str(datareturned).replace(str(os.path.abspath('pages')).replace(os.sep+"pages",""),"")
    datareturned = str(datareturned).replace("EXAMPLE TEXT STRING","")
    datareturned = datareturned + debughandler(params)
    return(params,datareturned,cj,headers,response,request)
    
    
if sievetype=="in":
    cherrypy,page,data,bad = sievein(cherrypy,page,data,bad)
elif sievetype=="out":
    params,datareturned,cj,headers,response,request = sieveout(params,datareturned,cj,headers,response,request)
