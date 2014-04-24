global regexmatch2
def regexmatch2(text,regex):
    match = regex.match(text)
    if not match:
        return("")
    (matcho,) = match.groups()
    return matcho

def sieve(cherrypy,page,data,bad):
    if "host" in cherrypy.request.headers:
        if cherrypy.request.headers['Host'] == "devin.red-m.net":
            cherrypy.response.status = 404
            bad = True
        if ":" in cherrypy.request.headers["host"]:
            cherrypy.request.headers["host"] = regexmatch2(cherrypy.request.headers["host"],re.compile(r'(.+?)\:.*',re.DOTALL))
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
        if cherrypy.request.headers['Host'] == "devin.red-m.net":
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
            if cherrypy.request.headers['Host'] == "munin.red-m.net":
                cherrypy.response.status = 404
                bad = True
    return(cherrypy,page,data,bad)
    
cherrypy,page,data,bad = sieve(cherrypy,page,data,bad)