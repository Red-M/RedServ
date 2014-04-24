global regexmatch2
def regexmatch2(text,regex):
    match = regex.match(text)
    if not match:
        return("")
    (matcho,) = match.groups()
    return matcho

def sieve(params,datareturned,cj,headers,response,request):
    virthost = request.headers["host"]
    if os.name == "posix":
        datareturned = str(datareturned).replace(os.path.abspath('pages')+"/"+virthost,"")
        datareturned = str(datareturned).replace(os.path.abspath('pages'),"")
        datareturned = str(datareturned).replace(str(os.path.abspath('pages')).replace("/pages",""),"")
    if os.name == "nt":
        datareturned = str(datareturned).replace(os.path.abspath('pages')+"\\"+virthost,"")
        datareturned = str(datareturned).replace(os.path.abspath('pages'),"")
        datareturned = str(datareturned).replace(str(os.path.abspath('pages')).replace("\\pages",""),"")
    datareturned = str(datareturned).replace("EXAMPLE TEXT STRING","")
    datareturned = datareturned + debughandler(params)
    return(params,datareturned,cj,headers,response,request)
    
params,datareturned,cj,headers,response,request = sieve(params,datareturned,cj,headers,response,request)
