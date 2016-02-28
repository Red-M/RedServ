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
import os,sys
import json
import ast

os.chdir('.' or sys.path[0])
current_dir = os.path.join(os.getcwd(),os.sep.join(sys.argv[0].split(os.sep)[0:-1]))
if current_dir.endswith("."):
    current_dir = current_dir[0:-1]
if sys.argv[0].split(os.sep)[-1] in os.listdir(current_dir):
    pass
else:
    print("Bad log path.")
    exit()
current_dir = os.path.join(current_dir,"logs")

def debug_log(file,line):
    print(file+"\n"+line)

def stat_gen(mode,round_amount,server_hits,req_types_recv,res_types_sent,req_res_types,global_page_hits):
    for server in sorted(server_hits):
        server_amount = int(server_hits[server])
        if round_amount==0:
            server_percent = server_hits[server]/global_page_hits*100
        else:
            server_percent = round(server_hits[server]/global_page_hits*100,round_amount)
        print("\n"+mode+": "+server+":	"+str(server_amount)+"	"+str(server_percent)+"%")
        print("	"+mode+" responses")
        for response in sorted(res_types_sent[server]):
            res_global = int(res_types_sent[server][response])
            if round_amount==0:
                res_percent = res_types_sent[server][response]/global_page_hits*100
            else:
                res_percent = round(res_types_sent[server][response]/global_page_hits*100,round_amount)
            print("		"+response+":	"+str(res_global)+"	"+str(res_percent)+"%")
        print("	"+mode+" request types")
        for req_type in sorted(req_types_recv[server]):
            res_global = int(req_types_recv[server][req_type])
            if round_amount==0:
                res_percent = req_types_recv[server][req_type]/global_page_hits*100
            else:
                res_percent = round(req_types_recv[server][req_type]/global_page_hits*100,round_amount)
            print("		"+req_type+":	"+str(res_global)+"	"+str(res_percent)+"%")
        print("	Request type to response stats:")
        for req_type in sorted(req_res_types[server]):
            for response in sorted(req_res_types[server][req_type]):
                res_amount = int(req_res_types[server][req_type][response])
                if round_amount==0:
                    res_percent = req_res_types[server][req_type][response]/server_hits[server]*100
                else:
                    res_percent = round(req_res_types[server][req_type][response]/server_hits[server]*100,round_amount)
                print("		"+req_type+"("+response+"):	"+str(res_amount)+"	"+str(res_percent)+"%")

def main():
    server_hits = {}
    domain_hits = {}
    page_hits = {}
    server_response_types_sent = {}
    domain_response_types_sent = {}
    response_types_sent = {}
    req_types_recv = {"domain":{},"server":{},"global":{}}
    res_types_sent = {"domain":{},"server":{},"global":{}}
    global_page_hits = 0.0
    
    
    
    
    for file in os.listdir(current_dir):
        if file.startswith("today."):
            file_loc = os.path.join(current_dir,file)
            f = open(file_loc,'r')
            f_data = f.read().strip()
            for line in f_data.split("\n"):
                line_split = line.split("	")
                if not line_split[1].startswith("Bad vhost:"):
                    req_time = line_split[0][1:-1]
                    ip = line_split[1]
                    req_type = line_split[2][1:-1].split("(")[0]
                    response = line_split[2][1:-1].split("(")[1][:-1]
                    if "?" in line_split[3][1:-1]:
                        page = line_split[3][1:-1].split("?")[0]
                        req_get_params = line_split[3][1:-1].split("?")[1]
                    else:
                        page = line_split[3][1:-1]
                        req_get_params = ""
                    try:
                        headers = json.loads(line_split[4].replace("'",'"'))
                    except:
                        headers = line_split[4]
                    domain = page.split("://")[1].split("/")[0]
                    server_name = file[6:-4]
                    
                    
                    
                    # if response=="None":
                        # debug_log(file,line)
                    
                    
                    
                    
                    global_page_hits += 1.0
                    if not domain in domain_hits:
                        domain_hits[domain] = 1.0
                    else:
                        domain_hits[domain] += 1.0
                    
                    if not server_name in server_hits:
                        server_hits[server_name] = 1
                    else:
                        server_hits[server_name] += 1
                    
                    if not page in page_hits:
                        page_hits[page] = 1.0
                    else:
                        page_hits[page] += 1.0
                    
                    if not req_type in response_types_sent:
                        response_types_sent[req_type] = {}
                    if not response in response_types_sent[req_type]:
                        response_types_sent[req_type][response] = 1.0
                    else:
                        response_types_sent[req_type][response] += 1.0
                    
                    if not server_name in server_response_types_sent:
                        server_response_types_sent[server_name] = {}
                    if not req_type in server_response_types_sent[server_name]:
                        server_response_types_sent[server_name][req_type] = {}
                    if not response in server_response_types_sent[server_name][req_type]:
                        server_response_types_sent[server_name][req_type][response] = 1.0
                    else:
                        server_response_types_sent[server_name][req_type][response] += 1.0
                    
                    if not domain in req_types_recv["domain"]:
                        req_types_recv["domain"][domain] = {}
                    if not req_type in req_types_recv["domain"][domain]:
                        req_types_recv["domain"][domain][req_type] = 1.0
                    else:
                        req_types_recv["domain"][domain][req_type] += 1.0
                    
                    if not server_name in req_types_recv["server"]:
                        req_types_recv["server"][server_name] = {}
                    if not req_type in req_types_recv["server"][server_name]:
                        req_types_recv["server"][server_name][req_type] = 1.0
                    else:
                        req_types_recv["server"][server_name][req_type] += 1.0
                    
                    if not req_type in req_types_recv["global"]:
                        req_types_recv["global"][req_type] = 1.0
                    else:
                        req_types_recv["global"][req_type] += 1.0
                    
                    if not domain in res_types_sent["domain"]:
                        res_types_sent["domain"][domain] = {}
                    if not response in res_types_sent["domain"][domain]:
                        res_types_sent["domain"][domain][response] = 1.0
                    else:
                        res_types_sent["domain"][domain][response] += 1.0
                    
                    if not server_name in res_types_sent["server"]:
                        res_types_sent["server"][server_name] = {}
                    if not response in res_types_sent["server"][server_name]:
                        res_types_sent["server"][server_name][response] = 1.0
                    else:
                        res_types_sent["server"][server_name][response] += 1.0
                    
                    if not response in res_types_sent["global"]:
                        res_types_sent["global"][response] = 1.0
                    else:
                        res_types_sent["global"][response] += 1.0
                    
                    if not domain in domain_response_types_sent:
                        domain_response_types_sent[domain] = {}
                    if not req_type in domain_response_types_sent[domain]:
                        domain_response_types_sent[domain][req_type] = {}
                    if not response in domain_response_types_sent[domain][req_type]:
                        domain_response_types_sent[domain][req_type][response] = 1.0
                    else:
                        domain_response_types_sent[domain][req_type][response] += 1.0
    
    
    
    round_amount = 3
    stat_gen("Domain",round_amount,domain_hits,req_types_recv["domain"],res_types_sent["domain"],domain_response_types_sent,global_page_hits)
    stat_gen("Server",round_amount,server_hits,req_types_recv["server"],res_types_sent["server"],server_response_types_sent,global_page_hits)
    
    print("\nGlobal today hits:	"+str(int(global_page_hits)))
    print("	Global responses")
    for response in sorted(res_types_sent["global"]):
        res_global = int(res_types_sent["global"][response])
        if round_amount==0:
            res_percent = res_types_sent["global"][response]/global_page_hits*100
        else:
            res_percent = round(res_types_sent["global"][response]/global_page_hits*100,round_amount)
        print("		"+response+":	"+str(res_global)+"	"+str(res_percent)+"%")
    print("	Global request types")
    for req_type in sorted(req_types_recv["global"]):
        res_global = int(req_types_recv["global"][req_type])
        if round_amount==0:
            res_percent = req_types_recv["global"][req_type]/global_page_hits*100
        else:
            res_percent = round(req_types_recv["global"][req_type]/global_page_hits*100,round_amount)
        print("		"+req_type+":	"+str(res_global)+"	"+str(res_percent)+"%")
    print("	Global request type to response stats:")
    for req_type in sorted(response_types_sent):
        for response in sorted(response_types_sent[req_type]):
            res_global = int(response_types_sent[req_type][response])
            if round_amount==0:
                res_percent = response_types_sent[req_type][response]/global_page_hits*100
            else:
                res_percent = round(response_types_sent[req_type][response]/global_page_hits*100,round_amount)
            print("		"+req_type+"("+response+"):	"+str(res_global)+"	"+str(res_percent)+"%")

if __name__=="__main__":
    main()
    
