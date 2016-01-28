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

def stat_gen(mode,round_amount,server_hits,server_response_types_sent,global_page_hits):
    for server in sorted(server_hits):
        server_amount = int(server_hits[server])
        if round_amount==0:
            server_percent = server_hits[server]/global_page_hits*100
        else:
            server_percent = round(server_hits[server]/global_page_hits*100,round_amount)
        print("\n"+mode+": "+server+":	"+str(server_amount)+"	"+str(server_percent)+"%")
        for response in sorted(server_response_types_sent[server]):
            res_amount = int(server_response_types_sent[server][response])
            if round_amount==0:
                res_percent = server_response_types_sent[server][response]/server_hits[server]*100
            else:
                res_percent = round(server_response_types_sent[server][response]/server_hits[server]*100,round_amount)
            print(response+":	"+str(res_amount)+"	"+str(res_percent)+"%")

def main():
    server_hits = {}
    domain_hits = {}
    page_hits = {}
    server_response_types_sent = {}
    domain_response_types_sent = {}
    response_types_sent = {}
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
                    
                    if not response in response_types_sent:
                        response_types_sent[response] = 1.0
                    else:
                        response_types_sent[response] += 1.0
                    
                    if not server_name in server_response_types_sent:
                        server_response_types_sent[server_name] = {}
                    if not response in server_response_types_sent[server_name]:
                        server_response_types_sent[server_name][response] = 1.0
                    else:
                        server_response_types_sent[server_name][response] += 1.0
                    
                    if not domain in domain_response_types_sent:
                        domain_response_types_sent[domain] = {}
                    if not response in domain_response_types_sent[domain]:
                        domain_response_types_sent[domain][response] = 1.0
                    else:
                        domain_response_types_sent[domain][response] += 1.0
    
    
    
    
    round_amount = 3
    stat_gen("Domain",round_amount,domain_hits,domain_response_types_sent,global_page_hits)
    stat_gen("Server",round_amount,server_hits,server_response_types_sent,global_page_hits)
    
    print("\nGlobal today hits:	"+str(int(global_page_hits)))
    for response in sorted(response_types_sent):
        res_global = int(response_types_sent[response])
        if round_amount==0:
            res_percent = response_types_sent[response]/global_page_hits*100
        else:
            res_percent = round(response_types_sent[response]/global_page_hits*100,round_amount)
        print(response+":	"+str(res_global)+"	"+str(res_percent)+"%")

if __name__=="__main__":
    main()
    
