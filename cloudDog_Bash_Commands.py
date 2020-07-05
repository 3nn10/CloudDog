##################
#Author:Ennio Calderoni
###################
##CloudDog_SSH_Privesc
## v1
#This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2.

import boto3
from datetime import datetime, timedelta
import time
import re
import os
import urllib.parse
import yaml
import logging
import socket
from netaddr import IPNetwork
from cloudDog_CommonFunctions import block_on_vpc_egress
from cloudDog_CommonFunctions import ipInCidr
from pid import PidFile
logging.basicConfig(filename = os.path.join('logs/', 'cloudDog_Bash_Commands_Errors.log'), format='%(asctime)s %(message)s')

try:
    with PidFile(piddir='pids/',pidname='cloudDog_Bash_Commands'):
        with open("configuration.yaml", "r") as conf:
            configuration = yaml.load(conf)
        AlreadyBlocked=[]
        active = configuration["linux_bash_command_history"]["active"]
        if active:
            for regions_nacl in configuration["regions_nacl"]:
                region=regions_nacl["region"]
                nacl_id=regions_nacl["network_acl_id"]
                client = boto3.client('logs',region_name=region)
                log_group = configuration["linux_bash_command_history"]["log_group"]
                #print(log_group)
                time_window = configuration["linux_bash_command_history"]["time_window"]
                egressDomainWhitelist = configuration["linux_bash_command_history"]["egressDomainWhitelist"]
                if egressDomainWhitelist is None:
                    egressDomainWhitelist = []
                ipWhitelist = configuration["linux_bash_command_history"]["ipWhitelist"]
                if ipWhitelist is None:
                    ipWhitelist = []
                active_block = configuration["linux_bash_command_history"]["block"]["active"]
                if active_block:
                    only_ip =configuration["linux_bash_command_history"]["block"]["only_ip"]
                    dedicated_nacl_RuleNumber_min = configuration["linux_bash_command_history"]["block"]["dedicated_nacl_RuleNumber_min"]
                    dedicated_nacl_RuleNumber_max = configuration["linux_bash_command_history"]["block"]["dedicated_nacl_RuleNumber_max"]
                try:
                    time=int((datetime.today() - timedelta(minutes=time_window)).timestamp())*1000
                    response = client.filter_log_events(
                        logGroupName=log_group,
                        logStreamNamePrefix='i-',
                        startTime=time,
                        limit=10000,
                        )
                except Exception as e:
                    logging.warning("wrong configuration detected, check the configuartion.yaml")
                    print(e)
                    continue

                dangerous_commands = re.compile("^\s*wget\s+.+|^\s*nc\s+.+|^\s*netcat\s+.+|^\s*curl\s+.+|^\s*lynx\s+.+|^\s*scp\s+.+|^\s*ssh\s+.+|^\s*ftp\s+.+|^\s*sftp\s+.+|^\s*telnet\s+.+|^\s*nmap\s+.+|^\s*rdesktop\s+.+|^\s*tsclient\s+.+|^\s*remmina\s+.+")
                ip_or_domain  = re.compile("((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\S+\.[\S\.]+)")
                for log in response["events"]:
                    try:
                        suspicious=dangerous_commands.search(log["message"])
                        if suspicious:
                            Whitelisted=False
                            domain_ip=ip_or_domain.search(suspicious.group(0))
                            if domain_ip:
                                if domain_ip.group(1):
                                    for domain in egressDomainWhitelist:
                                        if domain == domain_ip.group(1):
                                            Whitelisted=True
                                if domain_ip.group(2):
                                    if ipInCidr(domain_ip.group(2),ipWhitelist):
                                        Whitelisted=True
                                if not Whitelisted:
                                    with open('results/Bash_Command.log', 'a') as bash:
                                        toPrint=region+" ; "+log["logStreamName"]+" ; "+suspicious.group(0)+"\n"
                                        bash.write(toPrint)
                                    if active_block:
                                        if domain_ip.group(2):
                                            block_on_vpc_egress(nacl_id,dedicated_nacl_RuleNumber_min,dedicated_nacl_RuleNumber_max,domain_ip.group(2),region,AlreadyBlocked)
                                            AlreadyBlocked.append(domain_ip.group(2))
                                            # with open('results/Bash_Command.log', 'a') as bash:
                                            #     toPrint=region+" ; the following IP has been blocked ; "+domain_ip.group(2)+"\n"
                                            #     bash.write(toPrint)
                                        if domain_ip.group(1) and not domain_ip.group(2):
                                            resolved_ip=socket.gethostbyname_ex(domain_ip.group(1))
                                            ipx=resolved_ip[2]
                                            for ip in ipx:
                                                block_on_vpc_egress(nacl_id,dedicated_nacl_RuleNumber_min,dedicated_nacl_RuleNumber_max,ip,region,AlreadyBlocked)
                                                AlreadyBlocked.append(domain_ip.group(2))
                                                # with open('results/Bash_Command.log', 'a') as bash:
                                                #     toPrint=region+" ; the following IP has been blocked ; "+domain_ip.group(2)+"\n"
                                                #     bash.write(toPrint)
                    except Exception as e:
                        logging.warning("wrong configuration detected, check the configuartion.yaml")
                        print(e)
                        continue
except Exception as e:
    logging.warning("service failed")
    print (e)


#PROMPT_COMMAND='history -a' come aggiornare lhistory .bashrc
