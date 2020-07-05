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
from cloudDog_CommonFunctions import block_on_vpc
from cloudDog_CommonFunctions import ipInCidr
from pid import PidFile
logging.basicConfig(filename = os.path.join('logs/', 'cloudDog_SSH_Bruteforce_Privesc_Errors.log'), format='%(asctime)s %(message)s')

def correlator(logs,Blacklist,region,active_block,only_successeful,dedicated_nacl_RuleNumber_min,dedicated_nacl_RuleNumber_max,ipWhitelist):
    Checked=[]  #dictionary
    Bruteforced=[]
    SuccessfullBruteforce=[]
    Blacklist=Blacklist+Bruteforced
    failRegex="sshd\[[0-9]+\]:\sInvalid user.+?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|sshd\[[0-9]+\]:\sConnection closed by authenticating.+?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|sshd\[[0-9]+\]:\sFailed password for.+?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    failSudoRegex="sudo:\s+(\S+) : user NOT in sudoers ;.+; COMMAND=(.+)"
    i=0
    SuccessBlocked=[]
    for log in logs:
            relog=re.search(failRegex,log["message"])
            Success=re.search("Accepted.+?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",log["message"])
            failSudo=re.search(failSudoRegex,log["message"])
            nAttacks=0
            ip=""
            if relog:
                    if(relog.group(1)):
                        ip=relog.group(1)
                        if ipInCidr(ip,ipWhitelist):
                            continue
                    elif(relog.group(2)):
                        ip=relog.group(2)
                        if ipInCidr(ip,ipWhitelist):
                            continue
                    if(relog.group(3)):
                        ip=relog.group(3)
                        if ipInCidr(ip,ipWhitelist):
                            continue
                    if ip in Checked:
                             for a in range(i+1,len(logs)):
                                  relog2=re.search(failRegex,logs[a]["message"])
                                  if relog2:
                                      if(relog2.group(1)):
                                          ip2=relog2.group(1)
                                      elif(relog2.group(2)):
                                          ip2=relog2.group(2)
                                      if(relog2.group(3)):
                                          ip2=relog2.group(3)
                                      if ip2==ip:
                                            nAttacks=nAttacks+1
                                      if nAttacks == treshold:
                                            Bruteforced.append(ip)
                                            with open('results/SSH_Bruteforce.log', 'a') as bruteforce:
                                                toPrint=region+" ; "+log["logStreamName"]+" ; "+ip+"\n"
                                                bruteforce.write(toPrint)
                                            if ip not in Blacklist:
                                                Blacklist.append(ip)
                                                with open('tools/ssh_blacklist.txt', 'a') as blacklist:
                                                    toPrint=ip+"\n"
                                                    blacklist.write(toPrint)
                                                    if active_block and not only_successeful:
                                                        block_on_vpc(nacl_id,dedicated_nacl_RuleNumber_min,dedicated_nacl_RuleNumber_max,ip,region,[])
                                                        # with open('results/SSH_Bruteforce.log', 'a') as bruteforce:
                                                        #     toPrint=region+" ; this IP has been blocked for bruteforce attempt ; "+ip+"\n"
                                                        #     bruteforce.write(toPrint)
                                            break
                    else:
                         Checked.append(ip)
            elif Success:
                    ip=Success.group(1)
                    if ip in Blacklist:
                        #SuccessefullBruteforce.append(ip)
                        with open('results/SuccessfullBruteforce.log', 'a') as SuccessefullBruteforce:
                            toPrint=region+" ; "+log["logStreamName"]+" ; "+ip+"\n"
                            SuccessefullBruteforce.write(toPrint)
                        if ip not in SuccessBlocked:
                            block_on_vpc(nacl_id,dedicated_nacl_RuleNumber_min,dedicated_nacl_RuleNumber_max,ip,region,[])
                            SuccessBlocked.append(ip)
                            # with open('results/SSH_Bruteforce.log', 'a') as bruteforce:
                            #     toPrint=region+" ; this IP has been blocked cause after a bruteforce attempt it made a successeful login ; "+ip+"\n"
                            #     bruteforce.write(toPrint)

            elif failSudo:
                    user=failSudo.group(1)
                    command=failSudo.group(2)
                    with open('results/FailedSudo.log', 'a') as FailedSudoText:
                        toPrint=region+" ; "+log["logStreamName"]+" ; "+user+" ; sudo "+command+" ; Failed_Sudo"+"\n"
                        FailedSudoText.write(toPrint)

            i=i+1

try:
    with PidFile(piddir='pids/',pidname='cloudDog_SSH_Bruteforce_Privesc'):
        with open("configuration.yaml", "r") as conf:
            configuration = yaml.load(conf)

        active = configuration["linux_authorization_log"]["active"]
        if active:
            for regions_nacl in configuration["regions_nacl"]:
                region=regions_nacl["region"]
                nacl_id=regions_nacl["network_acl_id"]
                client = boto3.client('logs',region_name=region)
                log_group = configuration["linux_authorization_log"]["log_group"]
                time_window= configuration["linux_authorization_log"]["time_window"]
                treshold = configuration["linux_authorization_log"]["treshold"]
                ipWhitelist = configuration["linux_authorization_log"]["ipWhitelist"]
                if ipWhitelist is None:
                    ipWhitelist = []
                active_block = configuration["linux_authorization_log"]["block"]["active"]
                if active_block:
                    only_successeful =configuration["linux_authorization_log"]["block"]["only_successeful"]
                    dedicated_nacl_RuleNumber_min = configuration["linux_authorization_log"]["block"]["dedicated_nacl_RuleNumber_min"]
                    dedicated_nacl_RuleNumber_max = configuration["linux_authorization_log"]["block"]["dedicated_nacl_RuleNumber_max"]
                Blacklist=[]
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

                if os.path.exists('tools/ssh_blacklist.txt'):
                    with open('tools/ssh_blacklist.txt', 'r',errors='ignore') as file:
                                    Blacklist=Blacklist+file.read().splitlines()
                    file.closed

                correlator(response["events"],Blacklist,region,active_block,only_successeful,dedicated_nacl_RuleNumber_min,dedicated_nacl_RuleNumber_max,ipWhitelist)

except Exception as e:
    logging.warning("service failed")
    print (e)
