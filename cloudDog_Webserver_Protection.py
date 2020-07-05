##################
#Author:Ennio Calderoni
###################
##Webserver_Protection
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

logging.basicConfig(filename = os.path.join('logs/', 'cloudDog_Webserver_Protection.log'), format='%(asctime)s %(message)s')

def waf(rule,richiesta,html_status_to_check,treshold,logStreamName,region,html_status_active,ipWhitelist):
        ip=richiesta.group(1)
        if not ipInCidr(ip,ipWhitelist):
            param=richiesta.group(2)
            html_status=int(richiesta.group(3))
            AlreadyDone=[]
            Attacker_Ips=[]
            if html_status_active:
                if html_status in html_status_to_check:  # farlo per stato rallenta troppo
                    status={
                    "ip":ip,
                    "html_status":html_status
                    }
                    if ip not in AlreadyDone:
                        Found_StatusCodes.append(status)
                        if Found_StatusCodes.count(status) == treshold:
                            with open('results/ips_results.log', 'a') as waf:
                                toPrint=region+"; "+logStreamName+"; "+ip+"; the ip triggered an "+str(html_status)+" html status more than "+str(treshold)+" times; html_status_to_check; medium; "+param+"\n"
                                waf.write(toPrint)
                            attack={"region":region, "logStreamName":logStreamName,"attacker_ip":ip,"attack":"the ip triggered an "+str(html_status)+" html status more than "+str(treshold)+" times"}
                            Attacks.append(attack)
                            AlreadyDone.append(ip)
                            #Attacker_Ips.append(ip)

            regole = compRegole.search(rule)
            if (regole):
                nome = regole.group(1)
                tipo = regole.group(2)
                regex= regole.group(3)
                risk = regole.group(4)
                candidato=True
                if candidato:
                    verdetto1=re.search(regex, urllib.parse.unquote_plus(param))
                    verdetto2=re.search(regex, param)
                    if (verdetto1 or verdetto2):
                        with open('results/ips_results.log', 'a') as waf:
                            toPrint=region+"; "+logStreamName+"; "+ip+"; "+nome+"; "+tipo+"; "+risk+"; "+param+"\n"
                            waf.write(toPrint)
                        attack={"region":region, "logStreamName":logStreamName, "attacker_ip":ip, "attack":nome}
                        Attacks.append(attack)
                        return True
                    else:
                        return False
        else:
            return False

def aggregated_Attacker_Detail():
    i=0
    Attacker_details=[]
    AlreadyDone=[]
    for a1 in Attacks:
        count=1
        DifferentAttacks=[]
        if a1["attacker_ip"] not in AlreadyDone:
            if i != (len(Attacks)-1):
                i=i+1
            for a2 in range(i,len(Attacks)):
                if a1["attacker_ip"]==Attacks[a2]["attacker_ip"]:
                    count=count+1
                    #DifferentAttacks.append(a1["attack"])
                    if Attacks[a2]["attack"] not in DifferentAttacks:
                        DifferentAttacks.append(Attacks[a2]["attack"])
            attacker={"ip":a1["attacker_ip"],"nAttacks":count,"differentAttacks":len(DifferentAttacks)}
            Attacker_details.append(attacker)
            AlreadyDone.append(a1["attacker_ip"])
    return Attacker_details


try:

    with PidFile(piddir='pids/',pidname='cloudDog_Webserver_Protection'):
        with open("configuration.yaml", "r") as conf:
            configuration = yaml.load(conf)

        active = configuration["apache_nginx_log"]["active"]
        if active:
            for regions_nacl in configuration["regions_nacl"]:
                region=regions_nacl["region"]
                nacl_id=regions_nacl["network_acl_id"]
                client = boto3.client('logs',region_name=region)
                log_group = configuration["apache_nginx_log"]["log_group"]
                time_window = configuration["apache_nginx_log"]["time_window"]
                ipWhitelist = configuration["apache_nginx_log"]["ipWhitelist"]
                if ipWhitelist is None:
                    ipWhitelist = []
                html_status_active = configuration["apache_nginx_log"]["html_status"]["active"]
                if html_status_active:
                    treshold = configuration["apache_nginx_log"]["html_status"]["treshold"]
                    html_status_to_check = configuration["apache_nginx_log"]["html_status"]["html_status_to_check"]
                else:
                    treshold=0
                    html_status_to_check =[]
                block = configuration["apache_nginx_log"]["block"]["active"]
                if block:
                    block_treshold_Total_Attacks = configuration["apache_nginx_log"]["block"]["treshold_Total_Attacks"]
                    block_treshold_Different_Attack = configuration["apache_nginx_log"]["block"]["treshold_Different_Attack"]
                    block_treshold_operator = configuration["apache_nginx_log"]["block"]["treshold_operator"]
                    block_dedicated_nacl_RuleNumber_min = configuration["apache_nginx_log"]["block"]["dedicated_nacl_RuleNumber_min"]
                    block_dedicated_nacl_RuleNumber_max = configuration["apache_nginx_log"]["block"]["dedicated_nacl_RuleNumber_max"]

                try:
                    time=int((datetime.today() - timedelta(minutes=time_window)).timestamp())*1000
                    response = client.filter_log_events(
                        logGroupName=log_group,
                        logStreamNamePrefix='i-',
                        startTime=time,
                        #endTime=int((datetime.today() - timedelta(minutes=1)).timestamp()),
                        #limit=10000,
                        )
                    #print (response)
                except Exception as e:
                    logging.warning("wrong configuration detected, check the configuartion.yaml")
                    print(e)
                    continue

                cloudDogRules = ["CloudDog_Rules/wazuh-webrules.txt"]
                Attackers_Ip=[]
                Found_StatusCodes=[]
                Attacks=[]
                AlreadyBlocked=[]
                if os.path.isfile("results/Attackers_Ip.log"):
                    with open("results/Attackers_Ip.log", 'r',errors='ignore') as file:
                        Attackers_Ip=file.read().splitlines()
                    file.closed

                for cdr in cloudDogRules:
                    with open(cdr, 'r',errors='ignore') as file:
                        rules=file.readlines()
                    file.closed
                    compRegole= re.compile("(.+?);;;(.+?);;;(.+?);;;(.+?)\n")
                    compRichiesta = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?\"(.*?) HTTP.+\s([0-9]{3})\s[0-9]{3}")

                    for log in response["events"]:
                        try:
                            richiesta=compRichiesta.search(log["message"])
                            if richiesta:
                                for rule in rules:

                                    try:
                                        a=waf(rule,richiesta,html_status_to_check,treshold,log["logStreamName"],region,html_status_active,ipWhitelist)
                                        if a:
                                            break
                                    except Exception as e:
                                        print(e)
                                        break
                            # if html_status_active:
                            #     html_status_attacks()


                        except Exception as e:
                            print(e)
                            break
                    if block:
                        Attacker_details=aggregated_Attacker_Detail()
                        if block_treshold_operator == "and":

                            for attacker in Attacker_details:
                                if attacker["nAttacks"] >= block_treshold_Total_Attacks and attacker["differentAttacks"]>= block_treshold_Different_Attack:
                                    blockIP=block_on_vpc(nacl_id,block_dedicated_nacl_RuleNumber_min,block_dedicated_nacl_RuleNumber_max,attacker["ip"],region,AlreadyBlocked)
                                    if blockIP:
                                        AlreadyBlocked.append(attacker["ip"])

                        else:
                            for attacker in Attacker_details:
                                if attacker["nAttacks"] >= block_treshold_Total_Attacks or attacker["differentAttacks"]>= block_treshold_Different_Attack:
                                    blockIP=block_on_vpc(nacl_id,block_dedicated_nacl_RuleNumber_min,block_dedicated_nacl_RuleNumber_max,attacker["ip"],region,AlreadyBlocked)
                                    if blockIP:
                                        AlreadyBlocked.append(attacker["ip"])
except Exception as e:
    logging.warning("service failed")
    print(e)
