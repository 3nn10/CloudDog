##################
#Author:Ennio Calderoni
###################
##CloudDog_CommonFunctions
## v1
#This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2.
import random
import re
import boto3
from netaddr import IPNetwork
def block_on_vpc(Nacl_ids,dedicated_RuleNumber_min,dedicated_RuleNumber_max,ip_to_block,region,AlreadyBlocked):
    for nacl_id in Nacl_ids:
        if ip_to_block not in AlreadyBlocked:
             ec2 = boto3.resource('ec2',region_name=region)
             network_acl = ec2.NetworkAcl(nacl_id)
             client = boto3.client('ec2',region_name=region)
             usedRules=[]
             inRangeRules=[]
             ruleNumber=-1


             response =  client.describe_network_acls(
                     DryRun=False,
                     NetworkAclIds=[
                         nacl_id,
                     ],
                 )

             for nacl in response['NetworkAcls']:
                 for entry in nacl["Entries"]:
                     if entry['CidrBlock']==str(ip_to_block)+'/32':
                         return False
                     if not entry['Egress']:
                         usedRules.append(int(entry['RuleNumber']))
             for num in range(int(dedicated_RuleNumber_min),int(dedicated_RuleNumber_max+1)):
                 if num not in usedRules:
                     ruleNumber=num
                     break
             if ruleNumber==-1:
                 ruleNumber=random.randint(int(dedicated_RuleNumber_min), int(dedicated_RuleNumber_max))
                 response = client.replace_network_acl_entry(
                     CidrBlock=str(ip_to_block)+'/32',
                     DryRun=False,
                     Egress=False,
                     IcmpTypeCode={
                         'Code': -1,
                         'Type': -1
                     },
                     NetworkAclId=nacl_id,
                     PortRange={
                         'From': 0,
                         'To': 65535
                     },
                     Protocol='-1',
                     RuleAction='deny',
                     RuleNumber=ruleNumber
                 ) #NetworkAclIds
             else:
                 response = network_acl.create_entry(
                 CidrBlock=str(ip_to_block)+'/32',
                 DryRun=False,
                 Egress=False,
                 IcmpTypeCode={
                     'Code': -1,
                     'Type': -1
                 },
                 PortRange={
                     'From': 0,
                     'To': 65535
                 },
                 Protocol='-1',
                 RuleAction='deny',
                 RuleNumber=ruleNumber
                 )
             return True
        else:
            return False

def block_on_vpc_egress(Nacl_ids,dedicated_RuleNumber_min,dedicated_RuleNumber_max,ip_to_block,region,AlreadyBlocked):
    for nacl_id in Nacl_ids:
        if ip_to_block not in AlreadyBlocked:
             ec2 = boto3.resource('ec2',region_name=region)
             network_acl = ec2.NetworkAcl(nacl_id)
             client = boto3.client('ec2',region_name=region)
             usedRules=[]
             inRangeRules=[]
             ruleNumber=-1


             response =  client.describe_network_acls(
                     DryRun=False,
                     NetworkAclIds=[
                         nacl_id,
                     ],
                 )

             for nacl in response['NetworkAcls']:
                 for entry in nacl["Entries"]:
                     if entry['CidrBlock']==str(ip_to_block)+'/32':
                         return False
                     if entry['Egress']:
                         usedRules.append(int(entry['RuleNumber']))
             for num in range(int(dedicated_RuleNumber_min),int(dedicated_RuleNumber_max+1)):
                 if num not in usedRules:
                     ruleNumber=num
                     break
             if ruleNumber==-1:
                 ruleNumber=random.randint(int(dedicated_RuleNumber_min), int(dedicated_RuleNumber_max))
                 response = client.replace_network_acl_entry(
                     CidrBlock=str(ip_to_block)+'/32',
                     DryRun=False,
                     Egress=True,
                     IcmpTypeCode={
                         'Code': -1,
                         'Type': -1
                     },
                     NetworkAclId=nacl_id,
                     PortRange={
                         'From': 0,
                         'To': 65535
                     },
                     Protocol='-1',
                     RuleAction='deny',
                     RuleNumber=ruleNumber
                 ) #NetworkAclIds
             else:
                 response = network_acl.create_entry(
                 CidrBlock=str(ip_to_block)+'/32',
                 DryRun=False,
                 Egress=True,
                 IcmpTypeCode={
                     'Code': -1,
                     'Type': -1
                 },
                 PortRange={
                     'From': 0,
                     'To': 65535
                 },
                 Protocol='-1',
                 RuleAction='deny',
                 RuleNumber=ruleNumber
                 )
             return True
        else:
            return False

def IPcheck(ip):

    regex = "^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)"
    if(re.search(regex, ip)):
        return True
    else:
        return False

def ipInCidr(ip,cidr):
    if IPcheck(ip):
        for c in cidr:
            if ip in IPNetwork(c):
                return True
        else:
            return False
