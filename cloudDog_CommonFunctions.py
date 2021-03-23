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
                #print(str(ip)+"is in "+str(cidr))
                return True
        else:
            #print(str(ip)+"is not in "+str(cidr))
            return False

# def emailSender(testo,alert):
#
#
#     # Replace sender@example.com with your "From" address.
#     # This address must be verified with Amazon SES.
#     SENDER = ""
#
#     # Replace recipient@example.com with a "To" address. If your account
#     # is still in the sandbox, this address must be verified.
#     RECIPIENT = ""
#
#     # Specify a configuration set. If you do not want to use a configuration
#     # set, comment the following variable, and the
#     # ConfigurationSetName=CONFIGURATION_SET argument below.
#     #CONFIGURATION_SET = "ConfigSet"
# 
#     # If necessary, replace us-west-2 with the AWS Region you're using for Amazon SES.
#     AWS_REGION = ""
#
#     # The subject line for the email.
#     SUBJECT = alert
#
#     # The email body for recipients with non-HTML email clients.
#     BODY_TEXT = ("Amazon SES Test (Python)\r\n"
#                  "This email was sent with Amazon SES using the "
#                  "AWS SDK for Python (Boto)."
#                 )
#
#     # The HTML body of the email.
#     BODY_HTML = """<html>
#     <head></head>
#     <body>
#       <h1>ALERT</h1>
#       <p>"""+testo+""" </p>
#     </body>
#     </html>
#                 """
#
#     # The character encoding for the email.
#     CHARSET = "UTF-8"
#
#     # Create a new SES resource and specify a region.
#     client = boto3.client('ses',region_name=AWS_REGION)
#
#     # Try to send the email.
#     try:
#         #Provide the contents of the email.
#         response = client.send_email(
#             Destination={
#                 'ToAddresses': [
#                     RECIPIENT,
#                 ],
#             },
#             Message={
#                 'Body': {
#                     'Html': {
#                         'Charset': CHARSET,
#                         'Data': BODY_HTML,
#                     },
#                     'Text': {
#                         'Charset': CHARSET,
#                         'Data': BODY_TEXT,
#                     },
#                 },
#                 'Subject': {
#                     'Charset': CHARSET,
#                     'Data': SUBJECT,
#                 },
#             },
#             Source=SENDER,
#             # If you are not using a configuration set, comment or delete the
#             # following line
#             #ConfigurationSetName=CONFIGURATION_SET,
#         )
#     # Display an error if something goes wrong.
#     except ClientError as e:
#         print(e.response['Error']['Message'])
#     else:
#         print("Email sent! Message ID:"),
#         print(response['MessageId'])
