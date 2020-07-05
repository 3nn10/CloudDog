# CloudDog
The purpose of CloudDog is to improve detection and remediation capabilities of AWS. CloudDog doesn't substitute any AWS security tool or best practices, but it is a centralized HIPS using CloudWatch and VPC NACL.

Keywords: AWS, IPS, IDS, HIPS, HIDS, Cloud

# INDEX
  1) requirements for cloudDog's ec2
  2) Ec2 minimum Role
  3) Set the crontab
  4) send logs to CloudWatch from monitored EC2s (Cloud Watch Agent)
  5) send alerts to CloudWatch from CloudDog
  6) error logs

# 1) requirements for cloudDog's ec2
  - Linux (tested on Ubuntu 18.04)
  - EC2 instance type: it depends on how many events are generated, if the IP block is active you will need less resources.
  - CloudWatch agent
  - python version 3.x
	  - python modules:
		- boto3: pip3 install boto3
		- netaddr: pip3 install netaddr
		- pid: pip3 install pid

# 2) Ec2 minimum Role
  - create an ec2 iam role with the following permission policy to attach to the EC2 where CloudDog is Running
    - CloudWatchAgentServerPolicy (AWS managed policy)
    - CloudWatchLogsReadOnlyAccess (AWS managed policy)
    - CloudDog_NACL (Managed policy)

  below you can find the CloudDog_NACL:
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "ec2:DescribeNetworkAcls",
                  "ec2:CreateNetworkAclEntry",
                  "ec2:ReplaceNetworkAclEntry"
              ],
              "Resource": "*"
          }
      ]
  }

# 3) Set the crontab
  - first thing to do is to fill the configuration.yaml file with the right information
  - set the crontab according to the time_window setted in the configuration.yaml file
  - for web server protection:
    - set the scheduling according to apache_nginx_log:time_window, in this example every 5 minutes
      */5 * * * * cd /path_to_CloudWatch/ && /usr/bin/python3 cloudDog_Webserver_Protection.py
  - for SSH bruteforce and Privesc
    - set the scheduling according to linux_authorization_log:time_window, in this example every 10 minutes
      */5 * * * * cd /path_to_CloudWatch/ && /usr/bin/python3 cloudDog_SSH_Bruteforce_Privesc.py
  - for protection against lateral movement and exfiltration
      set the scheduling according to linux_bash_command_history:time_window, in this example every 10 minutes
      */10 * * * * cd /path_to_CloudWatch/ && /usr/bin/python3 cloudDog_Bash_Commands.py

# 4) send logs to CloudWatch from monitored EC2s (CloudWatch Agent)
  - install cloud watch agent on linux EC2 to monitor (for automation is advised system manager).
    - Link to the guide to install cloud watch agent: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/install-CloudWatch-Agent-commandline-fleet.html
    - logs to send are:
      - /var/log/auth.log
      - webserver access logs (for example /var/log/httpd-access.log)
      - ~/.bash_history
    - set the log stream name as Instance ID
    - note: to use properly the ~/.bash_history as intented from CloudDog it is necessary to insert PROMPT_COMMAND='history -a' in ~/.profile in all the monitored EC2
    - remember to rotate logs 

# 5) send alerts to CloudWatch from CloudDog
  - install cloud watch agent on linux EC2 to monitor (for automation is advised system manager).
    - Link to the guide to install cloud watch agent: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/install-CloudWatch-Agent-commandline-fleet.html
    - logs to send are:
      - /path_to_CloudWatch/results/SSH_Bruteforce.log (information about IP that performed SSH BruteForce Attacks)
      - /path_to_CloudWatch/results/Successfull_SSH_Bruteforce.log (information about IP that performed SSH BruteForce Attacks in the past and made a successeful login)
      - /path_to_CloudWatch/results/FailedSudo.log (information about commands performed without the right permissions)
      - /path_to_CloudWatch/results/WebServers_attacks.log (information about attacks perormed agains web servers)
      - /path_to_CloudWatch/results/Bash_Command.log (information about commands usually linked to attacks to not whitelisted domains/IPs)
  - remember to rotate logs
# 6) error logs
  - failure of scripts are logged in /path_to_CloudWatch/logs/
