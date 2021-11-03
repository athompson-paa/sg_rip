#!/usr/local/bin/python3
######################################################################################################################
# Usage:        ./sg_rip.py --profile paaclean  > /reports/paaclean.csv 
# Doc. Ref:	http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.describe_security_groups#
#                ____   ____   ____  _____ ____   ___  ____ _____ 
#               / ___| / ___| |  _ \| ____|  _ \ / _ \|  _ \_   _|
#               \___ \| |  _  | |_) |  _| | |_) | | | | |_) || |  
#                ___) | |_| | |  _ <| |___|  __/| |_| |  _ < | |  
#               |____/ \____| |_| \_\_____|_|    \___/|_| \_\|_|
######################################################################################################################
from __future__ import print_function

import json
import boto3
import boto3.session
import argparse



parser = argparse.ArgumentParser()
# Required aws profile 
parser.add_argument('--profile', type=str, required=True)
# Parse the argument
args = parser.parse_args()
#profile_selection = input ("You must select an aws profile :")
session = boto3.Session(profile_name=args.profile)

#description bug
print("%s,%s,%s,%s,%s,%s, %s" % ("Group-Name","Group-ID","In/Out","Protocol","Port","Source/Destination", "Description"))


for region in ["us-east-1","us-west-1", "us-west-2","us-east-2"]:

	ec2=session.client('ec2', region )
	sgs = ec2.describe_security_groups()["SecurityGroups"]
	for sg in sgs:
		group_name = sg['GroupName']
		group_id = sg['GroupId']
		print("%s,%s" % (group_name,group_id))
		# InBound permissions ##########################################
		inbound = sg['IpPermissions']
		print("%s,%s,%s" % ("","","Inbound"))
		for rule in inbound:
			if rule['IpProtocol'] == "-1":
				traffic_type="All Trafic"
				ip_protpcol="All"
				to_port="All"
				from_port="All" 
				port_range="All"
			else:
				ip_protpcol = rule['IpProtocol']
				from_port=rule['FromPort']
				to_port=rule['ToPort']
				if to_port == -1:
					to_port = "N/A"

			#Is source/target an IP v4?
			if len(rule['IpRanges']) > 0:
				for ip_range in rule['IpRanges']:
					cidr_block = ip_range['CidrIp']
				    #desc = ip_range['Description']

					print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, to_port, cidr_block))

			#Is source/target an IP v6?
			if len(rule['Ipv6Ranges']) > 0:
				for ip_range in rule['Ipv6Ranges']:
					cidr_block = ip_range['CidrIpv6']
#					desc = ip_range['Description']

					print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, to_port, cidr_block))

			#Is source/target a security group?
			if len(rule['UserIdGroupPairs']) > 0:
				for source in rule['UserIdGroupPairs']:
					from_source = source['GroupId']
					print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, to_port, from_source))

		# OutBound permissions ##########################################
		outbound = sg['IpPermissionsEgress']
		print("%s,%s,%s" % ("","","Outbound"))
		for rule in outbound:
			if rule['IpProtocol'] == "-1":
				traffic_type="All Trafic"
				ip_protpcol="All"
				to_port="All"
			else:
				ip_protpcol = rule['IpProtocol']
				from_port=rule['FromPort']
				to_port=rule['ToPort']
				#If ICMP, report "N/A" for port #
				if to_port == -1:
					to_port = "N/A"

			#Is source/target an IP v4?
			if len(rule['IpRanges']) > 0:
				for ip_range in rule['IpRanges']:
					cidr_block = ip_range['CidrIp']
					print("%s,%s,%s,%s,%s, %s" % ("", "", "", ip_protpcol, to_port, cidr_block))

			#Is source/target an IP v6?
			if len(rule['Ipv6Ranges']) > 0:
				for ip_range in rule['Ipv6Ranges']:
					cidr_block = ip_range['CidrIpv6']
					print("%s,%s,%s,%s,%s " % ("", "", "", ip_protpcol, to_port, cidr_block ))

			#Is source/target a security group?
			if len(rule['UserIdGroupPairs']) > 0:
				for source in rule['UserIdGroupPairs']:
					from_source = source['GroupId']
					print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, to_port, from_source))