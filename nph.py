#!/usr/bin/env python
#
# Easily view HTTP Nmap scan results.
# Takes Nmap scan results from standard input and generates a browser command to open all HTTP results in a new tab.
# @tprime_
#

import xml.etree.ElementTree as ET
import argparse
import sys
import re

# Create global variables
hostnames = []
ip_addresses = []
open_ports = []

def output_firefox(hostnames, ip_addresses):
	print 'firefox', ' '.join(hostnames), ' '.join(ip_addresses)

def output_chrome(hostnames, ip_addresses):
	print 'chrome', ' '.join(hostnames), ' '.join(ip_addresses)
	
def output_iceweasel(hostnames, ip_addresses):
	print 'iceweasel', ' '.join(hostnames), ' '.join(ip_addresses)
	
def output_chromium(hostnames, ip_addresses):
	print 'chromium-browser', ' '.join(hostnames), ' '.join(ip_addresses)
	
def determine_protocol(port, hostname):
	if port == '80':
		hostname = 'http://' + hostname + ':80'
	elif port == '443':
		hostname = 'https://' + hostname + ':443'
	elif port == '8080':
		hostname = 'http://' + hostname + ':8080'
	elif port == '8443':
		hostname = 'https://' + hostname + ':8443'
	else:
		hostname = 'http://' + hostname + ':' + port
	return hostname

def grepable_results(ports):
	# Grab Nmap data from stdin
	for line in sys.stdin:
		for port in ports:
			m = re.search('((?:[0-9]{1,3}\.){3}[0-9]{1,3}.+?' + port + '/open)', line)
			if m:
				# If there's a hostname, extract it
				if "()" not in m.group(1):
					extr_hostname = re.search('(?:[0-9]{1,3}\.){3}[0-9]{1,3} \((.+?)\).+?' + port + '/open', m.group(1))
					hostnames.append(determine_protocol(port, extr_hostname.group(1)))
				# If there isn't a hostname, extract the IP address
				if "()" in m.group(1):
					extr_ip_address = re.search('((?:[0-9]{1,3}\.){3}[0-9]{1,3}).+?' + port + '/open', m.group(1))
					ip_addresses.append(determine_protocol(port, extr_ip_address.group(1)))

	return (hostnames, ip_addresses)

# This function has messy regex, but it works. 	
def normal_results(ports):
	data = sys.stdin.read()
	# Extract each full nmap result
	m = re.findall('(Nmap scan report for .+?\n\n)', data, re.DOTALL)
	for port in ports:
		for item in m:
			# Does this result have the port open?
			http_open = re.search('(Nmap scan (report) for.+?\n).*(?:' + port + '/tcp open.+$)', item, re.DOTALL)
			# Is there a "(" within the first line of the nmap result or not?
			if http_open:
				if "(" not in http_open.group(1):
					extr_ip_address = re.search('((?:[0-9]{1,3}\.){3}[0-9]{1,3})', http_open.group(1))
					ip_addresses.append(determine_protocol(port, extr_ip_address.group(1)))
				if "(" in http_open.group(1):
					extr_hostname = re.search('(?:for )(.*)(?: \()', http_open.group(1))
					hostnames.append(determine_protocol(port, extr_hostname.group(1)))
				
	return (hostnames, ip_addresses)
	
def xml_results(target_ports):
	data = sys.stdin.read()
	try:
		root = ET.fromstring(data)
		for target_port in target_ports:
			for host in root.findall('host'):
				ports = host.find('ports').findall('port')
				for port in ports:
					if port.find('state').get('state') == 'open' and port.get('portid') == target_port:
						if not host.find('hostnames').findall('hostname'):
							ip_addresses.append(determine_protocol(port.get('portid'),host.find('address').get('addr')))	
						else:
							hostnames.append(determine_protocol(port.get('portid'), host.find('hostnames').findall('hostname')[0].get('name')))
	except Exception:
		print "[!] Error reading XML"
	return (hostnames, ip_addresses)

def main(args):
	ports = args.ports.split(',')

	if args.input == 'n':
		hostnames, ip_addresses = normal_results(ports)
	elif args.input == 'x':
		hostnames, ip_addresses = xml_results(ports)
	else:
		hostnames, ip_addresses = grepable_results(ports)
		
	if args.browser == 'c':
		output_chrome(hostnames, ip_addresses)
	elif args.browser == 'i':
		output_iceweasel(hostnames, ip_addresses)
	elif args.browser == 'ch':
		output_chromium(hostnames, ip_addresses)
	else:
		output_firefox(hostnames, ip_addresses)
	
if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='Takes Nmap scan results from standard input and generates a browser command to open all HTTP results in a new tab.',
		usage='cat results.scan | nph.py [-h] [-v] [-i INPUT_FORMAT] [-b BROWSER] [-p PORTS]',
	)
	parser.add_argument('-v', '--version',
		action='version',
		version='nph.py version 0.4.0',
	)
	parser.add_argument('-i',
		dest='input',
		choices=['g', 'x', 'n'],
		default='g',
		help='format of Nmap results: ([g]repable, [x]ml, [n]ormal) (default: grepable)',
#		required=True,
	)
	parser.add_argument('-p',
		dest='ports',
		default='80,443',
		help='comma-seperated list of ports to include as HTTP results. (default:80,443)',
#		required=True,
	)
	parser.add_argument('-b',
		dest='browser',
		choices=['f', 'c', 'i', 'ch'],
		default='f',
		help='browser: ([f]irefox, [c]hrome, [i]ceweasel, [ch]romium) (default: firefox)',
#		required=True,
	)
	args = parser.parse_args()
	main(args)