#!/usr/bin/env python
# -*- coding:utf-8 -*- 
#
# @name   : Infoga - Email OSINT
# @url    : http://github.com/m4ll0k
# @author : Momo Outaadi (m4ll0k)

import sys
import json
from lib.colors import *
from recon.pwned import *
from recon.shodan import *

def plus(string):print("%s[+]%s %s"%(G,E,string))
def warn(string):print("%s[!]%s %s"%(R,E,string))
def test(string):print("%s[*]%s %s"%(B,E,string))
def info(string):print("%s[i]%s %s"%(Y,E,string))
def more(string):print(" %s|%s  %s"%(W,E,string))

class PPrint(object):
	'''PPrint class'''
	def __init__(self,ips,email,ver,pwned=False,report=None):
		self.ips = ips
		self.s_data = None
		self.email = email 
		self.verbose = ver
		self.spaces = lambda x: ' '*x
		self.separator = lambda x: '-'*x
		self.pwned = pwned
		self.file = None
		if report != None: 
			self.file = report
	
	def output(self):
		data = None
		# if verbose 1
		if self.verbose == 1:
			email = 'Email: %s (%s)'%(self.email,', '.join([x for x in self.ips]))
			plus(email)
			if self.file != None:
				self.file.write('[+] '+email+'\n')
			if self.pwned:
				 data = Pwned(self.email).search()
				 if data is None:
					 print('%s>> This email wasn\'t leaked'%self.spaces(1))
					 if self.file != None:
						 self.file.write('%s>> This email wasn\'t leaked\n'%self.spaces(1))
				 elif 'Breaches' in data:
				 	if data.get('Breaches') is None and 'Breaches' in data:
				 		data.pop('Breaches')
				 		data['Breaches'] = data.pop('Pastes')
				 	headers  = '%s>> This email was leaked... found %s results'%(self.spaces(1),len(data['Breaches']))
				 	if self.file != None:
				 		self.file.write(headers+'\n')
				 	print(headers)
			if self.file != None:
				self.file.writelines(self.separator(30)+'\n') 
		# if verbose 2
		elif self.verbose == 2:
			email = 'Email: %s (%s)'%(self.email,', '.join([x for x in self.ips]))
			plus(email)
			if self.file != None:
				self.file.write('[+] '+email+'\n')
			if self.ips != []:
				data = json.loads(Shodan(self.ips[0]).search())
				if data == {}:
					data = None
			if data != None:
				headers = ''
				if 'hostnames' in data:
					headers += '%s- Hostname: %s\n'%(self.spaces(1),data.get('hostnames')[0])
				if 'country_code' in data and 'country_name' in data:
					headers += '%s- Country: %s (%s)\n'%(self.spaces(1),data.get('country_code'),data.get('country_name'))
				if 'city' in data and 'region_code' in data:
					headers += '%s- City: %s (%s)'%(self.spaces(1),data.get('city'),data.get('region_code'))
				if self.file != None:
					self.file.write(headers+'\n')
				print(headers)
			else: 
				info('Not found information (on shodan) for this email, search this ip/ips on internet..')
				if self.file != None:
					self.file.write('%s- Not found information (on shodan) for this email, search this ip/ips on internet..')
			if self.pwned:
				headers = ''
				data = Pwned(self.email).search()
				if data is None:
					print('%s>> This email wasn\'t leaked'%self.spaces(1))
					if self.file != None:
						self.file.write('%s>> This email wasn\'t leaked\n'%(self.spaces(1)))
					headers += '%s\n'%self.separator(30)
				elif 'Breaches' in data:
					if data.get('Breaches') is None and 'Breaches' in data:
						data.pop('Breaches')
						data['Breaches'] = data.pop('Pastes')
					headers = '%s>> This email was leaked... found %s results...\n'%(self.spaces(1),len(data['Breaches']))
					for i in range(0,len(data['Breaches'])):
						if 'Title' in data['Breaches'][i]:
							headers += '%s> Leaked in: %s\n'%(self.spaces(2),data['Breaches'][i].get('Title'))
						if 'BreachDate' in data['Breaches'][i]:
							headers += '%s> Data Leaked: %s\n'%(self.spaces(2),data['Breaches'][i].get('BreachDate'))
						if 'IsVerified' in data['Breaches'][i]:
							headers += '%s> Verified: %s\n'%(self.spaces(2),data['Breaches'][i].get('IsVerified'))
						headers += '%s%s\n'%(self.spaces(2),self.separator(30))
					if self.file != None:
						self.file.write(headers)
					print(headers)
		# if verbose 3					
		elif self.verbose == 3:
			email = 'Email: %s (%s)'%(self.email,', '.join([x for x in self.ips]))
			plus(email)
			if self.file != None:
				self.file.write('[+] '+email+'\n')
			if self.ips != []:
				data = json.loads(Shodan(self.ips[0]).search())
				if data == {}:
					data = None
			if data != None:
				headers = ''
				if 'hostnames' in data:
					headers += '%s- Hostname: %s\n'%(self.spaces(1),data.get('hostnames')[0])
				if 'country_code' in data and 'country_name' in data:
					headers += '%s- Country: %s (%s)\n'%(self.spaces(1),data.get('country_code'),data.get('country_name'))
				if 'city' in data and 'region_code' in data:
					headers += '%s- City: %s (%s)\n'%(self.spaces(1),data.get('city'),data.get('region_code'))
				if 'asn' in data:
					headers += '%s- ASN: %s\n'%(self.spaces(1),data.get('asn'))
				if 'isp' in data:
					headers += '%s- ISP: %s\n'%(self.spaces(1),data.get('isp'))
				if 'latitude' in data and 'longitude' in data:
					headers += '%s- Map: https://www.google.com/maps/@%s,%s,10z (%s,%s)\n'%(
						self.spaces(1),data.get('latitude'),data.get('longitude'),
						 data.get('latitude'),data.get('longitude')
					)
				if 'org' in data:
					headers += '%s- Organization: %s\n'%(self.spaces(1),data.get('org'))
				if 'ports' in data:
					headers += '%s- Ports: %s'%(self.spaces(1),', '.join([str(x) for x in data.get('ports')]))

				if headers != '':
					if self.file != None:
						self.file.write(headers)
					print(headers)
			else: 
				info('Not found information (on shodan) for this email, search this ip/ips on internet..')
				if self.file != None:
					self.file.write('%s- Not found information (on shodan) for this email, search this ip/ips on internet..')
			if self.pwned:
				headers = ''
				data = Pwned(self.email).search()
				if data is None:
					print('%s>> This email wasn\'t leaked'%self.spaces(1))
					if self.file != None:
						self.file.write('%s>> This email wasn\'t leaked\n'%(self.spaces(1)))
				elif 'Breaches' in data:
					if data.get('Breaches') is None and 'Breaches' in data:
						data.pop('Breaches')
						data['Breaches'] = data.pop('Pastes')
					headers = '%s>> This email was leaked... found %s results...\n'%(self.spaces(1),len(data['Breaches']))
					for i in range(0,len(data['Breaches'])):
						if 'Title' in data['Breaches'][i]:
							headers += '%s> Leaked in: %s\n'%(self.spaces(2),data['Breaches'][i].get('Title'))
						if 'BreachDate' in data['Breaches'][i]:
							headers += '%s> Data Leaked: %s\n'%(self.spaces(2),data['Breaches'][i].get('BreachDate'))
						if 'IsVerified' in data['Breaches'][i]:
							headers += '%s> Verified: %s\n'%(self.spaces(2),data['Breaches'][i].get('IsVerified'))
						if 'Description' in data['Breaches'][i]:
							headers += '%s> Description: %s\n'%(self.spaces(2),data['Breaches'][i].get('Description'))
						headers += '%s%s\n'%(self.spaces(2),self.separator(30))

					if self.file != None:
						self.file.write('\n'+headers)
					print(headers)