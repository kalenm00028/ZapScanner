#Zed Attack Proxy Download: https://github.com/zaproxy/zaproxy/wiki/Downloads
#ZAP Python API Download: https://pypi.python.org/pypi/python-owasp-zap-v2.4

import time
from zapv2 import ZAPv2
import os
import subprocess
import datetime
import sys
import getopt

def main(argv):

	#Check API key
	api_key = ''
        with open('apiKey.txt', 'a+') as apiFile:
        	api_key = apiFile.read()

	#If API key not set
	if api_key == '':
		try:
			opts,args = getopt.getopt(argv,'hk:',["help","key="])
		except:
			print 'API Key must be set before use'
			print 'Key may be found in ZAP client under Tools>>Options>>API'
			print 'To set, use "python zapScanner.py -k <api key>"'
			sys.exit(2)
		if not opts:
			print 'API Key must be set before use'
			print 'Key may be found in ZAP client under Tools>>Options>>API'
                        print 'To set, use "python zapScanner.py -k <api key>"'
                        sys.exit(2)
		for opt,arg in opts:
	                if opt in ('-h','--help'):
				print 'API Key must be set before use'
				print 'Key may be found in ZAP client under Tools>>Options>>API'
	                        print 'To set, use "python zapScanner.py -k <api key>"'
			elif opt in ('-k','--key'):
				api_key = arg
		with open('apiKey.txt', 'w+') as apiFile:
			apiFile.write(api_key)
			apiFile.close()
			if os.stat('apiKey.txt').st_size > 0:
				print 'API Key successfully set'
		sys.exit()

	#Command line input rules
	target = ''
	format = ''
	ascan = False
	sscan = False

	try:
		opts,args = getopt.getopt(argv,'hasr:k:t:',["help","target=","report=","active=","spider=", "key="])
	except:
		print 'Usage: zapScanner.py -t <target> -r <report format>'
		print '-a [active scan] -s [spider scan]'
                print 'Report output options are html and xml'
		sys.exit(2)
	if not opts:
		print 'Usage: zapScanner.py -t <target> -r <report format>'
		print '-a [active scan] -s [spider scan]'
                print 'Report output options are html and xml'
		sys.exit(2)
	for opt,arg in opts:
		if opt in ('-h','--help'):
			print 'Usage: zapScaner.py -t <target> -r <report format>'
			print '-a [active scan] -s [spider scan]'
	                print 'Report output options are html and xml'
			print '-k to set new API key'
			sys.exit(2)
		elif opt in ('-t','--target'):
			target = arg
		elif opt in ('-r','--report'):
			format = arg
		elif opt in ('-a','--ascan'):
			ascan = True
		elif opt in ('-s','--sscan'):
			sscan = True
		elif opt in ('-k','--key'):
			open('apiKey.txt','w').close()
			with open('apiKey.txt', 'w+') as apiFile:
	                        apiFile.write(arg)
        	                apiFile.close()
                	        if os.stat('apiKey.txt').st_size > 0:
                        	        print 'API Key successfully set'
			sys.exit()


	if not (format == 'html' or format == 'xml'):
		print 'Report format usage error'
		print 'Report format reads ' + format
		print 'Usage: zapScanner.py -t <target> -r <report format>'
		print '-a [active scan] -s [spider scan]'
                print 'Report output options are html and xml'
		sys.exit(2)

	c = False
	if 'http://' in target:
		c = True
	elif 'https://' in target:
		c = True
	if c == False:
		print 'Website format usage error: must contain "http://" or "https://"'
	        print 'Usage: zapScanner.py -t <target> -r <report format>'
		print '-a [active scan] -s [spider scan]'
	        print 'Report output options are html and xml'
		sys.exit(2)
	#Yup, this bool thing is kinda weird ^
	#Python was not being friendly
	#End command line input rules

	#Start ZAP
	print 'Starting ZAP...'
	subprocess.Popen(['/usr/share/zaproxy/zap.sh','-daemon', '-port', '8080'],stdout=open(os.devnull,'w'))
	print 'Waiting for Zap to load, 10 seconds...'
	time.sleep(10)


	#ZAP instance created
	zap = ZAPv2()

	#If necessary, specify ports for ZAP to listen on for http and https
	#zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8443'})

	#ZAP accesses the target
	print 'Accessing target %s' % target
	zap.urlopen(target)
	time.sleep(2)

	if sscan==True:
		#Spider starts crawling website for urls
		print 'Spidering target %s' % target
		scanid = zap.spider.scan(target,apikey=api_key)

		#Spider progress
		#It hangs up around 40-43%
		time.sleep(2)
		spiderProgress = zap.spider.status(scanid)
		elapsedTime = 0
		print 'Spider progress %: ' + spiderProgress
		while (int(zap.spider.status(scanid)) < 100):
			if (zap.spider.status(scanid) > spiderProgress):
				spiderProgress = zap.spider.status(scanid)
				print 'Spider progress %: ' + spiderProgress
				print 'Time elapsed: ' + str(elapsedTime/60) + ':' + str(elapsedTime%60)
			elapsedTime += 1
			time.sleep(1)
		print 'Spider completed'
		elapsedTime -= 1
		print 'Total elapsed time: ' + str(elapsedTime/60) + ':' + str(elapsedTime%60)

		#Let passive scanner finish
		time.sleep(5)

	if ascan==True:
		#Begin active scanner
		#I haven't used this much, didn't want to be too disruptive in testing
		#Should work, however
		scanid = zap.ascan.scan(target,apikey=api_key)
		ascanProgress = zap.ascan.status(scanid)
		elapsedTime = 0
		print 'Scanning target %s' % target
		while (int(zap.ascan.status(scanid)) < 100):
			if (zap.spider.status(scanid) > ascanProgress):
				ascanProgress = zap.ascan.status(scanid)
				print 'Active Scan progress %: ' + ascanProgress
		                print 'Time elapsed: ' + str(elapsedTime/60) + ':' + str(elapsedTime%60)
			elapsedTime += 1
			time.sleep(1)
		print 'Scan completed'
		elapsedTime -= 1
		print 'Total elapsed time: ' + str(elapsedTime/60) + ':' + str(elapsedTime%60)

		#Let active scanner finish
		time.sleep(5)

	#To print results in command line:
	print 'Hosts: ' + ', '.join(zap.core.hosts)
	#for i in range(1,numAlerts):
	#	print zap.core.alert(i)["alert"]
	#	print zap.core.alert(i)["attack"]
	#	print zap.core.alert(i)["confidence"]
	#	print zap.core.alert(i)["cweid"]
	#	print zap.core.alert(i)["description"]
	#	print zap.core.alert(i)["evidence"]
	#	print zap.core.alert(i)["id"]
	#	print zap.core.alert(i)["messageId"]
	#	print zap.core.alert(i)["name"]
	#	print zap.core.alert(i)["other"]
	#	print zap.core.alert(i)["param"]
	#	print zap.core.alert(i)["pluginId"]
	#	print zap.core.alert(i)["reference"]
	#	print zap.core.alert(i)["risk"]
	#	print zap.core.alert(i)["solution"]
	#	print zap.core.alert(i)["url"]
	#	print zap.core.alert(i)["wascid"]

	#Generate Report File
	print 'Generating report...'
	t = datetime.datetime.now()
	if 'https://' in target:
		target = target[8:]
		target = target[:-4]
	else:
		target = target[7:]
		target = target[:-4]
	docName = str(t.year) + '-' + str(t.month) + '-' + str(t.day) + '_' + target + '_scan.' + format
	f = open(docName,'w')
	if format=='html':
		f.write(zap.core.htmlreport(api_key))
	elif format=='xml':
		f.write(zap.core.xmlreport(api_key))
	f.close()
	print 'Report ' + docName + ' generated!'

	#Close ZAP
	zap.core.shutdown()

if __name__=="__main__":
	main(sys.argv[1:])
