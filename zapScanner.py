#Zed Attack Proxy Download: https://github.com/zaproxy/zaproxy/wiki/Downloads
#ZAP Python API Download: https://pypi.python.org/pypi/python-owasp-zap-v2.4

import time
from zapv2 import ZAPv2
import os
import subprocess
import datetime
import sys
import getopt


def apiCheck(argv):

	global api_key

	apiText = 'API Key must be set before use\nKey may be found in ZAP client under Tools>>Options>>API\nTo set, use "python zapScanner.py -k <api key>"'

	#Check API key
	with open('apiKey.txt', 'a+') as apiFile:
		api_key = apiFile.read()

	#If API key not set
	if api_key == '':
		try:
			opts,args = getopt.getopt(argv,'hk:',["help","key="])
		except:
			print apiText
			sys.exit(2)
		if not opts:
			print apiText
			sys.exit(2)
		for opt,arg in opts:
			if opt in ('-h','--help'):
				print apiText
			elif opt in ('-k','--key'):
				api_key = arg
		with open('apiKey.txt', 'w+') as apiFile:
			apiFile.write(api_key)
			apiFile.close()
			if os.stat('apiKey.txt').st_size > 0:
				print 'API Key successfully set'
		sys.exit()


def runArgs(argv):

	global target
        global format
        global ascan
        ascan = False
        global sscan
        sscan = False

	useText = 'Usage: zapScanner.py -t <target> -r <report format>\n-a [active scan] -s [spider scan]\nReport output options are html and xml'
	#Command line input rules
	try:
		opts,args = getopt.getopt(argv,'hasr:k:t:',["help","target=","report=","active=","spider=", "key="])
	except:
		print useText
		sys.exit(2)
	if not opts:
		print useText
		sys.exit(2)
	for opt,arg in opts:
		if opt in ('-h','--help'):
			print useText
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
		print useText
		sys.exit(2)

	c = False
	if 'http://' in target:
		c = True
	elif 'https://' in target:
		c = True
	if c == False:
		print 'Website format usage error: must contain "http://" or "https://"'
		print useText
		sys.exit(2)
	#Yup, this bool thing is kinda weird ^
	#Python was not being friendly
	#End command line input rules

def runZap():

	#Start ZAP
	print 'Starting ZAP...'
	subprocess.Popen(['/usr/share/zaproxy/zap.sh','-daemon', '-port', '8080'],stdout=open(os.devnull,'w'))
	print 'Waiting for Zap to load, 10 seconds...'
	time.sleep(10)

	#ZAP instance created
	global zap
	zap = ZAPv2()

	#If necessary, specify ports for ZAP to listen on for http and https
	#zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8443'})

	#ZAP accesses the target
	print 'Accessing target %s' % target
	zap.urlopen(target)
	time.sleep(2)

	if sscan==True:
		spiderScan()

	if ascan==True:
		activeScan()

def activeScan():
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


def spiderScan():
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

def generateReport(target):
	target = target
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


def main(argv):
	apiCheck(argv)
	runArgs(argv)
	runZap()
	generateReport(target)

	#Close ZAP
	zap.core.shutdown()

if __name__=="__main__":
	main(sys.argv[1:])
