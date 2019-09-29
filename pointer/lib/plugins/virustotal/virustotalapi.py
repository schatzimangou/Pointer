#!/usr/bin/env python

# A virustotal.com Public API interactiong script
# Copyright (C) 2015, Tal Melamed <virustotal AT appsec.it>
# Contribute @ https://github.com/nu11p0inter/virustotal/
#
# VT SCAN EULA
# ------------
# By using the upload/ scan API, you consent to virustotal
# Terms of Service (https://www.virustotal.com/en/about/terms-of-service/)
# and allow VirusTotal to share this file with the security community. 
# See virustotal Privacy Policy (https://www.virustotal.com/en/about/privacy/) for details.

#this code has been taken from https://github.com/nu11p0inter/virustotal/blob/master/README.md and modified for this plugin
#cudos to this guy for the amazing work

import hashlib
import urllib
import urllib2
import json
import os
import logging

try:
    import requests
except:
    logging.error('Requests module is missing. Please install it by running: pip install requests.')

class vt:
    def __init__(self):
        self.api_key = ''
        self.api_url = 'https://www.virustotal.com/vtapi/v2/'
        self.errmsg = 'Something went wrong. Please try again later, or contact us.'

    def handleHTTPErrors(self, code):
        if code == 404:
            logging.error('[Response Code 404]' + self.errmsg)
            return 0
        elif code == 403:
            logging.error( '[Response Code 403] You do not have persmission for this api call. Please check your virustotal api key.')
            return 0
        elif code == 204:
            logging.error( '[Response Code 204] The request limit has been exceeded. Please wait for a few minutes and try again.')
            return 0
        else:
            logging.error( '[Response Code '+str(code)+']' +self.errmsg)
            return 0

    # Sending and scanning files
    def scanfile(self, file):
        url = self.api_url + "file/scan"
        files = {'file': open(file, 'rb')}
        headers = {"apikey": self.api_key}
        try:
            response = requests.post( url, files=files, data=headers )
            xjson = response.json()
            response_code = xjson ['response_code']
            verbose_msg = xjson ['verbose_msg']
            if response_code == 1:
                logging.debug(verbose_msg)
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErrors(e.code)
        except urllib2.URLError, e:
            logging.error('URLError: ' + str(e.reason))
        except Exception:
            import traceback
            logging.error('generic exception: ' + traceback.format_exc())           

    # Retrieving file scan reports
    def getfilereport(self, file):
        if os.path.isfile(file):
            f = open(file, 'rb')
            file = hashlib.sha256(f.read()).hexdigest()
            f.close()
        url = self.api_url + "file/report"
        parameters = {"resource": file, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                logging.debug(verbose_msg)
                return xjson
            else:
                logging.debug(verbose_msg)
                return xjson
                
        except urllib2.HTTPError, e:
            self.handleHTTPErrors(e.code)
        except urllib2.URLError, e:
            logging.error('URLError: ' + str(e.reason))
        except Exception:
            import traceback
            print response
            logging.error('generic exception: ' + traceback.format_exc())       
              
    #Rescanning already submitted files  
    def rescan(self, resource):
        if os.path.isfile(resource):
            f = open(resource, 'rb')
            resource = hashlib.sha256(f.read()).hexdigest()
            f.close()
        url = self.api_url + "file/rescan"
        parameters = {"resource":  resource, "apikey": self.api_key }
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                logging.debug(verbose_msg)
                return xjson
            else:
               logging.debug(verbose_msg)
                
        except urllib2.HTTPError, e:
            self.handleHTTPErrors(e.code)
        except urllib2.URLError, e:
            logging.error('URLError: ' + str(e.reason))
        except Exception:
            import traceback
            logging.error('generic exception: ' + traceback.format_exc())


    # set a new api-key
    def setkey(self, key):
        self.api_key = key
