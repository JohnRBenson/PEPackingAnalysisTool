import pefile   #for PE file manipulation, must install package (https://github.com/erocarrera/pefile)
import os       #for file/directory manipulation
from elasticsearch import Elasticsearch #plugin to interact with elsaticsearch DB
#remember to start elasticsearch service in windows.  ToDo: add auto start service function?
import requests #for http methods
import json     #to work with json formats and objects
import sys      #for exit and arguments
from time import sleep  #for "wait" functionality
import getopt   #command line options
import hashlib  #for creating md5 hash
import base64, re   #required for parsing bonsai URL
from requests.auth import HTTPBasicAuth #ssl authentication
import PEAnalysisHeader

def main(argv):

    f = open('creds.txt', 'r')
    ESAddress = f.read()

    #check for elasticsearch server
    bonsai = ESAddress#os.environ['BONSAI_URL']
    auth = re.search('https\:\/\/(.*)\@', bonsai).group(1).split(':')
    host = bonsai.replace('https://%s:%s@' % (auth[0], auth[1]), '')

    # Connect to cluster over SSL using auth for best security:
    esHeader = [{
     'host': host,
     'port': 443,
     'use_ssl': True,
     'http_auth': (auth[0],auth[1])
    }]

    # Instantiate the new Elasticsearch connection:
    es = Elasticsearch(esHeader)
    host = 'https://' + host
    try:
        es.ping()
    except:
        print('Could not reach elasticsearch at' + host + 'quitting in 3 seconds...')
        sys.exit(2)
    
    creds = HTTPBasicAuth(auth[0],auth[1])

    path = os.getcwd()
    samplesPath = path + '\\samples'

    try:
        os.listdir(samplesPath)
    except:
        print('Samples folder could not be found, quitting in 3 seconds...')
        sleep(3)
        sys.exit(2)

    try:
        opts, args = getopt.getopt(argv,'ho:',['reset='])
    except getopt.GetoptError:
        print ('Try: PEPackingAnalysisTool.py -h')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('[-o reset] to delete the samples table')
            sys.exit(2)
        elif opt in ('-o','--reset'):
            choice = input('Are you sure you want to delete all sample data in database?  This CANNOT be undone. (Y/N): ')
            if choice == 'Y' or choice == 'y':
                res = requests.delete(host + '/samples', auth=creds)
                print(res.text)
                res = requests.put(host + '/samples', auth=creds, json = PEAnalysisHeader.mapping)
                print(res.text)
            else:
                print('Deletion request canceled')
                #sys.exit(2)

    #connect to local elasticsearch server using elasticsearch-py
    #es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
    
    payload = {
        "aggs" : {
        "maxID" : { "max" : { "field" : "ID" } }
        }
    }
    res = requests.get(host + '/samples/_search', auth=creds, json = payload)
    print(res.text)
    sampleIDCounter = res.json()['aggregations']['maxID']['value']
    
    #if there are samples in the DB, then increment to the next sample ID
    if sampleIDCounter:
        sampleIDCounter += 1
    else:
        sampleIDCounter=1

    for fileName in os.listdir(samplesPath):#loops through all samples in samples folder
        hash = hashlib.md5(open(samplesPath + "\\" + fileName,'rb').read()).hexdigest()#get hash of sample
        payload = {
        "query": {
                  "match": {
                    "md5": hash
                  }
             }
        }
        res = requests.get(host + '/samples/_search', auth=creds, json = payload)
        if (res.json()['hits']['total']) == 0:#if there are no matches to the current sample's hash then load sample
            sampleObject = PEAnalysisHeader.sampleFeatures()#make object
            sampleObject.es = es#pass ES connection variable
            sampleObject.sampleIDCounter = sampleIDCounter#pass ID counter for id field
            sampleIDCounter += 1
            sampleObject.exePath = samplesPath + "\\" + fileName#give full sample path
            sampleObject.fileName = fileName#pass the file name
            sampleObject.md5 = hash#pass the md5 hash
            print('Reading ' + fileName + '...')
            sampleObject.getSampleFeatures()#run getSampleFeatures on current sample
            del(sampleObject)
        else:
            print(fileName + ' already in database')
        
    
    payload = {
        "query": {
        "nested": {
          "path": "sectionData",
          "query": {
            "bool": {
              "must": [
                {
                  "match": {
                    "sectionData.sectionName": ".text"
                  }
                }
              ]
            }
          }
        }
      }
    }
    choice = input('Run a test query to return first filename with .text section (ensures nested loop is functioning)? (Y/N): ')
    if choice == 'Y' or choice == 'y':
        res = requests.get(host + '/samples/sample/_search', auth=creds, json = payload)
        print(res.json()['hits']['hits'][0]['_source']['fileName'])
    else:
        sys.exit(2)

if __name__ == '__main__':
    main(sys.argv[1:])
    
