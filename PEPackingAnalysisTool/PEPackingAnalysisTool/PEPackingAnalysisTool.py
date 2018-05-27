import pefile   #for PE file manipulation, must install package (https://github.com/erocarrera/pefile)
import os       #for file/directory manipulation
from elasticsearch import Elasticsearch #plugin to interact with elsaticsearch DB
import requests #for http methods
import sys      #for exit function
from time import sleep  #for "wait" functionality

'''
reference research:
    (1) http://www.sersc.org/journals/IJSIA/vol7_no5_2013/24.pdf (A Heuristics-based Static Analysis Approach for Detecting Packed PE Binaries)
'''
'''
index mapping:

PUT /samples
{
  "mappings": {
    "sample": {
      "properties": {
        "fileName":{"type":"text"},
        "numberOfSections":{"type":"integer"},
        "addressOfEntry":{"type":"text"},
        "sectionData":{"type": "nested",
          "properties": {
            "sectionName":{"type":"text"},
            "sectionEntropy":{"type":"float"}
          }
        },
        "containsCodeSection":{"type":"boolean"},
        "importData":{"type": "nested",
          "properties": {
            "libraryName":{"type":"text"},
            "functionName":{"type":"text"}
          }
        },
        "numberOfImports":{"type": "integer"},
        "exportData":{"type": "nested",
          "properties": {
            "exportName":{"type":"text"}
          }
        },
        "numberOfExports":{"type": "integer"}
      }
    }
  }
}
'''
class sampleFeatures:
    #elasticstack variables
    es = ""
    sampleIDCounter = ""
    features = {}
    #holder variables
    stringHolder = ""
    #file variables
    exePath = ""
    fileName = ""
    #pe variables
    pe = ""
    peSignature = ""
    peNumberOfSections = ""
    peEntryAddress = ""
    #pe sections
    peSectionName = ""
    peSectionVirtualAddress = ""
    peSectionVirtualSize = ""
    peSectionRawSize = ""
    peSectionEntropy = ""
    peSectionDict = {}
    peSectionArray = []
    #heuristics
    containsCodeSection = ""
    #pe imports
    peLibraryName = ""
    peFunctionName = ""
    peFunctionAddress = ""
    peNumberOfImports = ""
    peImportDict = {}
    peImportArray = []
    #pe exports
    peExportName = ""
    peExportAddress = ""
    peNumberOfExports = ""
    peExportDict = {}
    peExportArray = []


    def getSampleFeatures(self):
        try:
            self.pe = pefile.PE(self.exePath)
        except OSError as e:
            print(e)
        except pefile.PEFormatError as e:
            print("---PEFormatError: %s---" % e.value)
        try:
            self.peSignature = hex(self.pe.NT_HEADERS.Signature)#get signature
        except:
            print('No Signature')
        self.peNumberOfSections = self.pe.FILE_HEADER.NumberOfSections#get number of sections
        self.peEntryAddress = hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)#get address of entry

        #pe section data
        for section in self.pe.sections:#loop through all sections
            try:
                self.stringHolder = section.Name.decode('utf-8')#name data is in utf-8 format
                self.peSectionName = self.stringHolder.replace('\x00', '')#remove extra zero hex values from name
            except:
                self.peSectionName = section.Name
            '''
            self.peSectionVirtualAddress = hex(section.VirtualAddress)#get VA of section
            self.peSectionVirtualSize = hex(section.Misc_VirtualSize)#get virtual size of section
            self.peSectionRawSize = hex(section.SizeOfRawData)#get size of raw data
            '''
            self.peSectionEntropy = section.get_entropy()#get entropy (0-8)

            #check for the code section, this is a heuristic explained in (1)
            if self.peSectionName == 'CODE':
                self.containsCodeSection = True
            else:
                self.containsCodeSection = False


            #create dict and add that to an array
            self.peSectionDict = {'sectionName' : self.peSectionName,
                                  'sectionEntropy' : self.peSectionEntropy}
            self.peSectionArray.append(dict(self.peSectionDict))

        try:
            #import data
            self.peNumberOfImports = 0
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                self.stringHolder = entry.dll.decode('utf-8')#name data is in utf-8 format
                self.peLibraryName = self.stringHolder.replace('\x00', '')#remove extra zero hex values from name

                for func in entry.imports:#loop through all imports
                    self.stringHolder = func.name.decode('utf-8')#name data is in utf-8 format
                    self.peFunctionName = self.stringHolder.replace('\x00', '')#remove extra zero hex values from name
                    #self.peFunctionAddress = hex(func.address)#get address
                    self.peImportDict = {'libraryName' : self.peLibraryName,
                                         'functionName' : self.peFunctionName}
                    self.peImportArray.append(dict(self.peImportDict))
                    self.peNumberOfImports += 1
        except:
            print('No Import Data')
            self.peNumberOfImports = 0
       

        try:
            #export data
            self.peNumberOfExports = 0
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:#loop through exports
                self.stringHolder = exp.name.decode('utf-8')#name data is in utf-8 format
                self.peExportName = self.stringHolder.replace('\x00', '')#remove extra zero hex values from name
                #self.peExportAddress = hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address)#get export address
                self.peExportDict = {'exportName' : self.peExportName}
                self.peExportArray.append(dict(self.peExportDict))
                self.peNumberOfExports += 1

        except:
            print('No Export Data')
            self.peNumberOfExports = 0
        
        #build features for the body of ES document
        self.features = {
            'fileName' : self.fileName,
            'numberOfSections' : self.peNumberOfSections,
            'addressOfEntry' : self.peEntryAddress,
            }
        self.features.update({'sectionData' : self.peSectionArray})#sectionData is nested type, peSectionArray is an array of dictionary entries
        self.features.update({'containsCodeSection' : self.containsCodeSection})
        self.features.update({'importData' : self.peImportArray})
        self.features.update({'numberOfImports' : self.peNumberOfImports})
        self.features.update({'exportData' : self.peExportArray})
        self.features.update({'numberOfExports' : self.peNumberOfExports})
        #print (self.features)
        self.es.create(index='samples', doc_type='sample', id=self.sampleIDCounter, body=self.features)#create document with attributes pulled from sample
        
        


def main():
    path = os.getcwd()
    samplesPath = path + '\\samples'

    #check for elasticsearch server
    try:
        res = requests.get('http://localhost:9200')
    except:
        print('Could not reach elasticsearch at localhost:9200, quitting in 3 seconds...')
        sleep(3)
        sys.exit()

    try:
        os.listdir(samplesPath)
    except:
        print('Samples folder could not be found, quitting in 3 seconds...')
        sleep(3)
        sys.exit()

    #connect to local elasticsearch server using elasticsearch-py
    es = Elasticsearch([{'host': 'localhost', 'port': 9200}])

    sampleIDCounter=1

    for fileName in os.listdir(samplesPath):#loops through all samples in samples folder
        sampleObject = sampleFeatures()#make object
        sampleObject.es = es#pass ES connection variable
        sampleObject.sampleIDCounter = sampleIDCounter#pass ID counter for id field
        sampleIDCounter += 1
        sampleObject.exePath = samplesPath + "\\" + fileName#give full sample path
        sampleObject.fileName = fileName#pass the file name
        print('Reading ' + fileName + '...')
        sampleObject.getSampleFeatures()#run getSampleFeatures on current sample
    
    '''
    res = es.get(index='samples')
    print(res)
    '''

if __name__ == '__main__':
    main()
    
