import pefile   #for PE file manipulation, must install package (https://github.com/erocarrera/pefile)
import os       #for file/directory manipulation
from elasticsearch import Elasticsearch #plugin to interact with elsaticsearch DB
#remember to start elasticsearch service in windows.  ToDo: add auto start service function?
import requests #for http methods
import json     #to work with json formats and objects
import sys      #for exit function
from time import sleep  #for "wait" functionality
import getopt   #command line options

'''
reference research:
    (1) http://www.sersc.org/journals/IJSIA/vol7_no5_2013/24.pdf (A Heuristics-based Static Analysis Approach for Detecting Packed PE Binaries)
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
    peImageBase = ""
    #pe sections
    peSectionName = ""
    peSectionVirtualAddress = ""
    peSectionVirtualSize = ""
    peSectionRawSize = ""
    peSectionIsEntryPoint = False
    peSectionNameDescription = ""
    peSectionRead = ""
    peSectionWrite = ""
    peSectionExecute = ""
    peSectionContainsCode = ""
    peSectionContainsInitData = ""
    peSectionEntropy = ""
    peSectionDict = {}
    peSectionArray = []
    #heuristics
    packerSectionName = False       #Sign of packing
    unknownSectionName = False      #Possible packing
    numberOfUnknownSections = 0     #Higher num of unknown section names, higher packing probability
    containsNamedCodeSection = False   #if no named code section, then sign of packing
    nonExecutableCodeSection = False   #Sign of packing
    executableDataSection = False      #Sign of packing
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

    #Section names know to be linked to packers
    #http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    packerSections = {
        '.aspack': 'Aspack packer',
        '.adata': 'Aspack packer/Armadillo packer',
        'ASPack': 'Aspack packer',
        '.ASPack': 'ASPAck Protector',
        '.boom': 'The Boomerang List Builder (config+exe xored with a single byte key 0x77)',
        '.ccg': 'CCG Packer (Chinese Packer)',
        '.charmve': 'Added by the PIN tool',
        'BitArts': 'Crunch 2.0 Packer',
        'DAStub': 'DAStub Dragon Armor protector',
        '!EPack': 'Epack packer',
        'FSG!': 'FSG packer (not a section name, but a good identifier)',
        '.gentee': 'Gentee installer',
        'kkrunchy': 'kkrunchy Packer',
        '.mackt': 'ImpRec-created section',
        '.MaskPE': 'MaskPE Packer',
        'MEW': 'MEW packer',
        '.MPRESS1': 'Mpress Packer',
        '.MPRESS2': 'Mpress Packer',
        '.neolite': 'Neolite Packer',
        '.neolit': 'Neolite Packer',
        '.nsp1': 'NsPack packer',
        '.nsp0': 'NsPack packer',
        '.nsp2': 'NsPack packer',
        'nsp1': 'NsPack packer',
        'nsp0': 'NsPack packer',
        'nsp2': 'NsPack packer',
        '.packed': 'RLPack Packer (first section)',
        'pebundle': 'PEBundle Packer',
        'PEBundle': 'PEBundle Packer',
        'PEC2TO': 'PECompact packer',
        'PECompact2': 'PECompact packer (not a section name, but a good identifier)',
        'PEC2': 'PECompact packer',
        'pec1': 'PECompact packer',
        'pec2': 'PECompact packer',
        'PEC2MO': 'PECompact packer',
        'PELOCKnt': 'PELock Protector',
        '.perplex': 'Perplex PE-Protector',
        'PESHiELD': 'PEShield Packer',
        '.petite': 'Petite Packer',
        '.pinclie': 'Added by the PIN tool',
        'ProCrypt': 'ProCrypt Packer',
        '.RLPack': 'RLPack Packer (second section)',
        '.rmnet': 'Ramnit virus marker',
        'RCryptor': 'RPCrypt Packer',
        '.RPCrypt': 'RPCrypt Packer',
        '.seau': 'SeauSFX Packer',
        '.sforce3': 'StarForce Protection',
        '.spack': 'Simple Pack (by bagie)',
        '.svkp': 'SVKP packer',
        'Themida': 'Themida Packer',
        '.Themida': 'Themida Packer',
        '.taz': 'Some version os PESpin',
        '.tsuarch': 'TSULoader',
        '.tsustub': 'TSULoader',
        '.packed': 'Unknown Packer',
        'PEPACK!!': 'Pepack',
        '.Upack': 'Upack packer',
        '.ByDwing': 'Upack Packer',
        'UPX0': 'UPX packer',
        'UPX1': 'UPX packer',
        'UPX2': 'UPX packer',
        'UPX!': 'UPX packer',
        '.UPX0': 'UPX Packer',
        '.UPX1': 'UPX Packer',
        '.UPX2': 'UPX Packer',
        '.vmp0': 'VMProtect packer',
        '.vmp1': 'VMProtect packer',
        '.vmp2': 'VMProtect packer',
        'VProtect': 'Vprotect Packer',
        '.winapi': 'Added by API Override tool',
        'WinLicen': 'WinLicense (Themida) Protector',
        '_winzip_': 'WinZip Self-Extractor',
        '.WWPACK': 'WWPACK Packer',
        '.yP': 'Y0da Protector',
        '.y0da': 'Y0da Protector'
        }

    #Commmon section names
    commonSections = {
        '.00cfg': 'Control Flow Guard (CFG) section (added by newer versions of Visual Studio)',
        '.apiset': 'a section present inside the apisetschema.dll',
        '.arch': 'Alpha-architecture section',
        '.autoload_text': 'cygwin/gcc; the Cygwin DLL uses a section to avoid copying certain data on fork.',
        '.bindat': 'Binary data (also used by one of the downware installers based on LUA)',
        '.bootdat': 'section that can be found inside Visual Studio files; contains palette entries',
        '.bss': 'Uninitialized Data Section',
        '.BSS': 'Uninitialized Data Section',
        '.buildid': 'gcc/cygwin; Contains debug information (if overlaps with debug directory)',
        '.CLR_UEF': '.CLR Unhandled Exception Handler section; see https://github.com/dotnet/coreclr/blob/master/src/vm/excep.h',
        '.code': 'Code Section',
        '.cormeta': '.CLR Metadata Section',
        '.complua': 'Binary data, most likely compiled LUA (also used by one of the downware installers based on LUA)',
        '.CRT': 'Initialized Data Section  (C RunTime)',
        '.cygwin_dll_common': "cygwin section containing flags representing Cygwin's capabilities; refer to cygwin.sc and wincap.cc inside Cygwin run-time",
        '.data': 'Data Section',
        '.DATA': 'Data Section',
        '.data1': 'Data Section',
        '.data2': 'Data Section',
        '.data3': 'Data Section',
        '.debug': 'Debug info Section',
        '.debug$F': 'Debug info Section (Visual C++ version <7.0)',
        '.debug$P': 'Debug info Section (Visual C++ debug information',
        '.debug$S': 'Debug info Section (Visual C++ debug information',
        '.debug$T': 'Debug info Section (Visual C++ debug information',
        '.drectve ': 'directive section (temporary, linker removes it after processing it; should not appear in a final PE image)',
        '.didat': 'Delay Import Section',
        '.didata': 'Delay Import Section',
        '.edata': 'Export Data Section',
        '.eh_fram': 'gcc/cygwin; Exception Handler Frame section',
        '.export': 'Alternative Export Data Section',
        '.fasm': 'FASM flat Section',
        '.flat': 'FASM flat Section',
        '.gfids': 'section added by new Visual Studio (14.0); purpose unknown',
        '.giats': 'section added by new Visual Studio (14.0); purpose unknown',
        '.gljmp': 'section added by new Visual Studio (14.0); purpose unknown',
        '.glue_7t': 'ARMv7 core glue functions (thumb mode)',
        '.glue_7': 'ARMv7 core glue functions (32-bit ARM mode)',
        '.idata': 'Initialized Data Section  (Borland)',
        '.idlsym': 'IDL Attributes (registered SEH)',
        '.impdata': 'Alternative Import data section',
        '.itext': 'Code Section  (Borland)',
        '.ndata': 'Nullsoft Installer section',
        '.orpc': 'Code section inside rpcrt4.dll',
        '.pdata': 'Exception Handling Functions Section (PDATA records)',
        '.rdata': 'Read-only initialized Data Section  (MS and Borland)',
        '.reloc': 'Relocations Section',
        '.rodata': 'Read-only Data Section',
        '.rsrc': 'Resource section',
        '.sbss': 'GP-relative Uninitialized Data Section',
        '.script': 'Section containing script',
        '.shared': 'Shared section',
        '.sdata': 'GP-relative Initialized Data Section',
        '.srdata': 'GP-relative Read-only Data Section',
        '.stab': 'Created by Haskell compiler (GHC)',
        '.stabstr': 'Created by Haskell compiler (GHC)',
        '.sxdata': 'Registered Exception Handlers Section',
        '.text': 'Code Section',
        '.text0': 'Alternative Code Section',
        '.text1': 'Alternative Code Section',
        '.text2': 'Alternative Code Section',
        '.text3': 'Alternative Code Section',
        '.textbss': 'Section used by incremental linking',
        '.tls': 'Thread Local Storage Section',
        '.tls$': 'Thread Local Storage Section',
        '.udata': 'Uninitialized Data Section',
        '.vsdata': 'GP-relative Initialized Data',
        '.xdata': 'Exception Information Section',
        '.wixburn': 'Wix section; see https://github.com/wixtoolset/wix3/blob/develop/src/burn/stub/StubSection.cpp',
        '.wpp_sf' : 'section that is most likely related to WPP (Windows software trace PreProcessor); not sure how it is used though; the code inside the section is just a bunch of routines that call FastWppTraceMessage that in turn calls EtwTraceMessage',
        'BSS': 'Uninitialized Data Section  (Borland)',
        'CODE': 'Code Section (Borland)',
        'DATA': 'Data Section (Borland)',
        'DGROUP': 'Legacy data group section',
        'edata': 'Export Data Section',
        'idata': 'Initialized Data Section  (C RunTime)',
        'INIT': 'INIT section (drivers)',
        'minATL': 'Section that can be found inside some ARM PE files; purpose unknown. exe files on Windows 10 also include this section as well; its purpose is unknown, but it contains references to ___pobjectentryfirst,___pobjectentrymid,___pobjectentrylast pointers used by Microsoft::WRL::Details::ModuleBase:: methods described e.g. here, and also referenced by .pdb symbols; so, looks like it is being used internally by Windows Runtime C++ Template Library (WRL) which is a successor of Active Template Library (ATL); further research needed',
        'PAGE': 'PAGE section (drivers)',
        'rdata': 'Read-only Data Section',
        'sdata': 'Initialized Data Section',
        'shared': 'Shared section',
        'Shared': 'Shared section',
        'testdata': 'section containing test data (can be found inside Visual Studio files)',
        'text': 'Alternative Code Section',
    }


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
        self.peImageBase = hex(self.pe.OPTIONAL_HEADER.ImageBase)#get Image Base

        #pe section data
        '''fix for issue where object data would be kept even after the object was deleted'''
        self.peSectionDict.clear()
        self.peSectionArray = []

        sectionPermissions = pefile.retrieve_flags(pefile.SECTION_CHARACTERISTICS, 'IMAGE_SCN_')#returns list of section flags from dict defined in pefile.py
        for section in self.pe.sections:#loop through all sections
            try:
                self.stringHolder = section.Name.decode('utf-8')#name data is in utf-8 format
                self.peSectionName = self.stringHolder.replace('\x00', '')#remove extra zero hex values from name
            except:
                self.peSectionName = section.Name

            self.peSectionVirtualAddress = hex(section.VirtualAddress)#get VA of section

            #check if section is at entry point, this is a heuristic explained in (1)
            if self.peSectionVirtualAddress == (self.peEntryAddress + self.peImageBase):
                self.peSectionIsEntryPoint = True

            self.peSectionVirtualSize = hex(section.Misc_VirtualSize)#get virtual size of section
            self.peSectionRawSize = hex(section.SizeOfRawData)#get size of raw data

            #Add descriptions for section names if known, check for common packer names and non-packer names. This is a heuristic explained in (1)
            if self.peSectionName in self.packerSections:
                self.peSectionNameDescription = self.packerSections[self.peSectionName]
                self.packerSectionName = True
            elif self.peSectionName in self.commonSections:
                self.peSectionNameDescription = self.commonSections[self.peSectionName]
            else:
                self.peSectionNameDescription = 'unknown'
                self.unknownSectionName = True
                self.numberOfUnknownSections += 1

            '''adds permissions to list for each section but not used as a feature in ES document, object flags are set accordingly and used as features'''
            permissions = []
            for permission in sorted(sectionPermissions):
                if getattr(section, permission[0]):
                    permissions.append(permission[0])
                    if (permission[0] == 'IMAGE_SCN_MEM_READ'):
                        self.peSectionRead = True
                    else:
                        self.peSectionRead = False
                    if (permission[0] == 'IMAGE_SCN_MEM_WRITE'):
                        self.peSectionWrite = True
                    else:
                        self.peSectionWrite = False
                    if (permission[0] == 'IMAGE_SCN_MEM_EXECUTE'):
                        self.peSectionExecute = True
                    else:
                        self.peSectionExecute = False
                    if (permission[0] == 'IMAGE_SCN_CNT_CODE'):
                        self.peSectionContainsCode = True
                    else:
                        self.peSectionContainsCode = False
                    if (permission[0] == 'IMAGE_SCN_CNT_INITIALIZED_DATA'):
                        self.peSectionContainsInitData = True
                    else:
                        self.peSectionContainsInitData = False

            '''If a section contains code but is not executable, this is a sign of packing.  This is a heuristic explained in (1)'''
            if (self.peSectionContainsCode == True & self.peSectionExecute == False):
                self.nonExecutableCodeSection = True
            elif self.nonExecutableCodeSection == False:
                self.nonExecutableCodeSection = False

            '''If a section contains initialized data and is executable, this is a sign of packing.  This is a heuristic explained in (1)'''
            if (self.peSectionContainsInitData == True & self.peSectionExecute == True):
                self.executableDataSection = True
            elif self.executableDataSection == False:
                self.executableDataSection = False

            self.peSectionEntropy = section.get_entropy()#get entropy (0-8)

            #check for the code section, this is a heuristic explained in (1)
            if self.peSectionName == 'CODE':
                self.containsNamedCodeSection = True
            elif self.containsNamedCodeSection == False:
                self.containsNamedCodeSection = False


            #create dict and add that to an array
            self.peSectionDict = {'sectionName' : self.peSectionName,
                                  'sectionVirtualAddress' : self.peSectionVirtualAddress,
                                  'sectionVirtualSize' : self.peSectionVirtualSize,
                                  'sectionRawSize' : self.peSectionRawSize,
                                  'sectionIsEntryPoint' : self.peSectionIsEntryPoint,
                                  'sectionDescription' : self.peSectionNameDescription,
                                  'sectionEntropy' : self.peSectionEntropy,
                                  'sectionRead' : self.peSectionRead,
                                  'sectionWrite' : self.peSectionWrite,
                                  'sectionExecute' : self.peSectionExecute,
                                  'sectionContainsCode' : self.peSectionContainsCode,
                                  'sectionContainsData' : self.peSectionContainsInitData}
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
            'imageBase' : self.peImageBase
            }
        self.features.update({'sectionData' : self.peSectionArray})#sectionData is a nested object, peSectionArray is an array of dictionary entries
        self.features.update({'packerSectionName' : self.packerSectionName})
        self.features.update({'unknownSectionName' : self.unknownSectionName})
        self.features.update({'containsNamedCodeSection' : self.containsNamedCodeSection})
        self.features.update({'nonExecutableCodeSection' : self.nonExecutableCodeSection})
        self.features.update({'executableDataSection' : self.executableDataSection})
        self.features.update({'importData' : self.peImportArray})#nested object
        self.features.update({'numberOfImports' : self.peNumberOfImports})
        self.features.update({'exportData' : self.peExportArray})#nested object
        self.features.update({'numberOfExports' : self.peNumberOfExports})
        #print (self.features)
        self.es.create(index='samples', doc_type='sample', id=self.sampleIDCounter, body=self.features)#create document with attributes pulled from sample
        
        

def main(argv):
    mapping = {
          "mappings": {
            "sample": {
              "properties": {
                "fileName":{"type":"text"},
                "numberOfSections":{"type":"integer"},
                "addressOfEntry":{"type":"text"},
                "imageBase":{"type":"text"},
                "sectionData":{"type": "nested",
                  "properties": {
                    "sectionName":{"type":"text"},
                    "sectionVirtualAddress":{"type":"text"},
                    "sectionVirtualSize":{"type":"text"},
                    "sectionRawSize":{"type":"text"},
                    "sectionIsEntryPoint":{"type":"boolean"},
                    "sectionDescription":{"type":"text"},
                    "sectionEntropy":{"type":"float"},
                    "sectionRead":{"type":"boolean"},
                    "sectionWrite":{"type":"boolean"},
                    "sectionExecute":{"type":"boolean"},
                    "sectionContainsCode":{"type":"boolean"},
                    "sectionContainsData":{"type":"boolean"}
                  }
                },
                "packerSectionName":{"type":"boolean"},
                "unknownSectionName":{"type":"boolean"},
                "containsNamedCodeSection":{"type":"boolean"},
                "containsNamedCodeSection":{"type":"boolean"},
                "nonExecutableCodeSection":{"type":"boolean"},
                "executableDataSection":{"type":"boolean"},
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
    try:
        opts, args = getopt.getopt(argv,'ho:',['reset='])
    except getopt.GetoptError:
        print ('Try: PEPackingAnalysisTool.py -h')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('-o reset to delete the samples table')
            sys.exit(2)
        elif opt in ('-o','--reset'):
            choice = input('Are you sure you want to delete all sample data in database?  This CANNOT be undone. (Y/N): ')
            if choice == 'Y' or choice == 'y':
                res = requests.delete('http://localhost:9200/samples')
                print(res.text)
                res = requests.put('http://localhost:9200/samples', json = mapping)
                print(res.text)
            else:
                print('Deletion request canceled')
                sys.exit(2)
    path = os.getcwd()
    samplesPath = path + '\\samples'

    #check for elasticsearch server
    try:
        res = requests.get('http://localhost:9200')
    except:
        print('Could not reach elasticsearch at localhost:9200, quitting in 3 seconds...')
        sleep(3)
        sys.exit(2)

    try:
        os.listdir(samplesPath)
    except:
        print('Samples folder could not be found, quitting in 3 seconds...')
        sleep(3)
        sys.exit(2)

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
        del(sampleObject)
    
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
        res = requests.get('http://localhost:9200/samples/sample/_search', json = payload)
        print(res.json()['hits']['hits'][0]['_source']['fileName'])
    else:
        sys.exit(2)

if __name__ == '__main__':
    main(sys.argv[1:])
    
