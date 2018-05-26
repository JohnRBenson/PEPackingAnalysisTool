import sqlite3  #for db manipulation
import pefile   #for PE file manipulation, must install package (https://github.com/erocarrera/pefile)
import hashlib  #for sha-256 hash generation
import os       #for file/directory manipulation


class sampleFeatures:
    #database variables
    sqliteFile = ""
    exePath = ""
    c = ""
    conn = ""
    #holder variables
    IDHolderList = ""
    IDHolder = ""
    stringHolder = ""
    #sha variable
    sha256 = ""
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
    #pe imports
    peLibraryName = ""
    peFunctionName = ""
    peFunctionAddress = ""
    #pe exports
    peExportName = ""
    peExportAddress = ""



    def sha256Sum(self, fileName, blockSize=65536):
        hash = hashlib.sha256()
        with open(fileName, "rb") as f:
            for block in iter(lambda: f.read(blockSize), b""):
                hash.update(block)
        return hash.hexdigest()

    def dbInsert(self, c, table, row):
        #print("Inserting")
        cols = ', '.join('"{}"'.format(col) for col in row.keys())
        vals = ', '.join(':{}'.format(col) for col in row.keys())
        sql = 'INSERT INTO "{0}" ({1}) VALUES ({2})'.format(table, cols, vals)
        self.c.execute(sql, row)
        self.conn.commit()

    def getSampleFeatures(self):
        self.sha256 = self.sha256Sum(self.exePath)#get sha256 hash
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
        #save to sample table: sha256, signature, number of sections, address of entry
        self.dbInsert(self.c, 'sample', {
                'sha': self.sha256,
                'peSignature': self.peSignature,
                'peNumberOfSections': self.peNumberOfSections,
                'peAddressOfEntry': self.peEntryAddress})

        #get the id for the current sample
        self.c.execute('select id from sample where sha="' + self.sha256 + '"')
        self.IDHolderList = self.c.fetchall()
        self.IDHolder = str(self.IDHolderList[0])
        self.IDHolder = self.IDHolder.strip('(),')#remove other characters from the retrieved list value

        #pe section data
        for section in self.pe.sections:#loop through all sections
            try:
                self.stringHolder = section.Name.decode('utf-8')#name data is in utf-8 format
                self.peSectionName = self.stringHolder.replace('\x00', '')#remove extra zero hex values from name
            except:
                self.peSectionName = section.Name
            self.peSectionVirtualAddress = hex(section.VirtualAddress)#get VA of section
            self.peSectionVirtualSize = hex(section.Misc_VirtualSize)#get virtual size of section
            self.peSectionRawSize = hex(section.SizeOfRawData)#get size of raw data
            self.peSectionEntropy = section.get_entropy()#get entropy (0-8)

            #save to section table: current sample ID (for connecting sample table to section table), section name, VA, VS, Raw Size, section entropy
            self.dbInsert(self.c, 'section', {
                    'sampleID': self.IDHolder,
                    'name': self.peSectionName,
                    'virtualAddress': self.peSectionVirtualAddress,
                    'virtualSize': self.peSectionVirtualSize,
                    'rawSize': self.peSectionRawSize,
                    'entropy': self.peSectionEntropy})
        try:
            #import data
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                self.stringHolder = entry.dll.decode('utf-8')#name data is in utf-8 format
                self.peLibraryName = self.stringHolder.replace('\x00', '')#remove extra zero hex values from name

                for func in entry.imports:#loop through all imports
                    self.stringHolder = func.name.decode('utf-8')#name data is in utf-8 format
                    self.peFunctionName = self.stringHolder.replace('\x00', '')#remove extra zero hex values from name
                    self.peFunctionAddress = hex(func.address)#get address

                    #save to import table: current sample ID (for connecting sample table to section table), library name (dlls), function name, function address
                    self.dbInsert(self.c, 'import', {
                            'sampleID': self.IDHolder,
                            'libraryName': self.peLibraryName,
                            'functionName': self.peFunctionName,
                            'functionAddress': self.peFunctionAddress})
        except:
            print('No Import Data')
       
        #print(self.pe.dump_info())

        try:
            #export data
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:#loop through exports
                self.stringHolder = exp.name.decode('utf-8')#name data is in utf-8 format
                self.peExportName = self.stringHolder.replace('\x00', '')#remove extra zero hex values from name
                self.peExportAddress = hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address)#get export address

                #save to export table: current sample ID (for connecting sample table to section table), export name, export address
                self.dbInsert(self.c, 'export', {
                        'sampleID': self.IDHolder,
                        'name': self.peExportName,
                        'address': self.peExportAddress})
        except:
            print('No Export Data')
            
        


def main():
    startTime = datetime.now()
    path = os.getcwd()
    sqliteFile = path + "\\database.sqlite"
    samplesPath = path + '\\samples'

    #connect to DB
    conn = sqlite3.connect(sqliteFile)
    c = conn.cursor()
    c.execute('select sha from sample')
    '''
    if c.fetchone():#if the db has values in it, skip loading db
        NNet = neuralNet()#initialize neural network object
        #NNet.exePath = samplesPath + "\\" + fileName
        NNet.conn = conn#pass DB connection
        NNet.c = c
        NNet.loadInputNodes()#read data from DB into input array for NNet
        NNet.trainNNet()#run training with dataframe created
    else:
        for fileName in os.listdir(samplesPath):#loops through all samples in samples folder
            sampleObject = sampleFeatures()#make object
            sampleObject.exePath = samplesPath + "\\" + fileName#give samples folder
            sampleObject.conn = conn#pass DB connection
            sampleObject.c = c
            print("Reading File Attributes")
            sampleObject.getSampleFeatures()#run getSampleFeatures on current sample
        conn.commit()#commit to DB before next step
    '''

    for fileName in os.listdir(samplesPath):#loops through all samples in samples folder
        sampleObject = sampleFeatures()#make object
        sampleObject.exePath = samplesPath + "\\" + fileName#give samples folder
        sampleObject.conn = conn#pass DB connection
        sampleObject.c = c
        print('Non Threaded Reading ' + fileName + '...')
        sampleObject.getSampleFeatures()#run getSampleFeatures on current sample

    conn.commit()
    conn.close()
    timeElapsed = datetime.now() - startTime 
    print('Time elpased (hh:mm:ss.ms) {}'.format(timeElapsed))


if __name__ == '__main__':
    main()
    
