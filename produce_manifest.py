from __future__ import division 
import csv 
import sys 
import socket
from collections import defaultdict 
import glob
from pyndn.name import Name
from pyndn.face import Face
from pyndn.util.blob import Blob
from manifest import Manifest
from data import Data
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pyndn.sha256_with_rsa_signature import Sha256WithRsaSignature
import json

def main(filepath=None, manifest_size=None, writepath=None):
       if filepath is None or manifest_size is None:# or writepath is None:
        sys.stderr.write("usage: python3 %s <file-path> <manifest size> <write-path>\n")
        return 1
       with open(filepath, 'rb') as f:
          dataArray = [] #for holding the generated data packets
          readdata = f.read(8*1024) #read first bit of data
          datapacket = Data(Name("prefix/data").appendSequenceNumber(1))
          datapacket.setContent(readdata) #add content from file
          #dataf = open(writepath + "-1.txt","wb")#need to update for packet
          #dataf.write(readdata)
          dataArray.append(datapacket)
          manifestData = {} #manifest dictionary 
          manifestStorage = [] #for storing manifest packets
          count = 0 #entries created 
          seq = 0 #current sequence number
          while readdata or count != 0: #go till no data is left and no manifest file is
                                        #waiting to be created
             if(readdata): #if there is data create digest and add digest to manifest
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(readdata)
                manifestData[(seq+count+1)]=(str(digest.finalize()))

             #c = sys.getsizeof(manifestData) #used to check size of manifest file
             count = count + 1 #keeps track of entries currently in manifest
             if count == int(manifest_size):#check if it is time to create a new manifest
                #manifestStorage.append(manifestData)
                s=json.dumps(manifestData).encode('utf-8') #set up dictionary so that it may
                                                           # be stored in manifest content

                manifest_packet = Manifest(Name("prefix/data/"+str(seq)))
                manifest_packet.setContent(s)
                manifestStorage.append(manifest_packet)
                #k = json.loads(Blob(manifest_packet.getContent()).toBytes().decode('utf-8'))
                #print(sys.getsizeof(Blob(s))) #see size of bytes 
                #print(manifestData) #check and compare original manifestData 
                                     #against k derived from manifest packet
                #print(k) 

                count = 0
                seq = seq + manifest_size + 1 #increase seq to account for next manifest
                manifestData = {} #reset the manifest table for new manifest
             readdata = f.read(8*1024) #read next bit of data
             if(readdata): #create datapackets as needed
                datapacket = Data(Name("prefix/data").appendSequenceNumber(seq+count+1))
                datapacket.setContent(readdata) #add content from file
                #dataf = open(writepath + "-"+str(seq+1+count)+".txt","wb") #need to update for packet
                #dataf.write(readdata)
                dataArray.append(datapacket)


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
