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
import ast
import json

def main(filepath=None, manifest_size=None, writepath=None):
       if filepath is None or manifest_size is None:# or writepath is None:
        sys.stderr.write("usage: python3 %s <file-path> <manifest size> <write-path>\n")
        return 1
       with open(filepath, 'rb') as f:
          dataArray = [] #for holding the generated data
          readdata = f.read(8*1024) #read first bit of data
          #dataf = open(writepath + "-1.txt","wb")
          #dataf.write(readdata)
          dataArray.append(readdata)
          manifestData = {} #manifest dictionary 
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

                s=json.dumps(manifestData).encode('utf-8') #set up dictionary so that it may
                                                           # be stored in manifest content
                manifest_packet = Manifest(Name("prefix/data/"+str(seq)))
                manifest_packet.setContent(s)
                #k = json.loads(Blob(manifest_packet.getContent()).toBytes().decode('utf-8'))
                #print(sys.getsizeof(Blob(s))) #see size of bytes 
                #print(manifestData) #check and compare original manifestData 
                                     #against k derived from manifest packet
                #print(k) 
                while count > 0: # create data packets corresponding to the entries in 
                                 # the manifest
                  if(dataArray[10-count]!=0):
                     seq = seq + 1 #increase seq
                     datapacket = Data(Name("prefix/data/"+str(seq)))
                     datapacket.setContent(dataArray[10-count]) #add content from array
                     #readf = open(writepath+"-"+str(seq)+".txt", 'rb')
                     #datapacket.setContent(readf.read())
                     #print(datapacket.getContent())#to verify content
                  count = count - 1
                seq = seq + 1 #increase seq to account for next manifest
                manifestData = {} #reset the manifest table for new manifest
                dataArray = [] #reset data array
             readdata = f.read(8*1024) #read next bit of data
             if readdata: #add data to data array only if there is data to add
                #dataf = open(writepath + "-"+str(seq+1+count)+".txt","wb")
                #dataf.write(readdata)
                dataArray.append(readdata)
             else:
                dataArray.append(0)

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
