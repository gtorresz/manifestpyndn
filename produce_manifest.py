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
from pyndn.encoding.wire_format import WireFormat

def main(filepath=None, manifest_size=None, writepath=None):
       if filepath is None or manifest_size is None:# or writepath is None:
        sys.stderr.write("usage: python3 %s <file-path> <manifest size> <write-path>\n")
        return 1

       #open file and create packets
       with open(filepath, 'rb') as f:

          """initialize all variables that will be needed, along with read the first bit 
          of data and creating the corresponding data packet"""
          dataArray = [] 	#for holding the generated data packets
          manifestData = {}    	#manifest dictionary 
          manifestStorage = [] 	#for storing manifest packets
          entries = 0         	#entries created 
          seq = 0             	#current sequence number
          wireformat = WireFormat.getDefaultWireFormat()

          #Read int the first bit of data and create data packet from data
          readdata = f.read(8*1024) 	
          datapacket = Data(Name("prefix/data").appendSequenceNumber(1))
          datapacket.setContent(readdata)
          dataArray.append(datapacket)
          
          #Create byte repersentation of packet, for digest and storing to file
          dpacket_bytes = datapacket.wireEncode(wireformat).toBytes()

          #For storing data packet to a file
          #dataf = open(writepath + "-1.txt","wb")
          #dataf.write(dpacket_bytes)

          """Create manifest and data packets until no data is left and no manifest 
          file is waiting to be created"""
          while readdata or entries != 0: 

             entries = entries + 1 #update number entries

             #if there is data create digest from packet and add digest to manifest
             if(readdata): 
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(dpacket_bytes)
                t = Blob(bytearray(digest.finalize())).toHex()
                manifestData[(seq+entries)]=t

                #For storing data packet to a file
                #dataf = open(writepath + "-"+str(seq+count)+".txt","wb")
                #dataf.write(dpacket_bytes)

             """check if it is time to create a new manifest, if so creat it and reset 
             manifest dictionary and entry count"""
             if entries == int(manifest_size):

                #set up dictionary so that it may be stored in manifest content
                s=json.dumps(manifestData).encode('utf-8') 

                #Creating and storing manifest packets
                manifest_packet = Manifest(Name("prefix/data").appendSequenceNumber(seq))
                manifest_packet.setContent(s)
                manifestStorage.append(manifest_packet)

                #for writing manifest packet to file   
                #mpacket_bytes = manifest_packet.wireEncode(wireformat).toBytes()             
                #dataf = open(writepath + "-1.txt","wb")
                #dataf.write(mpacket_bytes)


                """#following code is used for to insure data is being saved correctly
                k = json.loads(Blob(manifest_packet.getContent()).toBytes().decode('utf-8'))
                #print(sys.getsizeof(Blob(s))) #see size of bytes 
                #check and compare original manifestData against k derived from manifest packet
                print(manifestData) 
                print(k)"""

                entries = 0                        #reset number of entries
                seq = seq + int(manifest_size) + 1 #increase seq to account for next manifest
                manifestData = {}                  #reset the manifest table for new manifest

             #Read in next bit of data and create corresponding data packet if there is data
             readdata = f.read(8*1024) 
             if(readdata): 
                datapacket = Data(Name("prefix/data").appendSequenceNumber(seq+entries+1))
                datapacket.setContent(readdata) 
                dataArray.append(datapacket)
                dpacket_bytes = datapacket.wireEncode(wireformat).toBytes()

                #For storing data packet to a file
                #dataf = open(writepath + "-"+str(seq+count)+".txt","wb")
                #dataf.write(dpacket_bytes)


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
