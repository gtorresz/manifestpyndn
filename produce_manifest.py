from __future__ import division 
import csv 
import sys 
import socket
from collections import defaultdict 
import glob
from pyndn.name import Name
from pyndn.face import Face
from manifest import Manifest
from data import Data

def main(filepath=None, maxSuccess=None):
    #da = Manifest(Name("hi/01"))
    #print(sys.getsizeof(da))

    #server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #server_socket.bind(("0.0.0.0", 6677))
    #server_socket.listen(5)
    while True:
       #client_socket, addr = server_socket.accept()
       with open('attacker2.csv', 'rb') as f:
          dat = []
          dat.append(f.read(8*1024))
          manifest = []
          count = 0
          seq = 0
          while dat:
             manifest.append((seq+count, "001"))
             #c = sys.getsizeof(manifest)
             count = count + 1
             if count == 10:
                man = Data(manifest)
                man.setName("prefix/data/"+str(seq))
                print(man.getName())
                #client_socket.send(bytes(man))
                while count > 0:
                   seq = seq + 1
                   da = Data(Name("prefix/data/"+str(seq)))
                   print(da.getName())
                   #client_socket.send(bytes(da))
                   count = count - 1
                seq = seq + 1
                manifest = []
                dat = []
             dat.append(f.read(8*1024))
             #client_socket.send(data)
       #client_socket.close()
    #print(da.getKeyValuePairs())

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
