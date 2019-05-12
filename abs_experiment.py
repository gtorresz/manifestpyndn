#!/usr/bin/env python3
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

import argparse
import csv
import json
import socket
import sys
import tempfile
import os

from pyndn import Blob, Data, Face, Name, DigestSha256Signature
import ndnabs

class Error(RuntimeError):
    pass

SHA256_DIGEST_SIZE = 32

class Experiment:

    _maxSegmentPayloadLength = 8192
    
    def __init__(self):
        parser = argparse.ArgumentParser(description = 'NDN-ABS experiment')
        parser.add_argument('file', help='''File to encode in chunks and sign''')
        parser.add_argument('groupSize', type=int, help='''Group size (the number of digests per manifest file)''')
        parser.add_argument('nAttributes', type=int, help='''Number of ABS attributes in the signature. Note that each experiment creates new authority, creates and uses the new set of attributes using `attributeN` (where N is 1, 2, 3, ... ) pattern''')
        parser.add_argument('--keep-data', action='store_true', help='''Keep all generated chunks in memory''')

        args = parser.parse_args()
        if args.nAttributes < 1 or args.nAttributes > 10:
            parser.print_help()
            raise Error("The number of ABS attributes must be between 1 and 10")

        self._setupAbs()
        self._generateAttributes(args.nAttributes)
        self._readDataAndCreateManifests(args.file, args.groupSize, args.keep_data)

    def _setupAbs(self):
        
        fd, tmpDbPath = tempfile.mkstemp()
        os.close(fd)
        os.remove(tmpDbPath)
        print ("Creating NDN-ABS authority and signer in %s" % tmpDbPath)
        self.db = ndnabs.PickleDb(tmpDbPath)
        
        self.authority = ndnabs.AttributeAuthority(self.db)
        self.signer = ndnabs.Signer(self.db)
        self.verifier = ndnabs.Verifier(self.db)

        self.authority.setup(Name("/icn2019/test/authority"))
        # databse for authority, verifier, and signer are shared, so no need to get and install public parameters

    def _generateAttributes(self, nAttrs):
        self.attributes = [b'attribute%d' % i for i in range(1, nAttrs + 1)]
        secret = self.authority.gen_attr_keys(self.attributes)
        self.signer.install_secret(secret)

    def _createManifest(self, name, manifestBuffer, nManifests):
        manifest = Data(name)
        manifest.setContent(manifestBuffer[0:nManifests * SHA256_DIGEST_SIZE])
        return manifest
        
    def _readDataAndCreateManifests(self, filename, groupSize, keepData):
        if groupSize < 1:
            raise RuntimeError("Group size cannot be less than 1")
        
        self.allChunks = []            # for holding the generated data packets, including unsigned manifests
        self.allUnsignedManifests = [] # for storing only unsigned manifest packets

        seqNo = 0   # sequence number of data packets
        chunkNo = 0 # number of the chunk in the group

        with open(filename, 'rb') as f:

            # prepare space to store all manifests of the group (last manifest will not use all the space)
            def allocateBufferForDigests():
                return bytearray(groupSize * SHA256_DIGEST_SIZE)

            digests = allocateBufferForDigests()
            
            while f.readable():
                chunkPayload = f.read(self._maxSegmentPayloadLength)
                if len(chunkPayload) == 0:
                    break

                chunk = Data(Name("/icn2019/test/data").appendSequenceNumber(seqNo))
                seqNo = seqNo + 1
                chunk.setContent(chunkPayload)

                digestSignature = DigestSha256Signature()
                digestSignature.setSignature(Blob(bytearray(SHA256_DIGEST_SIZE))) # not real a valid signature, but ok for the experiment
                chunk.setSignature(digestSignature)

                if keepData:
                    self.allChunks.append(chunk)

                # For storing data packet to a file
                # with open(writepath + "-1.txt", "wb") as dataf
                #     dataf.write(dpacket_bytes)
                    
                implicitDigest = chunk.getFullName()[-1].getValue()

                offset = chunkNo * SHA256_DIGEST_SIZE
                digests[offset:offset + SHA256_DIGEST_SIZE] = implicitDigest.toBytes()[:]

                if (seqNo % groupSize) == groupSize - 1:
                    manifest = self._createManifest(Name("/icn2019/test/data").appendSequenceNumber(seqNo), digests, groupSize) # full group
                    seqNo = seqNo + 1
                    self.allChunks.append(manifest)
                    self.allUnsignedManifests.append(manifest)
                    chunkNo = 0
                    digests = allocateBufferForDigests()

                chunkNo = chunkNo + 1

            if chunkNo != 0:
                manifest = self._createManifest(Name("/icn2019/test/data").appendSequenceNumber(seqNo), digests, groupSize) # partial group
                self.allChunks.append(manifest)
                self.allUnsignedManifests.append(manifest)

if __name__ == "__main__":
    try:
        experiment = Experiment()
        # for i in experiment.allChunks:
        #     print ("name:", i.getName(), "size:", len(i.wireEncode().toBytes()))
    except Error as e:
        print (e)
