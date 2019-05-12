#!/usr/bin/env python3
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

import argparse
import csv
import json
import socket
import sys
import tempfile
import os
import timeit
import numpy

from pyndn import Blob, Data, Face, Name, DigestSha256Signature
import ndnabs

class Error(RuntimeError):
    pass

SHA256_DIGEST_SIZE = 32

class Experiment:

    _maxSegmentPayloadLength = 8192

    def __init__(self, filename, groupSize, nAttributes, absPath, keepData = False):

        self.attributes = [b'attribute%d' % i for i in range(1, nAttributes + 1)]
        self._setupAbs(absPath)
        self._readDataAndCreateManifests(filename, groupSize, keepData)

    def _setupAbs(self, absPath):

        # sys.stderr.write ("Using NDN-ABS authority, signer, and verifier database from %s\n" % absPath)
        self.db = ndnabs.PickleDb(absPath)

        self.signer = ndnabs.Signer(self.db)
        self.verifier = ndnabs.Verifier(self.db)

        try:
            info = self.signer.get_public_params_info()
            if info.getName().getPrefix(-2).toUri() != "/icn2019/test/authority":
                raise RuntimeError('NDN-ABS authority exists, but not setup for experiment. Use `ndnabs setup -f /icn2019/test/authority` to force-setup the authority')
        except:
            raise RuntimeError("Public parameters are not properly installed for the signer/verifier")

        for attr in self.attributes:
            if not attr in self.signer.get_attributes():
                raise RuntimeError("%s attribute missing. Generate attributes for the experiment using `ndnabs gen-secret %s | ndnabs install-secret`" % (str(attr, 'utf-8'), ' '.join([str(i, 'utf-8') for i in self.attributes])))

    def _createManifest(self, name, manifestBuffer, nManifests):
        manifest = Data(name)
        manifest.setContent(manifestBuffer[0:nManifests * SHA256_DIGEST_SIZE])
        return manifest

    def _readDataAndCreateManifests(self, filename, groupSize, keepData):
        if groupSize < 1:
            raise RuntimeError("Group size cannot be less than 1")

        self.allChunks = []    # for holding the generated data packets, including unsigned manifests
        self.allManifests = [] # for storing first unsigned manifest packets, which are then signed in-place
        self.rawDataCount = 0
        self.ndnChunkCount = 0

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
                self.rawDataCount = self.rawDataCount + len(chunkPayload)

                chunk = Data(Name("/icn2019/test/data").appendSequenceNumber(seqNo))
                seqNo = seqNo + 1
                chunk.setContent(chunkPayload)

                digestSignature = DigestSha256Signature()
                digestSignature.setSignature(Blob(bytearray(SHA256_DIGEST_SIZE))) # not real a valid signature, but ok for the experiment
                chunk.setSignature(digestSignature)

                if keepData:
                    self.allChunks.append(chunk)

                # only data chunks; manifest sizes counted separatedly, as they are signed
                self.ndnChunkCount = self.ndnChunkCount + chunk.wireEncode().size()

                # For storing data packet to a file
                # with open(writepath + "-1.txt", "wb") as dataf
                #     dataf.write(dpacket_bytes)

                implicitDigest = chunk.getFullName()[-1].getValue()

                offset = chunkNo * SHA256_DIGEST_SIZE
                digests[offset:offset + SHA256_DIGEST_SIZE] = implicitDigest.toBytes()[:]

                chunkNo = chunkNo + 1

                if chunkNo == groupSize:
                    manifest = self._createManifest(Name("/icn2019/test/data").appendSequenceNumber(seqNo), digests, groupSize) # full group
                    seqNo = seqNo + 1
                    self.allChunks.append(manifest)
                    self.allManifests.append(manifest)
                    chunkNo = 0
                    digests = allocateBufferForDigests()

            if chunkNo != 0:
                manifest = self._createManifest(Name("/icn2019/test/data").appendSequenceNumber(seqNo), digests, groupSize) # partial group
                self.allChunks.append(manifest)
                self.allManifests.append(manifest)

            self.nDataChunks = seqNo - len(self.allManifests) # number of data packets, excluding the manifests

    def signManifests(self):
        self.manifestCount = 0
        self.signatureCounts = []
        for manifest in self.allManifests:
            self.signer.sign(manifest, self.attributes)
            self.manifestCount = self.manifestCount + manifest.wireEncode().size()
            self.signatureCounts.append(manifest.getSignature().getSignature().size())

    def verifyManifests(self):
        for manifest in self.allManifests:
            self.signer.verify(manifest.wireEncode())

def main():
    parser = argparse.ArgumentParser(description = 'NDN-ABS experiment')
    parser.add_argument('file', help='''File to encode in chunks and sign''')
    parser.add_argument('--minGroupSize', type=int, default=1, help='''Min manifestt group size (default: 1)''')
    parser.add_argument('--maxGroupSize', type=int, default=10, help='''Max manifest group size (default: 10)''')
    parser.add_argument('--minAttributes', type=int, default=1, help='''Min number of attributes (default: 1)''')
    parser.add_argument('--maxAttributes', type=int, default=10, help='''Max number of attributes (default: 10)''')
    parser.add_argument('--keep-data', action='store_true', help='''Keep all generated chunks in memory''')
    parser.add_argument('--abs-path', default=os.path.expanduser('~/.ndn/ndnabs.db'), help='''Set path for security database (default: ~/.ndn/ndnabs.db)''')

    args = parser.parse_args()

    print ("GroupSize,NAttributes,SignTime,VerifyTime,RawDataSize,NdnDataSize,NManifests,NData,MinAbsSignatureSize,MaxAbsSignatureSize,AvgAbsSignatureSize,StdAbsSignatureSize")

    for groupSize in range(args.minGroupSize, args.maxGroupSize + 1):
        for nAttributes in range(args.minAttributes, args.maxAttributes + 1):
            experiment = Experiment(args.file, groupSize, nAttributes, args.abs_path, args.keep_data)
            # for i in experiment.allChunks:
            #     print ("name:", i.getName(), "size:", len(i.wireEncode().toBytes()), "contentSize:", i.getContent().size())
            # continue

            signTime = timeit.timeit(stmt='experiment.signManifests()', number=1, globals={**globals(), **locals()}) # sign all manifests 10 times
            verifyTime = timeit.timeit(stmt='experiment.verifyManifests()', number=10, globals={**globals(), **locals()}) # sign all manifests 10 times

            # this requires Python 3.6
            print (f"{groupSize},{nAttributes}" +
                   f",{signTime / experiment.manifestCount},{verifyTime / experiment.manifestCount}" +
                   f",{experiment.rawDataCount},{experiment.ndnChunkCount + experiment.manifestCount}" +
                   f",{len(experiment.allManifests)},{experiment.nDataChunks}"
                   f",{numpy.min(experiment.signatureCounts)},{numpy.max(experiment.signatureCounts)}" +
                   f",{numpy.mean(experiment.signatureCounts)},{numpy.std(experiment.signatureCounts)}")

if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        sys.stderr.write("ERROR: %s\n" % str(e))
