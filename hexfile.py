#!/usr/bin/env python3
"""
Hexdump Utility
===============
A command line hexdump utility.
See the module's `Github homepage <https://github.com/risapav/ihex_analyzer>`_
for details.
"""

import struct
import codecs


class HexFile:
    """
    trieda spracuvajuca Hexfile
    """

    def __init__(self, filename):
        self.filename = filename
        self.segbase = 0
        self.mode = 8
        self.setStart()

    def doAnalyze(self):
        with open(self.filename, 'r', encoding='utf-8') as fp:
            cnt = 1
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                # kazdy riadok sa musi zacinat znakom ':'
                if not line.startswith(':'):
                    raise ValueError(
                        "Invalid line start character (%r)" % line[0])
                    continue
                # crc vypocitane zo zvysku riadku musi byt 0
                crc = self.calcChecksum(line[1:])
                print("crc : ", crc)
                if crc != 0:
                    raise ValueError(
                        "Record checksum doesn't match on line %d" % cnt)
                    continue
                # teraz je riadok validny a moze zacat analyza
                dataend = len(line)
                typ, length, addr, data = self.parseLine(
                    cnt, line[1:dataend - 2])

                self.analyzeLine(typ, length, addr, data)
                cnt += 1

    def setMode(self, mode):
        self.mode = int(mode)

    def setSegbase(self, data):
        self.segbase = data
        print("set segBase: ", self.segbase)

    def setStart(self, start=None):
        self.start = start

    def byteCnv(self, data):
        buffer = codecs.decode(data, "hex")
        return struct.unpack(">B", buffer)[0]

    def wordCnv(self, data):
        buffer = codecs.decode(data, "hex")
        num = struct.unpack(">H", buffer[0:2])[0]
        # print("wordCnv : ", data, buffer, num)
        # print("wordCnv : ", type(data), type(buffer), type(num))
        return num

    def dwordCnv(self, data):
        buffer = codecs.decode(data, "hex")
        return struct.unpack(">I", buffer)[0]

    # print(riadok[:-1])
    def analyzeLine(self, typ, length, addr, data):
        buffer = codecs.decode(data[:], "hex")

        if typ == 0x00:  # Data container
            target_address = self.segbase + self.mode + addr
            print('{0:0{1}X}'.format(target_address, 8), "Data: ", data)

        elif typ == 0x01:  # End of file
            print("End of file")  # Should we check for garbage after this?

        elif typ == 0x02:  # Extended Segment Address
            self.setMode(16)
            num = self.wordCnv(data)
            self.setSegbase(num)
            print('{0:0{1}X}'.format(self.segbase, 8),
                  "Extended Segment Address")

        elif typ == 0x03:  # Start Segment Address
            self.setMode(16)
            cs = self.wordCnv(data[0:2])
            ip = self.wordCnv(data[2:4])
            self.setStart((cs, ip))
            print('{0:0{1}X}'.format(self.segbase, 8),
                  "Start Segment Address")

        elif typ == 0x04:  # Extended Linear Address
            self.setMode(32)
            num = self.wordCnv(data)
            self.setSegbase(num)
            print('{0:0{1}X}'.format(self.segbase, 8),
                  "Extended Linear Address")

        elif typ == 0x05:  # Start Linear Address
            self.setMode(32)
            num = self.wordCnv(data[0:4])
            print('{0:0{1}X}'.format(num, 8),  "Start Linear Address")

        else:  # undefined record
            raise ValueError("Invalid type byte")

    def calcChecksum(self, data):
        crc = 0
        buffer = codecs.decode(data, "hex")
        print(type(buffer), len(buffer), buffer, data)
        for byte in buffer:
            crc += byte & 0xFF
        return crc & 0xFF

    def parseLine(self, cnt, rawline):
        try:
            line = codecs.decode(rawline, "hex")
            print(cnt, rawline, line)
            length, addr, typ = struct.unpack_from(">BHB", line, offset=0)
            data = rawline[8:]
            print("typ: ", '{0:0{1}X}'.format(typ, 2),
                  "addr: ", '{0:0{1}X}'.format(addr, 4),
                  "len: ", '{0:0{1}X}'.format(length, 2),
                  "data: ", data)
            return (typ, length, addr, data)
        except ValueError:
            raise ValueError("Invalid hex data")

        return (0x00, 0x00, 0x00, "\xFF\xFF")


def main():
    hexfile = HexFile('2.hex')
    hexfile.doAnalyze()
    return 0


main()
