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


ROWTYPE_DATA = 0x00
ROWTYPE_EOF = 0x01
ROWTYPE_EXT_SEG_ADDR = 0x02
ROWTYPE_START_SEG_ADDR = 0x03
ROWTYPE_EXT_LIN_ADDR = 0x04
ROWTYPE_START_LIN_ADDR = 0x05


class HexFile:
    """
    trieda spracuvajuca Hexfile
    """

    def __init__(self, filename):
        self._filename = filename
        self._CS = 0
        self._IP = 0
        self._EIP = 0

        self._ADDRESS = 0
        self._SBA = 0
        self._LBA = 0

        self._typ = ROWTYPE_DATA

    def doAnalyze(self):
        with open(self._filename, 'r', encoding='utf-8') as fp:
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
                # ------------------------------------------------------------
                # vypocet dlzky retazca ihex recordu
                buffer = codecs.decode(line[1:3], "hex")
                dataend = struct.unpack_from(">B", buffer, offset=0)[0]
                dataend *= 2
                dataend += 2 + 4 + 2 + 2 + 1
                # print(line[0:dataend])
                # ------------------------------------------------------------
                # crc vypocitane zo zvysku riadku musi byt 0
                crc = self.calcChecksum(line[1:dataend])
                # print("crc : ", crc)
                if crc != 0:
                    raise ValueError(
                        "Record checksum doesn't match on line %d" % cnt)
                    continue
                # ------------------------------------------------------------
                # teraz je riadok validny a moze zacat analyza
                # dataend = len(line)
                typ, length, addr, data = self.parseLine(
                    cnt, line[1:dataend - 2])

                self.analyzeLine(typ, length, addr, data)
                cnt += 1

    def setAddress(self, DRLO):
        if self._typ == ROWTYPE_EXT_SEG_ADDR:  # Extended Segment Address
            DRI = 0
            self._ADDRESS = self._SBA * 0x10 + (DRLO + DRI) % 0xFFFF

        elif self._typ == ROWTYPE_EXT_LIN_ADDR:  # Extended Linear Address
            DRI = 0
            self._ADDRESS = (self._LBA * 0x10000 + DRLO + DRI) % 0xFFFFFFFF

        else:
            DRI = 0
            self._ADDRESS = DRLO + DRI

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

    def txtMessage(self, typ, length, addr, data, txt):
        print('{0:0{1}X}'.format(self._ADDRESS, 8),
              "typ:", '{0:0{1}X}'.format(typ, 2),
              "addr:", '{0:0{1}X}'.format(addr, 4),
              "len:", '{0:0{1}X}'.format(length, 2),
              "data:", data,
              " -> ", txt
              )

    # print(riadok[:-1])
    def analyzeLine(self, typ, length, addr, data):
        buffer = codecs.decode(data[:], "hex")

        if typ == ROWTYPE_DATA:  # Data container
            self.setAddress(addr)
            self.txtMessage(typ, length, addr, data, " data ")

        elif typ == ROWTYPE_EOF:  # End of file
            # print("End of file")  # Should we check for garbage after this?
            self._typ = ROWTYPE_DATA
            self.setAddress(addr)
            self.txtMessage(typ, length, addr, data, "End of file")

        elif typ == ROWTYPE_EXT_SEG_ADDR:  # Extended Segment Address
            # SBA +  ([DRLO  +  DRI]  MOD  64K)
            self._typ = ROWTYPE_DATA
            self.setAddress(addr)
            self.txtMessage(typ, length, addr, data,
                            "Extended Segment Address")
            self._SBA = self.wordCnv(data)
            self._typ = ROWTYPE_EXT_SEG_ADDR

        elif typ == ROWTYPE_START_SEG_ADDR:  # Start Segment Address
            # CS:IP
            self._typ = ROWTYPE_DATA
            self.setAddress(addr)
            self.txtMessage(typ, length, addr,
                            data, "Start Segment Address")
            self._CS = self.wordCnv(data[0:2])
            self._IP = self.wordCnv(data[2:4])

        elif typ == ROWTYPE_EXT_LIN_ADDR:  # Extended Linear Address
            # (LBA + DRLO + DRI) MOD 4G
            self._typ = ROWTYPE_DATA
            self.setAddress(addr)
            self.txtMessage(typ, length, addr, data,
                            "Extended Linear Address")
            self._LBA = self.wordCnv(data)
            self._typ = ROWTYPE_EXT_LIN_ADDR

        elif typ == ROWTYPE_START_LIN_ADDR:  # Start Linear Address
            # EIP
            self._typ = ROWTYPE_DATA
            self.txtMessage(typ, length, addr,
                            data, "Start Linear Address")
            self._EIP = self.wordCnv(data[0:4])

        else:  # undefined record
            raise ValueError("Invalid type byte")

    def calcChecksum(self, data):
        crc = 0
        buffer = codecs.decode(data, "hex")
        # print(type(buffer), len(buffer), buffer, data)
        for byte in buffer:
            crc += byte
        return crc & 0xFF

    def parseLine(self, cnt, rawline):
        try:
            line = codecs.decode(rawline, "hex")
            # print(cnt, rawline, line)
            length, addr, typ = struct.unpack_from(">BHB", line, offset=0)
            data = rawline[8:]
            return (typ, length, addr, data)
        except ValueError:
            raise ValueError("Invalid hex data")

        return (0x00, 0x00, 0x00, "\xFF\xFF")


def main():
    hexfile = HexFile('demo/ds30loader.X.production.hex')
    hexfile.doAnalyze()
    return 0


main()
