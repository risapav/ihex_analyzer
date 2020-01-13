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


ROWTYPE_DATA = 0x00  # Data container
ROWTYPE_EOF = 0x01  # End of file
ROWTYPE_EXT_SEG_ADDR = 0x02  # Extended Segment Address
ROWTYPE_START_SEG_ADDR = 0x03  # Start Segment Address
ROWTYPE_EXT_LIN_ADDR = 0x04  # Extended Linear Address
ROWTYPE_START_LIN_ADDR = 0x05   # Start Linear Address


class HexFile:
    """
    trieda spracuvajuca Hexfile
    """

    def __init__(self, filename):
        # nazov suboru vo formate intel hex
        self._filename = filename
        # nedolezite udaje z pohladu umistnenia dat v pamati
        self._CS = 0
        self._IP = 0
        self._EIP = 0
        # udaje dolezite pre vypocet umiestnenia v pamati
        self._ADDRESS = 0
        self._SBA = 0
        self._LBA = 0

        self._typ = ROWTYPE_DATA

    # spustenie analyzy intel hex suboru
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
                data = self.byteCnv(line[1:3])
                # 1[:] + 2[LL] + 4[AAAA] + 2[TT] + 2n[DATA] + 2[CC]
                dataend = 1 + 2 + 4 + 2 + 2*data + 2
                # print(line[0:dataend])
                # ------------------------------------------------------------
                # crc vypocitane zo zvysku riadku musi byt 0
                crc = self.calcChecksum(line[1:dataend])
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

    # nastavenie adresy umiestnenia dat
    # drlo - adresa Word
    def setAddress(self, drlo):
        # index
        dri = 0
        if self._typ == ROWTYPE_EXT_SEG_ADDR:  # Extended Segment Address
            self._ADDRESS = self._SBA * 0x10 + (drlo + dri) % 0xFFFF

        elif self._typ == ROWTYPE_EXT_LIN_ADDR:  # Extended Linear Address
            self._ADDRESS = (self._LBA * 0x10000 + drlo + dri) % 0xFFFFFFFF

        else:
            self._ADDRESS = drlo + dri

    # konverzia z textoveho stringu na cislo velkosti Byte
    # data - textovy retazec data 2 znaky
    def byteCnv(self, data):
        buffer = codecs.decode(data, "hex")
        return struct.unpack(">B", buffer[0:1])[0]

    # konverzia z textoveho stringu na cislo velkosti Word
    # data - textovy retazec data 4 znaky
    def wordCnv(self, data):
        buffer = codecs.decode(data, "hex")
        return struct.unpack(">H", buffer[0:2])[0]

    # konverzia z textoveho stringu na cislo velkosti DWord
    # data - textovy retazec data 8 znakov
    def dwordCnv(self, data):
        buffer = codecs.decode(data, "hex")
        return struct.unpack(">I", buffer[0:4])[0]

    # textový výpis do stdout
    # typ - typ zaznamu 0-5
    # length - dlzka datovej casti
    # addr - nacitana adresa (index)
    # data - textovy retazec data
    # txt - komentar
    def txtMessage(self, typ, length, addr, data, txt):
        print('{0:0{1}X}'.format(self._ADDRESS, 8),
              "typ:", '{0:0{1}X}'.format(typ, 2),
              "addr:", '{0:0{1}X}'.format(addr, 4),
              "len:", '{0:0{1}X}'.format(length, 2),
              "data:", data,
              " -> ", txt
              )

    # analyzovanie parsovaneho riadku
    # typ - typ zaznamu 0-5
    # length - dlzka datovej casti
    # addr - nacitana adresa (index)
    # data - textovy retazec data
    def analyzeLine(self, typ, length, addr, data):
        if typ == ROWTYPE_DATA:  # Data container 0x00
            self.setAddress(addr)
            self.txtMessage(typ, length, addr, data, " data ")

        elif typ == ROWTYPE_EOF:  # End of file 0x01
            # print("End of file")  # Should we check for garbage after this?
            self._typ = ROWTYPE_DATA
            self.setAddress(addr)
            self.txtMessage(typ, length, addr, data, "End of file")

        elif typ == ROWTYPE_EXT_SEG_ADDR:  # Extended Segment Address 0x02
            # SBA +  ([DRLO  +  DRI]  MOD  64K)
            self._typ = ROWTYPE_DATA
            self.setAddress(addr)
            self.txtMessage(typ, length, addr, data,
                            "Extended Segment Address")
            self._SBA = self.wordCnv(data)
            self._typ = ROWTYPE_EXT_SEG_ADDR

        elif typ == ROWTYPE_START_SEG_ADDR:  # Start Segment Address 0x03
            # CS:IP
            self._typ = ROWTYPE_DATA
            self.setAddress(addr)
            self.txtMessage(typ, length, addr,
                            data, "Start Segment Address")
            self._CS = self.wordCnv(data[0:2])
            self._IP = self.wordCnv(data[2:4])

        elif typ == ROWTYPE_EXT_LIN_ADDR:  # Extended Linear Address 0x04
            # (LBA + DRLO + DRI) MOD 4G
            self._typ = ROWTYPE_DATA
            self.setAddress(addr)
            self.txtMessage(typ, length, addr, data,
                            "Extended Linear Address")
            self._LBA = self.wordCnv(data)
            self._typ = ROWTYPE_EXT_LIN_ADDR

        elif typ == ROWTYPE_START_LIN_ADDR:  # Start Linear Address 0x05
            # EIP
            self._typ = ROWTYPE_DATA
            self.txtMessage(typ, length, addr,
                            data, "Start Linear Address")
            self._EIP = self.wordCnv(data[0:4])

        else:  # undefined record
            raise ValueError("Invalid type byte")

    # vypocet crc suctu
    # data - textovy retazec data
    def calcChecksum(self, data):
        crc = 0
        buffer = codecs.decode(data, "hex")
        # print(type(buffer), len(buffer), buffer, data)
        for byte in buffer:
            crc += byte
        return crc & 0xFF

    # parsovanie jedne nacitaneho riadku
    # cnt - cislo nacitaneho riadku
    # rawline - textovy string, jeden riadok zo suboru
    def parseLine(self, cnt, rawline):
        try:
            # dlzka dat v zazname
            length = self.byteCnv(rawline[0:2])
            # adresa umiestnenia
            addr = self.wordCnv(rawline[2:6])
            # typ zaznamu
            typ = self.byteCnv(rawline[6:8])
            # data zaznamu
            data = rawline[8:]
            return (typ, length, addr, data)
        except ValueError:
            raise ValueError("Invalid hex data")

        return (0x00, 0x00, 0x00, "\xFF\xFF")

# hlavna funkcia


def main():
    hexfile = HexFile('demo/ds30loader.X.production.hex')
    hexfile.doAnalyze()
    return 0


# spustenie programu
main()
