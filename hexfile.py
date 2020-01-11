#!/usr/bin/env python3
"""
Hexdump Utility
===============
A command line hexdump utility.
See the module's `Github homepage <https://github.com/risapav/ihex_analyzer>`_
for details.
"""


class HexFile:
    """
    trieda spracuvajuca Hexfile
    """

    def __init__(self, filename):
        self.filename = filename


def main():
    hexfile = HexFile('pokus.hex')
    print (hexfile.filename)



main()