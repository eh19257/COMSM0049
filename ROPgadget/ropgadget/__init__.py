## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import ropgadget.args
import ropgadget.binary
import ropgadget.core
import ropgadget.gadgets
import ropgadget.loaders
import ropgadget.options
import ropgadget.rgutils
import ropgadget.ropchain
import ropgadget.updateAlert
import ropgadget.version


def main(execve, arguments, padding):
    import sys
    from   ropgadget.args import Args
    from   ropgadget.core import Core
    try:
        args = Args(arguments)
    except ValueError as e:
        print(e)
        sys.exit(-1)
    
    if (padding is None):
        padding = 44
    sys.exit(0 if Core(args.getArgs(), execve, padding).analyze() else 1)            ### MODIFIED
