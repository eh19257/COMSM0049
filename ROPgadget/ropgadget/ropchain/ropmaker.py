## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-13
##
##  http://shell-storm.org
##  http://twitter.com/JonathanSalwan
##

from capstone import *

from ropgadget.ropchain.arch.ropmakerx64 import *
from ropgadget.ropchain.arch.ropmakerx86 import *


class ROPMaker(object):
    def __init__(self, binary, gadgets, padding, offset, execve):
        self.__binary  = binary
        self.__gadgets = gadgets
        self.__offset  = offset
        self.__execve = self.__preProcessArgs(execve)       ### ADDED
        self.__padding = padding                            ### ADDED

        self.__handlerArch()


    def __handlerArch(self):

        if (
            self.__binary.getArch() == CS_ARCH_X86
            and self.__binary.getArchMode() == CS_MODE_32
            and self.__binary.getFormat() == "ELF"
        ):
            ROPMakerX86(self.__binary, self.__gadgets, self.__padding, self.__execve, self.__offset)

        elif (
            self.__binary.getArch() == CS_ARCH_X86
            and self.__binary.getArchMode() == CS_MODE_64
            and self.__binary.getFormat() == "ELF"
        ):
            ROPMakerX64(self.__binary, self.__gadgets, self.__offset)

        else:
            print("\n[Error] ROPMaker.__handlerArch - Arch not supported yet for the rop chain generation")


    ##### MODIFCATION #####
    def __preProcessArgs(self, args):
        # args [foo, bar, baz]
        outargs = []
        args = args.split(' ')

        for arg in args:
            if (len(arg) % 4 == 0):         # Does the arg actually need padding?
                outargs.append(bytes(arg, "utf-8"))
            else:                           # It does need padding!
                if "/" in arg:        # Does it contain a path to pad?
                    indexOfSlash = arg.index("/")
                    outargs.append(bytes(arg[0:indexOfSlash] + "/"*(4 - len(arg) % 4) + arg[indexOfSlash:len(arg)], "utf-8"))
                else:                       # Doesn't contain a path - here we pad with some stupid character
                    outargs.append(bytes(arg, "utf-8") + b'\x07'*(4 - len(arg) % 4))       # Adds 0x07 as some padding character - (it's the bell character) 

        # Outputs array of padded byte strings
        return outargs