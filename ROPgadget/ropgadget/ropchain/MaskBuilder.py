from struct import pack
from ropgadget.ropchain.NullHandler import NullHandler as nh

class MaskBuilder():
    def __init__(self, wordsize):
        self.__WORD_SIZE = wordsize
        return
        
        
    # Used to create a ROPchain for non iteratie masks (i.e. inc and dec). These chains are the most efficient
    # Based off CM
    def NonIterativeMask(self, mask, mask_addr, chainmask):
        # Creates a stack of this shape
        
        ##### POP SRC #####
        ### Masked_addr ###
        ##### POP DST #####
        ####### Mask ######
        ### XOR SRC/DST ###


        b =  pack("<I", popSrc["vaddr"])
        b += pack("<I", int_masked_addr)#" + str(self.__WORD_SIZE) + "s", masked_addr )
        b += self.__custompadding(popSrc, regAlreadSetted )        # merge any previous regs with the current one that's just been popped
        
        b += pack("<I", popDst["vaddr"])
        b += pack("<" + str(self.__WORD_SIZE) + "s", mask )
        b += self.__custompadding(popDst, regAlreadSetted | { popSrc["gadget"].split()[1]: int_masked_addr })
        
        # b += pack("<I", xorSrcDst)      # XOR PACK
        # Add padding for XOR

        return b
    




    # Creates the first part of the mask
    def CM(self, addr, regAlreadySetted, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall):
        # Creates a stack of this shape
        
        ##### POP SRC #####
        ### Masked_addr ###
        ##### POP DST #####
        ####### Mask ######
        ### XOR SRC/DST ###
    
        # Get mask and masked address
        # WARNING THIS CODE IS DIFFERENT
        mask, masked_addr = nh(self.__WORD_SIZE).CreateMask(addr)

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
        if (not ( nh(self.__WORD_SIZE).contains_null(addr) ) ):
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

        if (not (nh(self.__WORD_SIZE).contains_null(addr))):
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



   