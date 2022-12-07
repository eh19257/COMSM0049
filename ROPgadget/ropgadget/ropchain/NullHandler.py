from struct import pack

# Handles null bytes and stuff
class NullHandler():
    def __init__(self, wordsize):
        self.__WORD_SIZE = wordsize
        return

    # does the inputed binary contain a NULL byte?
    def contains_null(self, binary):
        for b in binary:
            if (b == 0):
                return True
        
        return False

    # create mask
        # does the mask have a null
        # does the masked_addr have a null
    # add to

    def CreateNonIterativeMask(self, value, mask_type):
        mask = b''
        masked_addr = b''
        direction = 1
        count = 0
        
        for i in range(0x01010101, 0xFFFFFFFF + 1):
            byte_mask = i.to_bytes(self.__WORD_SIZE, byteorder="big")
            byte_masked_addr = self.Apply_Mask(byte_mask,value,mask_type)

            if (not (self.contains_null(byte_mask)) and not (self.contains_null(byte_masked_addr))):
                break

            count = count + 1
            if(count > 20000):
                return None

        # we try a new mask
    
        return int.from_bytes(byte_mask, "big"), int.from_bytes(byte_masked_addr, "big")
    
    # Mask for iteractive mask generation (i.e. for inc and dec) maskChains
    def CreateIterativeMask(self, value, mask_type):
        mask = b''
        masked_addr = b''
        direction = 1

        if (mask_type == "inc"):
            direction = -1

        for b in value:

            for i in range(0, 256, direction):
                byte_mask = i#.to_bytes(1, byteorder="big")
                byte_masked_addr = self.Apply_Mask(byte_mask, b, mask_type)#.to_bytes(1, byteorder="big"), mask_type)

                if (not (self.contains_null(byte_masked_addr))):
                    mask += byte_mask.to_bytes(1, byteorder="big")
                    masked_addr += byte_masked_addr
                    break
        
        return int.from_bytes(mask, "big"), int.from_bytes(masked_addr, "big")


    # Applys some masking operation for the iterative mask
    def Apply_Mask(self, mask, value, mask_type):
        if   (mask_type == "xor"):
            return self.xor_byte(mask, value)
        
        # value = mask_value + mask ==> mask_value = value - mask
        elif (mask_type == "add"):
            mask_value = (int.from_bytes(value, "big") - int.from_bytes(mask, "big")) % (self.__WORD_SIZE * 256)
            return mask_value.to_bytes(self.__WORD_SIZE, byteorder="big")

        # value = mask_value - mask ==> mask_value = mask + value
        elif (mask_type == "sub"):
            mask_value = (int.from_bytes(value, "big") + int.from_bytes(mask, "big")) % (self.__WORD_SIZE * 256)
            return mask_value.to_bytes(self.__WORD_SIZE, byteorder="big")

        # value = mask_value - mask ==> mask_value = value + mask
        elif (mask_type == "dec"):
            mask_value = (value + mask) % (256)
            return mask_value.to_bytes(1, byteorder="big")
        
        # value = mask_value + mask ==> mask_value = value - mask
        elif (mask_type == "inc"):
            mask_value = (value - mask) % (256)
            return mask_value.to_bytes(1, byteorder="big")
        
        else:
            print("Unknown mask_type: {}".format(mask_type))
            raise
        

    # bitwise xor of 2 bytestrings
    def xor_byte(self, a, b):
        # return None if the strings are different length
        if (len(a) != len(b)):
            return None
        
        c = b''

        for i in range(0, len(a)):
            c += (a[i]^b[i]).to_bytes(1, byteorder="big")

        return c


#foo = 256
#foo = foo.to_bytes(2, byteorder='big')
#print(foo)
#print(NullHandler().contains_null(foo))

#print(NullHandler().CreateArithmeticMask(b'\xFF\xFF\x00\xFF', "dec"))