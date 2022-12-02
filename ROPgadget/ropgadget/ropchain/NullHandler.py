from struct import pack
# Handles null bytes and stuff
class NullHandler():
    def __init__(self):
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
    def CreateMask(self, binary):
        mask = b''
        masked_addr = b''
        for b in binary:

            for i in range(1, 256):
                byte_mask = i.to_bytes(1, byteorder="big")
                byte_masked_addr = self.xor_byte(byte_mask, b.to_bytes(1, byteorder="big"))
                if (not (self.contains_null(byte_mask))):
                    if (not (self.contains_null(byte_masked_addr))):
                        mask += byte_mask
                        masked_addr += byte_masked_addr
                        break
                
                # we try a new mask
        
        return mask, masked_addr

    
    # bitwise xor of 2 bytestrings
    def xor_byte(self, a, b):
        # return None if the strings are different length
        if (len(a) != len(b)):
            return None
        
        c = b''

        for i in range(0, len(a)):
            c += (a[i]^b[i]).to_bytes(1, byteorder="big")

        return c


#print(NullHandler().contains_null(b'\x00\x01\x02\x03'))