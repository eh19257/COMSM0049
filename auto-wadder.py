import subprocess
import sys
import re

TMP_INPUT_FILE_NAME = ".tmp_wad"

SIZE_OF_ADDRESS_IN_BYTES = 4

# Error codes
NO_SEG_FAULT = -1

# Cleans up stderr
def stderr_to_string(raw):
    out = ""
    char = raw.read(1)
    while (char != b''):
        out += char.decode("utf-8")
        char = raw.read(1)

    return out


# gets address from stderr
def get_seg_fault_addr_from_stderr(stderr):

    # Checks if there is a segfault or not
    if len(re.findall("--- SIGSEGV", stderr)) == 0:
        # Then there are no seg faults so we return with code -1
        print("No Segfault found")
        return NO_SEG_FAULT

    addr_arg = re.search("si_addr=", stderr)    # There should either be only 1 or 0 seg faults a program
    end_of_addr = re.search('}', stderr).span()[0]
    

    # Gets the start index of the address in stderr string
    str_addr = stderr[addr_arg.span()[1] + 2: end_of_addr]
    #start_of_addr = addr_arg.span()[1]# + 2
    
    print(stderr[addr_arg.span()[1]: end_of_addr])
    print(str_addr)

    byte_addr = None
    
    # check if the seg fault address is a null - this is pretty much useless
    if (str_addr == "LL"):
        byte_addr = b'\x00\x00\x00\x00'
    else:
        # First we make sure that the address is an even amount of bits
        if (len(str_addr) % 2):
            str_addr = '0' + str_addr
            print("After formatting", str_addr)
        # Else we take the address, pad it with enough \x0s at the beginning and then return
        byte_addr = b'\x00' * (SIZE_OF_ADDRESS_IN_BYTES - int(len(str_addr)/2)) + bytearray.fromhex(str_addr)
    
    

    #byte_addr = bytes(str_addr[2:len(str_addr)], "utf-8")

    print(byte_addr)
    
    # returns the address in bytes
    return byte_addr


# Run strace as a subprocess
def run_strace(args):

    strace_out = subprocess.Popen(["strace", "-e", "signal"] + args, stderr=subprocess.PIPE)        # Runs strace as a subprocess

    strace_out.wait()
    stderr = stderr_to_string(strace_out.stderr)            # Grabs stderr for when strace breaks (due to seg fault)

    # returns error code or address
    foo = get_seg_fault_addr_from_stderr(stderr)
    #print(foo)
    return foo



def find_BOF(vulnerableFile):
    out = b''
    
    # open input file
    file = open(TMP_INPUT_FILE_NAME, "bw")
    counter = 1

    bof = b''
    head = b''

    sig_addr = run_strace([vulnerableFile, TMP_INPUT_FILE_NAME])
    while sig_addr == -1 or sig_addr != head:#counter < 10:#run_strace():
        
        file = open(TMP_INPUT_FILE_NAME, "bw")
        
        # construct byte string
        
        head = (counter).to_bytes(1, byteorder='big')*4
        bof += head
        print(bof)

        file.write(bof)
        file.close()

        sig_addr = run_strace([vulnerableFile, TMP_INPUT_FILE_NAME])

        #print(file.read())
        counter += 1
    
    print("BoF Exploit Found!!!\nThe length of the padding is:", (counter - 2) * SIZE_OF_ADDRESS_IN_BYTES)
        
        
def handle_args():
    if len(sys.argv) != 2:
        print("usage: python3 auto-wadder.py <vulnerable_file>")
        return 1;
    return 0


def main():
    if (handle_args()):
        return
    
    find_BOF(sys.argv[1])
    #run_strace([sys.argv[1], TMP_INPUT_FILE_NAME])


main()