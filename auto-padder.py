import subprocess
import sys
import argparse

import re

from enum import Enum

class InputTypes(Enum):
    FILE = 0
    ARG = 1    
    STDIN = 2

# defind the input type (default uses FILE)
INPUT_TYPE = 0#InputTypes.FILE

TMP_INPUT_FILE_NAME = ".tmp_wad"

SIZE_OF_ADDRESS_IN_BYTES = 4

# Error codes
NO_SEG_FAULT = -1


# gets address from stderr
def get_seg_fault_addr_from_stderr(stderr):

    # Checks if there is a segfault or not
    if len(re.findall("--- SIGSEGV", stderr)) == 0:
        # Then there are no seg faults so we return with code -1
        print("No Segfault found")
        return NO_SEG_FAULT

    print("SEG FAULT FOUND!!!\n")
    addr_arg = re.search("si_addr=", stderr)    # There should either be only 1 or 0 seg faults a program
    end_of_addr = re.search('}', stderr).span()[0]
    

    # Gets the start index of the address in stderr string
    str_addr = stderr[addr_arg.span()[1] + 2: end_of_addr]
    #start_of_addr = addr_arg.span()[1]# + 2
    
    #print(stderr[addr_arg.span()[1]: end_of_addr])
    #print(str_addr)

    byte_addr = None
    
    # check if the seg fault address is a null - this is pretty much useless
    if (str_addr == "LL"):
        byte_addr = b'\x00\x00\x00\x00'
    else:
        # First we make sure that the address is an even amount of bits
        if (len(str_addr) % 2):
            str_addr = '0' + str_addr
            #print("After formatting", str_addr)
        # Else we take the address, pad it with enough \x0s at the beginning and then return
        byte_addr = b'\x00' * (SIZE_OF_ADDRESS_IN_BYTES - int(len(str_addr)/2)) + bytearray.fromhex(str_addr)
    
    #print("Byte addr of the seg fault:", byte_addr)

    # returns the address in bytes
    return byte_addr


# Run strace as a subprocess
def run_strace(args, use_stdin=False, stdin=None):

    strace_out = subprocess.Popen(["strace", "-e", "signal"] + args, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE)        # Runs strace as a subprocess
    
    # communicate with stdin (if needed)
    stdout_bytes, stderr_bytes = strace_out.communicate(input=stdin)

    strace_out.wait()
    stderr = stderr_bytes.decode("utf-8")            # Grabs stderr for when strace breaks (due to seg fault)

    #print("##############################\n", stdout_bytes, "\n##############################")
    # returns error code or address
    foo = get_seg_fault_addr_from_stderr(stderr)
    #print(foo)
    return foo


def handle_file(vulnerableFile, bof):
    file = open(TMP_INPUT_FILE_NAME, "bw")
    file.write(bof)
    file.close()

    # Return result
    return run_strace([vulnerableFile, TMP_INPUT_FILE_NAME])

# Handle the input if it's a cmd line argument
def handle_arg(vulnerableFile, bof):
    str_bof = bof.decode("utf-8")

    return run_strace([vulnerableFile, str_bof])

# Handle the input if it uses STDIN
def handle_stdin(vulnerableFile, bof):
    return run_strace([vulnerableFile], use_stdin=True, stdin=bof) 


# input type handler
def handle_input_type(vulnerableFile, bof, inputType):
    # case it's a file input
    if (inputType == InputTypes.FILE):
        return handle_file(vulnerableFile, bof)

    # case argument input
    elif (inputType == InputTypes.ARG):
        return handle_arg(vulnerableFile, bof)

    # case stdin input
    elif (inputType == InputTypes.STDIN):
        return handle_stdin(vulnerableFile, bof)
    
    # case it's smth else (weird af)
    else:
        print("Invalid input type:", inputType, "- this really shouldn't be running")
        return None


def find_BOF(vulnerableFile, inputType):   
    counter = 0

    bof = b''
    head = b''

    sig_addr = -1#run_strace([vulnerableFile, TMP_INPUT_FILE_NAME])
    while (sig_addr == -1 or sig_addr != head):#and counter < 20:#counter < 10:#run_strace():
              
        # construct byte string
        bof = (7).to_bytes(1, byteorder='big') * 4 * counter        
        head = (33).to_bytes(1, byteorder='big') * 4
        bof += head
        print("Unsuccessful :(\nTrying:", bof)

        # Write the bof string to the program and attempt to break it
        sig_addr = handle_input_type(vulnerableFile, bof, inputType)

        counter += 1
    
    print("BoF Exploit Found!!!\nThe length of the padding is:", (counter - 1) * SIZE_OF_ADDRESS_IN_BYTES)

        
def handle_args():
    desc = '''
     ________________
    < auto-padder.py >
     ----------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\\
                ||----w |
                ||     ||
    
    Welcome to auto-wadder.py! This program automatically finds the length of padding that is require to exploit some buffer overflow expolit.
    '''

    # create parser
    parser = argparse.ArgumentParser(prog="Auto-wadder.py", description=desc, epilog="Enjoy!",  formatter_class=argparse.RawTextHelpFormatter)


    parser.add_argument("filePath", help="The path to the vulnerable file", type=str)#, formatter_class=argparse.RawTextHelpFormatter)

    #parse.add_argumnet("-h", "--help", help)

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("-f", "--file", help="Case where the vulnerable input is a file", action="store_true", default=False)
    input_group.add_argument("-a", "--arg", help="Case where the vulnerable input is a cmd line argument", action="store_true", default=False)
    input_group.add_argument("-i", "--stdin", help="Case where the vulnerable input is in STDIN ", action="store_true", default=False)

    args = parser.parse_args()

    print(args.filePath)
    return args


def main():
    args = handle_args()
    
    # Define input args here
    find_BOF(args.filePath, InputTypes.FILE)

main()