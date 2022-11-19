import subprocess
import sys

def dumpAssembly(filePath):
    subprocess.run(["objdump", "-d", filePath])

    #return subprocess.stdout


if len(sys.argv) < 2:
    print("Not enough args")
else:
    dumpAssembly(sys.argv[1])
