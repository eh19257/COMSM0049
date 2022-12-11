# Return Oriented Programming Chain Script (COMSM0102)

This repo contains code for generating Return Oriented Programming chain exploits for bufferoverflows. The program `auto-padder.py` first works out the amount of padding that is needed to overwrite the return address of the local function. There is also the program ROPGadget.py which is a modified version of the original found [here](https://github.com/JonathanSalwan/ROPgadget), this can create ROP chains for arbitrary `execve()` syscalls and can handle .data addresses and values that contain NULL bytes - the program can (nearly) execute arbitrary shellcode. 

## Settin up the environment

We will be running this Proof of concept in a vargrant virtual machine. We can use the `Vagrantfile` below:
    
```
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.define "box" do |box|
                box.vm.box = "ubuntu/bionic64"
                box.vm.hostname = "SSS-CW"
                box.vm.provider "virtualbox" do |virtualbox|
        virtualbox.name="SSS-CW"
    end
 end
end
```

Save the Vagrantfile into your working directory and run the following in bash - this might take a while depending on your internet connection.

```
vagrant up
vagrant ssh
```

From now we can install some dependencies by running the following:

```
sudo apt update
sudo apt install -y python3-pip gcc-multilib
pip3 install capstone
```

From here we will need to extracted the provided `.zip` or clone the repo. If you are cloning from the repo then you'll need traverse into the local code using `cd COMSM0049`.

Or we can extract the zip with the following:

```
unzip <filename.zip>

```

We will be running `vulnz/vuln3.c` to test our program on, we can compile our program as such:

```
gcc -fno-stack-protector -m32 -static vulnz/vuln3.c -o vulnz/vuln3-32
```

`auto-padder.py` finds the amount of padding needed to overwrite the return address. This can be ran with:

```
python3 ROPgadget/auto-padder.py vulnz/vuln3-32
```

We can pipe this value into the modified ROPGadget.py by using the `-p` flag:

```
python3 ROPgadget/auto-padder.py vulnz/vuln3-32 -p
```

We can use the flags `--file`, `--arg` and `--stdin` to specify what input type the vulnerale file uses. For example:

```
gcc -fno-stack-protector -m32 -static vulnz/vuln1.c -o vulnz/vuln1-32
gcc -fno-stack-protector -m32 -static vulnz/vuln2.c -o vulnz/vuln2-32

python3 ROPgadget/auto-padder.py vulnz/vuln1-32 --arg
python3 ROPgadget/auto-padder.py vulnz/vuln2-32 --stdin
```

################### TASK 1 DONE #######################
################## TASK 2 ##############


Running




To generate ROPchain `python3 ROPgadget/ROPgadget.py --binary vuln3-32 --ropchain `
