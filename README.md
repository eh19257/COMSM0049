# Return Oriented Programming Chain Script (COMSM0102)

This repo contains code for generating return oriented programming (ROP) exploit chains. The program `auto-padder.py` first works out the amount of padding that is needed to overwrite the return address of the current function. The program `ROPGadget.py`, which is a modified version of the original found [here](https://github.com/JonathanSalwan/ROPgadget), can create ROP chains for arbitrary `execve()` syscalls and can handle .data addresses and values that contain NULL bytes - the program can (nearly) execute arbitrary shellcode. 

## Settin up the environment

We will be running this proof of concept in a Vagrant virtual machine by using the `Vagrantfile` below. We assume that you have vagrant installed on your machine. 
    
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

Save the Vagrantfile into your working directory and run the following in bash to start and connect to your VM - this might take a while depending on your internet connection.

```
vagrant up
vagrant ssh
```

We can now install some dependencies on the VM by running the following:

```
sudo apt update
sudo apt install -y python3-pip gcc-multilib
pip3 install capstone
```

Unzip/extract the provided `.zip` into your current working directory. If you are cloning the code from a repo, then remember to traverse into the local repository using `cd COMSM0049`.

We can extract the zip with the following:

```
unzip <filename.zip>

```

All of the test programs that we will be using are found in the directory `vulnz` and to compile each of them, we can run:

```
gcc -fno-stack-protector -m32 -static vulnz/vuln1.c -o vulnz/vuln1-32
gcc -fno-stack-protector -m32 -static vulnz/vuln2.c -o vulnz/vuln2-32
gcc -fno-stack-protector -m32 -static vulnz/vuln3.c -o vulnz/vuln3-32
```

## Running the code

`auto-padder.py` finds the amount of padding needed to overwrite the return address. This can be ran with:

```
python3 ROPgadget/auto-padder.py vulnz/vuln3-32
```

We can choose to pipe the value of padding into our modified ROPGadget.py by using the `-p` flag:

```
python3 ROPgadget/auto-padder.py vulnz/vuln3-32 -p
```

We can use the flags `--file`, `--arg` and `--stdin` to specify what input type the vulnerale file uses. For example:

```
python3 ROPgadget/auto-padder.py vulnz/vuln1-32 --arg
python3 ROPgadget/auto-padder.py vulnz/vuln2-32 --stdin
```

If we already know the amount of padding that is required to overwrite the return address of the current function, then we can directly run our modifed version of `ROPgadget.py` with the amount of padding paramertised. We do this with the `-p` or `--padding` flags.

```
python3 ROPgadget/ROPgadget.py --ropchain --binary vulnz/vuln3-32 --padding=44
```

################### TASK 1 DONE #######################
################## TASK 2 ##############


To generate a ropchain with an arbitrary execve we can set the environment variable `ROPCMD` to run our choosen program. For example:

```
export ROPCMD="/bin/sh"
```

We can then run our either `auto-padder.py` to generate the ropchain or we can run `ROPgadget.py` directly as such:

```
python3 ROPgadget/auto-padder.py vulnz/vuln3-32 -p
python3 ROPgadget/ROPgadget.py --ropchain --binary vulnz/vuln3-32 -p=44
```


###################### TASK 4

Running arbitrary shellcode can be done as the following:




To generate ROPchain `python3 ROPgadget/ROPgadget.py --binary vuln3-32 --ropchain `
