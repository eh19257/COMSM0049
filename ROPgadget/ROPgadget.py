#!/usr/bin/env python
## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import ropgadget
import os


execve = os.environ.get("ROPCMD")
if (execve is None):
    execve = "/bin/echo The exploit is working."
        

ropgadget.main(execve, [])
