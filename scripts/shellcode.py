from r2pipe import *
from json import *

r2 = open("shellcode/x64/Debug/shellcode.obj", flags=["-e", "io.cache=true"])
r2.cmd("s 0")
r2.cmd("af")
size = loads(r2.cmd("afij"))[0]["size"]
print(r2.cmd(f"pc {size}"))