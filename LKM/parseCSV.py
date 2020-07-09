import csv
import re
import sys

declarationRe = re.compile("(asmlinkage [a-z]+) (sys[_a-z0-9]+)\((.*)\)")

BUFF = []

def startBuf():
    BUFF.append("")

def endBuf():
    return BUFF.pop()

def printBuf(*p, sep=' ', end='\n'):
    if len(BUFF) == 0: startBuf()
    BUFF[-1] += sep.join(str(x) for x in p) + end

def parse(row, index):
    fndl = row[3].strip().strip(";")
    ret, funcName, args = None, None, []
    try:
        ret, funcName, args = declarationRe.findall(fndl)[0]
    except:
        print('!!ERROR!!', index, file=sys.stderr)
        return

    args = [x.strip() for x in args.split(",")]
    argsName = [x.split(" ")[-1].strip("*") for x in args if x != "void"]

    name = row[1]
    syscall = row[2]
    bind = row[5]=="TRUE"
    #print(argsName)
    return name, syscall, bind, (ret, funcName, args, argsName)
    #defineMySystemCall()

def printMySyscallDefinition(ret, name, origname, args, argsName):
    printBuf("//"+"="*30)
    printBuf("static asmlinkage", ret)
    printBuf(f"{name}(" + ", ".join(args) + ") {")
    printBuf("\t" f"{ret} (*origCall)(" + ", ".join(args) + f") = (void *) {origname};")
#     printBuf("\t" f"printk(KERN_WARNING \"Redirected {origname} called\\n\");")
    printBuf("\t" "functionRedirected += 1;")
    printBuf("\t" f"return origCall(" + ", ".join(argsName) + ");")
    printBuf("}")
    printBuf("")

def setupMacros():
    printBuf("")
    printBuf("typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);")
    printBuf("")
    printBuf("#define NOVA_max_syscalls 512 //it was hard to find a header which define it")
    printBuf("")
    printBuf("#define NOVA_STORE_ORIG(x, y) { \\")
    printBuf("\t" "orig_systemcall_table[x] = y[x]; \\")
    printBuf("}")
    printBuf("")
    printBuf("#define NOVA_REDIRECT(x, y) { \\")
    printBuf("\t", "y[x] = nova_syscall_table[x]; \\")
    printBuf("}")
    printBuf("")
    printBuf("#define NOVA_RESTORE(x, y) { \\")
    printBuf("\t", "y[x] = orig_systemcall_table[x]; \\")
    printBuf("}")
    printBuf("")
    printBuf("static long functionRedirected = 0;")

def defineSystemCalls(parsedSysCalls):
    startBuf()
    printBuf("#include <linux/syscalls.h>")
    printBuf("")
    setupMacros()
    printBuf("")
    headers = endBuf()

    startBuf()
    printBuf("static sys_call_ptr_t orig_systemcall_table[NOVA_max_syscalls] = {")
    printBuf("\t[0 ... NOVA_max_syscalls-1] = NULL")
    printBuf("};")
    origSyscallTable = endBuf()

    sysCallsMap = {}

    startBuf()
    for syscall in parsedSysCalls:
        name, syscall, bind, call = syscall
        ret, funcName, args, argsName = call
        if not bind: continue
        newname = "nova_" + funcName
        sysCallsMap["__NR_"+name] = newname;
        printMySyscallDefinition(ret, newname, f"orig_systemcall_table[__NR_{name}]", args, argsName)
    definition = endBuf()

    startBuf()
    printBuf("static sys_call_ptr_t nova_syscall_table[NOVA_max_syscalls] = {")
    printBuf("\t" "[0 ... NOVA_max_syscalls-1] = NULL,")
    for num, name in sysCallsMap.items():
        printBuf("\t" f"[{num}] = (sys_call_ptr_t) {name},")
    printBuf("};")
    table = endBuf()

    startBuf()
    printBuf("")
    printBuf("static int nova_handled_syscals[] = {")
    printBuf("\t" ",\n\t".join(sysCallsMap.keys()))
    printBuf("};")
    handled = endBuf()

#     print(table)
#     print(len(sysCallsMap))
    print("#ifndef __NOVA_SYS_CALL_REDIRECT__")
    print("#define __NOVA_SYS_CALL_REDIRECT__")
    print(headers)
    print(origSyscallTable)
    print(definition)
    print(table)
    print(handled)
    print("#endif")





def parseSysCallCsv(fname="syscall.csv"):
    with open(fname) as fp:
        syscsv = csv.reader(fp)
        rows = [row for row in syscsv][1:]

        parsedSysCalls = []
        for i, r in enumerate(rows):
            ret = parse(r, i+2) #to match with execl
            if ret is not None:
                parsedSysCalls.append(ret)

#         print(len(parsedSysCalls))
        defineSystemCalls(parsedSysCalls)

if __name__ == "__main__":
#     print(sys.argv)
    fname = "syscall.csv"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    parseSysCallCsv(fname)
