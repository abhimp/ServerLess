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
    printBuf(ret)
    printBuf(f"{name}(" + ", ".join(args) + ") {")
    printBuf("\t" f"{ret}(*origCall)(" + ", ".join(argsName) + f") = {origname};")
    printBuf("\t" f"return origCall(" + ", ".join(argsName) + ");")
    printBuf("}")
    printBuf("")

def defineSystemCalls(parsedSysCalls):
    startBuf()
    printBuf("void *orig_systemcall_table[NR_syscalls] = {")
    printBuf("\t[0 ... NR_syscalls-1] = sys_ni_syscall")
    printBuf("};")
    origSyscallTable = endBuf()

    sysCallsMap = {}

    startBuf()
    for syscall in parsedSysCalls:
        name, syscall, bind, call = syscall
        ret, funcName, args, argsName = call
        if not bind: continue
        newname = "nova_" + funcName
        sysCallsMap["NR_"+name] = newname;
        printMySyscallDefinition(ret, newname, f"orig_systemcall_table[NR_{name}]", args, argsName)
    definition = endBuf()

    startBuf()
    printBuf("syscall_handler_t nova_syscall_table[NR_syscalls];")
    for num, name in sysCallsMap.items():
        printBuf(f"nova_syscall_table[{num}] = {name};")
    table = endBuf()

    startBuf()
    printBuf("")
    printBuf("int nova_handled_syscals[] = {")
    printBuf("\t", ",\n\t".join(sysCallsMap.keys()))
    printBuf("};")
    handled = endBuf()

#     print(table)
#     print(len(sysCallsMap))
    print(origSyscallTable)
    print(definition)
    print(table)
    print(handled)





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

parseSysCallCsv()
