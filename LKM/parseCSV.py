import csv
import re
import sys

declarationRe = re.compile("asmlinkage ([a-z]+) (sys[_a-z0-9]+)\((.*)\)")

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

def printMySyscallDefinition(ret, name, syscall, args, argsName):
    printBuf("//"+"="*30)
    printBuf(f"#ifdef __NR_{syscall}")
    printBuf("static asmlinkage", ret)
    printBuf(f"{name}(" + ", ".join(args) + ") {")
    printBuf("\t" f"{ret} ret = -EPERM;")
    printBuf("\t" f"{ret} (*origCall)(" + ", ".join(args) + f") = (void *) orig_systemcall_table[__NR_{syscall}];")
    printBuf("#ifdef NOVA_REDIR_COUNT_DEBUG")
    printBuf("\t" "functionRedirected += 1;")
    printBuf("\t" "activeRedirection += 1;")
    printBuf("#endif")

    printBuf("")
    printBuf(f"#ifdef NOVA_PRE_PROC_{syscall}")
    printBuf("\t\t" f"NOVA_PRE_PROC_{syscall}(" + ", ".join(argsName) + ");")
    printBuf(f"#elif defined NOVA_PRE_PROC")
    printBuf("\t\t" f"NOVA_PRE_PROC({syscall});")
    printBuf("#endif")

    printBuf("")
    printBuf("\t" "if(0) {") #balanced bracket always looks good
    printBuf(f"#ifdef NOVA_BASE_VERIFY_{syscall}")
    printBuf("\t" "}", f"else if(NOVA_BASE_VERIFY_{syscall}(" + ", ".join(argsName) + ")) {")
    printBuf(f"#elif defined NOVA_BASE_VERIFY") #this is common. no argument will be provided
    printBuf("\t" "}", f"else if(NOVA_BASE_VERIFY({syscall}))" " {")
    printBuf("#else")
    printBuf("\t" "} else if(!IS_SAME_AS_NOVA_ID(current->real_parent->pid)) {") #can be enabled only if nov_ppid is not zero
    printBuf("#endif")
    printBuf("\t\t" f"ret = origCall(" + ", ".join(argsName) + ");")
    printBuf("\t" "} else { ")

    printBuf("")
    printBuf("\t\t" "if(0) {")
    printBuf(f"#ifdef NOVA_HANDLED_VERIFY_{syscall}")
    printBuf("\t\t" "}",  f"else if(NOVA_HANDLED_VERIFY_{syscall}(" + ", ".join(argsName) + ")) {")
    printBuf("\t\t\t" f"ret = origCall(" + ", ".join(argsName) + ");")
    printBuf(f"#elif defined NOVA_HANDLED_VERIFY")
    printBuf("\t\t" "}", f"else if(NOVA_HANDLED_VERIFY({syscall})" + ") {")
    printBuf("\t\t\t" f"ret = origCall(" + ", ".join(argsName) + ");")
    printBuf("#endif")
    printBuf("\t\t" "} ")

    printBuf("")
    printBuf(f"#ifdef NOVA_POST_PROC_{syscall}")
    printBuf("\t\t" f"NOVA_POST_PROC_{syscall}(" + ", ".join(argsName) + ");")
    printBuf("#endif")
    printBuf(f"#ifdef NOVA_POST_PROC")
    printBuf("\t\t" f"NOVA_POST_PROC({syscall});")
    printBuf("#endif")

    printBuf("")
    printBuf("\t}")

    printBuf("#ifdef NOVA_REDIR_COUNT_DEBUG")
    printBuf("\t" "activeRedirection -= 1;")
    printBuf("#endif")
    printBuf("\t" "return ret;")
    printBuf("}")
    printBuf(f"#endif //__NR_{syscall}")
    printBuf("")

def generateSourceFile(fileName, parsedSysCalls):
    sysCallsMap = {}

    startBuf()
    for syscall in parsedSysCalls:
        name, syscall, bind, call = syscall
        ret, funcName, args, argsName = call
        if not bind: continue
        newname = "nova_" + funcName
        sysCallsMap["__NR_"+name] = newname;
        printMySyscallDefinition(ret, newname, name, args, argsName)
    definition = endBuf()

    startBuf()
    printBuf("static sys_call_ptr_t nova_syscall_table[NOVA_max_syscalls] = {")
    printBuf("\t" "[0 ... NOVA_max_syscalls-1] = NULL,")
    for num, name in sysCallsMap.items():
        printBuf(f"#ifdef {num}")
        printBuf("\t" f"[{num}] = (sys_call_ptr_t) {name},")
        printBuf("#endif")
    printBuf("};")
    table = endBuf()

    startBuf()
    printBuf("")
    printBuf("static int nova_handled_syscals[] = {")
    for key in sysCallsMap.keys():
        printBuf(f"#ifdef {key}")
        printBuf(f"\t{key},")
        printBuf(f"#endif")
#     printBuf("\t" + ",\n\t".join(sysCallsMap.keys()))
    printBuf("};")
    handled = endBuf()


    with open(f"{fileName}.h", "w") as fp:
        print(definition, file=fp)
        print(table, file=fp)
        print(handled, file=fp)

def generateFiles(parsedSysCalls, fileName="nova_syscall"):
    generateSourceFile(fileName, parsedSysCalls)

def parseSysCallCsv(fname="syscall.csv"):
    with open(fname) as fp:
        syscsv = csv.reader(fp)
        rows = [row for row in syscsv][1:]

        parsedSysCalls = []
        for i, r in enumerate(rows):
            ret = parse(r, i+2) #to match with execl
            if ret is not None:
                parsedSysCalls.append(ret)

        return parsedSysCalls

if __name__ == "__main__":
    fname = "syscall.csv"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    parsedSysCalls = parseSysCallCsv(fname)
    generateFiles(parsedSysCalls)
