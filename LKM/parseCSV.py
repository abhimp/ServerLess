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
    printBuf("\t" f"{ret} ret;")
    printBuf("\t" f"{ret} (*origCall)(" + ", ".join(args) + f") = (void *) {origname};")
    printBuf("#ifdef NOVA_REDIR_COUNT_DEBUG")
    printBuf("\t" "functionRedirected += 1;")
    printBuf("\t" "activeRedirection += 1;")
    printBuf("#endif")
    printBuf("\t" "if(current->real_parent->pid == nova_ppid) {") #can be enabled only if nov_ppid is not zero
    printBuf("\t\t" f"ret = origCall(" + ", ".join(argsName) + ");")
    printBuf("\t}")
    printBuf("#ifdef NOVA_REDIR_COUNT_DEBUG")
    printBuf("\t" "activeRedirection -= 1;")
    printBuf("#endif")
    printBuf("\t" "return ret;")
    printBuf("}")
    printBuf("")

def generateSourceFile(fileName, parsedSysCalls):
    startBuf()
    printBuf("#define NOVA_REDIRECT_SOURCE") #need to identify variable definition
    printBuf("")
    printBuf(f"#include \"{fileName}.h\"")
    printBuf("#include \"kern_version_adjustment.h\"")
    printBuf("")
    printBuf("static long functionRedirected = 0;")
    printBuf("static long activeRedirection = 0;")
    printBuf("static pid_t nova_ppid = 0;")
    printBuf("")
    headers = endBuf()

    startBuf()
    printBuf("static sys_call_ptr_t orig_systemcall_table[NOVA_max_syscalls] = {")
    printBuf("\t[0 ... NOVA_max_syscalls-1] = NULL")
    printBuf("};")
    printBuf("")
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

    #exported functions
    startBuf()
    printBuf("")
    printBuf("long novaGetNumFunctionRedirected(void) { return functionRedirected; }")
    printBuf("long novaGetActiveRedirections(void) { return activeRedirection; }")
    printBuf("void novaSetPPid(pid_t pid) {")
    printBuf("\t" "if (pid <= 2) return;")
    printBuf("\t" "nova_ppid = pid;")
    printBuf("}")
    printBuf("void novaStoreOrigSysCall(int x, sys_call_ptr_t *y) {")
    printBuf("\t" "NOVA_STORE_ORIG(x, y);")
    printBuf("}")
    printBuf("void novaRedirectSysCall(int x, sys_call_ptr_t *y) {")
    printBuf("\t" "NOVA_REDIRECT(x, y);")
    printBuf("}")
    printBuf("void novaRestoreSysCall(int x, sys_call_ptr_t *y) {")
    printBuf("\t" "NOVA_RESTORE(x, y);")
    printBuf("}")

    printBuf("void novaStoreAllOrigSysCalls(sys_call_ptr_t *y) {")
    printBuf("\t" "int i;")
    printBuf("\t" "int numHandled = sizeof(nova_handled_syscals)/sizeof(nova_handled_syscals[0]);")
    printBuf("\t" "for(i = 0; i < numHandled; i++) {")
    printBuf("\t\t" "NOVA_STORE_ORIG(nova_handled_syscals[i], y);")
    printBuf("\t}")
    printBuf("}")
    printBuf("void novaRedirectAllSysCalls(sys_call_ptr_t *y) {")
    printBuf("\t" "int i;")
    printBuf("\t" "int numHandled = sizeof(nova_handled_syscals)/sizeof(nova_handled_syscals[0]);")
    printBuf("\t" "for(i = 0; i < numHandled; i++) {")
    printBuf("\t\t", "NOVA_REDIRECT(nova_handled_syscals[i], y);")
    printBuf("\t}")
    printBuf("}")
    printBuf("void novaRestoreAllSysCall(sys_call_ptr_t *y) {")
    printBuf("\t" "int i;")
    printBuf("\t" "int numHandled = sizeof(nova_handled_syscals)/sizeof(nova_handled_syscals[0]);")
    printBuf("\t" "for(i = 0; i < numHandled; i++) {")
    printBuf("\t\t", "NOVA_RESTORE(nova_handled_syscals[i], y);")
    printBuf("\t}")
    printBuf("}")
    exportedFunctions = endBuf()



#     print(table)
#     print(len(sysCallsMap))
    with open(f"{fileName}.c", "w") as fp:
        print(headers, file=fp)
        print(origSyscallTable, file=fp)
        print(definition, file=fp)
        print(table, file=fp)
        print(handled, file=fp)
        print(exportedFunctions, file=fp)

def setupMacros():
    printBuf("")
    printBuf("typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);")
    printBuf("")
    printBuf("#define NOVA_max_syscalls 512 //it was hard to find a header which define it")
    printBuf("")
    printBuf("#define NOVA_STORE_ORIG(x, y) { \\")
    printBuf("\t" "if(y[x] != nova_syscall_table[x]) {\\")
    printBuf("\t\t" "orig_systemcall_table[x] = y[x]; \\")
    printBuf("\t}\\")
    printBuf("}")
    printBuf("")
    printBuf("#define NOVA_REDIRECT(x, y) { \\")
    printBuf("\t" "if(nova_ppid >= 2 && y[x] != nova_syscall_table[x]) {\\")
    printBuf("\t\t" "y[x] = nova_syscall_table[x]; \\")
    printBuf("\t}\\")
    printBuf("}")
    printBuf("")
    printBuf("#define NOVA_RESTORE(x, y) { \\")
    printBuf("\t" "if(NULL != orig_systemcall_table[x]) {\\")
    printBuf("\t\t" "y[x] = orig_systemcall_table[x]; \\")
    printBuf("\t}\\")
    printBuf("}")
    printBuf("")
    printBuf("#define RESET_COUNTER functionRedirected=0")


def generateHeaderFile(fileName):
    startBuf()
    printBuf("#include <linux/syscalls.h>")
    printBuf("")
    setupMacros()
    printBuf("")
    printBuf("#ifndef NOVA_REDIRECT_SOURCE")
#     printBuf("extern long functionRedirected;")
#     printBuf("extern long activeRedirection;")
#     printBuf("extern sys_call_ptr_t orig_systemcall_table[NOVA_max_syscalls];")
#     printBuf("extern sys_call_ptr_t nova_syscall_table[NOVA_max_syscalls];")
#     printBuf("extern int nova_handled_syscals[];")
    printBuf("#endif")
    printBuf("")
    headers = endBuf()

    startBuf()
    printBuf("")
    printBuf("long novaGetNumFunctionRedirected(void);")
    printBuf("long novaGetActiveRedirections(void);")
    printBuf("void novaSetPPid(pid_t pid);")
    printBuf("void novaStoreOrigSysCall(int x, sys_call_ptr_t *y);")
    printBuf("void novaRedirectSysCall(int x, sys_call_ptr_t *y);")
    printBuf("void novaRestoreSysCall(int x, sys_call_ptr_t *y);")

    printBuf("void novaStoreAllOrigSysCalls(sys_call_ptr_t *y);")
    printBuf("void novaRedirectAllSysCalls(sys_call_ptr_t *y);")
    printBuf("void novaRestoreAllSysCall(sys_call_ptr_t *y);")
    exportedFunctions = endBuf()

    with open(f"{fileName}.h", "w") as fp:
        print("#ifndef __NOVA_SYS_CALL_REDIRECT__", file=fp)
        print("#define __NOVA_SYS_CALL_REDIRECT__", file=fp)
        print(headers, file=fp)
        print(exportedFunctions, file=fp)
        print("#endif", file=fp)

def generateFiles(parsedSysCalls, fileName="nova_syscall"):
    generateHeaderFile(fileName)
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
#         print(len(parsedSysCalls))
#         defineSystemCalls(parsedSysCalls)

if __name__ == "__main__":
#     print(sys.argv)
    fname = "syscall.csv"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    parsedSysCalls = parseSysCallCsv(fname)
    generateFiles(parsedSysCalls)
