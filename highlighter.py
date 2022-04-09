import idautils
import idc
import idaapi

for func in idautils.Functions():
    color = 0x000000
    dism_addr = list(idautils.FuncItems(func))
    for line in dism_addr:
        m = idc.print_insn_mnem(line)
        if m == 'call':
            idc.set_color(line, 1, color)
            print(line)
    num_refs = len(list(idautils.CodeRefsTo(func, 0)))
    idc.set_func_cmt(func, "xrefs: " + str(num_refs), 1)


for func in idautils.Functions():
    color = 0x000000
    dism_addr = list(idautils.FuncItems(func))
    for line in dism_addr:
        ins = idaapi.ida_ua.insn_t()
        idaapi.decode_insn(ins, line)
        
        m = idc.print_insn_mnem(line)
        if m in ['div', 'idiv', 'mul', 'imul', 'shl', 'shr', 'rol', 'ror', 'sar']:
            idc.set_color(line, 1, color)
        if m == 'xor':
            if ins.Op1.reg != ins.Op2.reg:
                idc.set_color(line, 1, color)