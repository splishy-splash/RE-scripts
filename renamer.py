def rename_things(start, end, prefix):
    current_addr = start
    while current_addr < end:
        if ida_name.get_name(current_addr) != '':
            ida_name.set_name(current_addr, f"{prefix}_{idc.print_operand(current_addr, 0).split()[1]}", ida_name.SN_FORCE)
        current_addr += 1
