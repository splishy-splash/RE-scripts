def run_until_call():
	while True:
		step_into()
		code = idaapi.wait_for_next_event(idaapi.WFNE_CONT | idaapi.WFNE_SUSP, -1)
		if code <= 0:
			return (False, "Failed to run until call.")
		elif idc.print_insn_mnem(ida_dbg.get_ip_val()) == 'call':
			return
		elif idc.print_insn_mnem(ida_dbg.get_ip_val()) == 'jmp':
			if idc.get_operand_type(idc.print_insn_mnem(ida_dbg.get_ip_val()) not in [6,7]:
				return
