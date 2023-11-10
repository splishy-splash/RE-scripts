def run_until_call():
	while idc.print_insn_mnem(get_reg_value('EIP')) != 'call':
		step_into()
		code = idaapi.wait_for_next_event(idaapi.WFNE_CONT | idaapi.WFNE_SUSP, -1)
		if code <= 0:
			return (False, "Failed to run until call.")