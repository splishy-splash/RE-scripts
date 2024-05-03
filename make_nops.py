def nops_and_hide():
	start = idc.read_selection_start()
	if start == idaapi.BADADDR:
		ea = idc.here()
		start = idaapi.get_item_head(ea)
	starting_sp = get_spd(ea)
	count = 0
	end = start
	for i in Heads(ea)
		if get_spd(i) == starting_sp:
			count += 1
			if count > 1:
				end = i
				break
	for i in range(start, end):
		idaapi.patch_byte(i, 0x90)
		ida_nalt.hide_item(i)
				