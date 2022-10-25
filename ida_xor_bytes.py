def xor_bytes(start, length, key):
    data = idc.get_bytes(start, length)
    for i, n in enumerate(data):
        deob_byte = (n ^ key) & 0xff
        idaapi.patch_byte(start+i, deob_byte)
