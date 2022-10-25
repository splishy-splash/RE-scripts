# Single byte key.
def xor_bytes(start, length, key):
    data = idc.get_bytes(start, length)
    for i, n in enumerate(data):
        deob_byte = (n ^ key) & 0xff
        idaapi.patch_byte(start+i, deob_byte)

        
# Newer version that takes multi-byte keys. Key should look like 'deadbeef'. Using spaces like 'de ad be ef' *probably* works too (untested).
def xor_multi_byte(start, length, key):
    data = idc.get_bytes(start, length)
	xor_key = bytes.fromhex(key)
	for i, n in enumerate(data):
	    deob_byte = (n ^ xor_key[i % len(xor_key)]) & 0xff
		idaapi.patch_byte(start+i, deob_byte)
