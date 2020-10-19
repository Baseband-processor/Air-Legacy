// Made by Edoardo Mantovani, 2020
// this file is still under development, probably will be converted into XS for perl library

#include "cfg80211_control.h"

void convert_key_from_CPU(struct brcmf_wsec_key *key, struct brcmf_wsec_key_le *key_length){
	key_length->index = cpu_to_le32(key->index);
	key_length->len = cpu_to_le32(key->len);
	key_length->algo = cpu_to_le32(key->algo);
	key_length->flags = cpu_to_le32(key->flags);
	key_length->rxiv.hi = cpu_to_le32(key->rxiv.hi);
	key_length->rxiv.lo = cpu_to_le16(key->rxiv.lo);
	key_length->iv_initialized = cpu_to_le32(key->iv_initialized);
	memcpy(key_length->data, key->data, sizeof(key->data));
	memcpy(key_length->ea, key->ea, sizeof(key->ea));
}
