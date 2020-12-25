// Made by Edoardo Mantovani, 2020
// Simple aircrack-ng's struct. spawn


#define MAX_KEYS_PER_CRYPT_SUPPORTED 16
#define CACHELINE_SIZE 64

#define CACHELINE_PADDED_FIELD(T, name, length, cacheline_size)                \
	T name[(length)];                                                          \
	uint8_t name##_padding[(cacheline_size)                                    \
						   - ((length * sizeof(T)) % (cacheline_size))]

#pragma pack(push, 1)
struct ac_crypto_engine_perthread
{
	CACHELINE_PADDED_FIELD(wpapsk_hash,
						   pmk,
						   MAX_KEYS_PER_CRYPT_SUPPORTED,
						   CACHELINE_SIZE);
	
	CACHELINE_PADDED_FIELD(uint8_t,
						   hash1,
						   (64 + 20) * MAX_KEYS_PER_CRYPT_SUPPORTED,
						   CACHELINE_SIZE);
	
};

#define MAX_THREADS 32

struct ac_crypto_engine{
	uint8_t ** essid;
	uint32_t essid_length;

	ac_crypto_engine_perthread * thread_data[MAX_THREADS];
 }
 
 ac_crypto_engine *spawn_crypto_engine(){
     ac_crypto_engine * crypto_eng = malloc(ac_crypto_engine *);
     crypto_eng->essid = NULL;
     crypto_eng->essid = NULL;

 }
