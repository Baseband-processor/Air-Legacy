// Made by Edoardo Mantovani, 2020
// Simple COWPAtty interface

#include <sys/types.h>

typedef struct hashdb_head
{
	uint32_t magic;
	uint8_t reserved1[3];
	uint8_t ssidlen;
	uint8_t ssid[32];
}HASHDB;

struct hashdb_rec
{
	uint8_t rec_size;
	char * word;
	uint8_t pmk[32];
} __attribute__((packed));

typedef struct hashdb_rec HASHDB_REC;

struct cowpatty_file
{
	char ssid[33];
	FILE * fp;
	char error[256 - sizeof(FILE *) - 33];
}COWPA_FILE;

hashdb_head *spawn_hashdb(){
  hashdb_head *COW_database =  ( hashdb_head *)malloc( hashdb_head *);
  COW_database->magic = 0x43575041;
  COW_database->ssid = NULL;
  return COW_database;
}

hashdb_head *spawn_ssid_hashdb(uint8_t ssid){
  hashdb_head *COW_database =  ( hashdb_head *)malloc( hashdb_head *);
  COW_database->ssid = ssid;
  return COW_database;
}

int set_hashdb_ssid(hashdb_head *COW_database, uint8_t ssid){
  if( !(ssid) || !( hashdb_head) ){
    return -1;
  }else{
    COW_database->ssid = ssid;
    COW_database->ssidlen = strlen(ssid);
    return 1;
  }
}

