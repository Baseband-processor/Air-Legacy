// Made by Edoardo Mantovani, 2020
// mainreaver manipulation functions

// export all struct

#include "reaver.h"
#define TIMESTAMP_LEN 64
#define LIBWPS_MAX_STR_LEN 256
#define P1_SIZE			10000
#define P2_SIZE	1000

struct libwps_data{
        uint8_t version;
        uint8_t state;
        uint8_t locked;
        char manufacturer[LIBWPS_MAX_STR_LEN];
        char model_name[LIBWPS_MAX_STR_LEN];
        char model_number[LIBWPS_MAX_STR_LEN];
        char device_name[LIBWPS_MAX_STR_LEN];
        char ssid[LIBWPS_MAX_STR_LEN];
        char uuid[LIBWPS_MAX_STR_LEN];
        char serial[LIBWPS_MAX_STR_LEN];
        char selected_registrar[LIBWPS_MAX_STR_LEN];
        char response_type[LIBWPS_MAX_STR_LEN];
        char primary_device_type[LIBWPS_MAX_STR_LEN];
        char config_methods[LIBWPS_MAX_STR_LEN];
        char rf_bands[LIBWPS_MAX_STR_LEN];
        char os_version[LIBWPS_MAX_STR_LEN];
};

struct globule{
        int last_wps_state;             
        int p1_index;                   
        int p2_index;                   
        char *p1[P1_SIZE];              
        char *p2[P2_SIZE];              
	char *static_p1;			
	char *static_p2;		
	int use_pin_string;		
        //enum *key_state key_status;      
	int dh_small;			
	int external_association;	
	int oo_send_nack;
	int win7_compat;
        int delay;                 
        int fail_delay;                
        int recurring_delay;            
	int lock_delay;			
	int ignore_locks;		
        int recurring_delay_count;	
        int eap_terminate;              
        int max_pin_attempts;           
        int rx_timeout;                 
        int timeout_is_nack;            
        int m57_timeout;                
        int out_of_time;                
	unsigned long long resend_timeout_usec;   
        //enum *debug_level debug;         
        int eapol_start_count;          
        int fixed_channel;              
	int auto_channel_select;
	int wifi_band;			
	int channel;			
	int repeat_m6;			
	int max_num_probes;		
	int validate_fcs;		
        //enum *wsc_op_code opcode;        
        uint8_t eap_id;                
        uint16_t ap_capability;         
        unsigned char bssid[MAC_ADDR_LEN];    
        unsigned char mac[MAC_ADDR_LEN];             
	unsigned char vendor_oui[1+3];	
	unsigned char *htcaps;		
	int htcaps_len;			
	unsigned char *ap_rates;	
	int ap_rates_len;		
	unsigned char *ap_ext_rates;	
	int ap_ext_rates_len;		
	FILE *fp;		
	char *session;			
        char *ssid;                     
        char *iface;                    
        char *pin;                      
	char *exec_string;		
        //enum *nack_code nack_reason;     
        pcap_t *handle;                 
	int output_fd;			
	uint64_t uptime;		
        struct libwps_data *wps;           
};

struct association_request_management_frame{
	le16 capability;
	le16 listen_interval;
};


struct association_response_management_frame{
	le16 capability;
	le16 status;
	le16 id;
};

struct  beacon_management_frame{
	unsigned char timestamp[TIMESTAMP_LEN];
	le16 beacon_interval;
	le16 capability;
};


struct authentication_management_frame{
	le16 algorithm;
	le16 sequence;
	le16 status;
};

// functions

struct association_request_management_frame *assoc_request_meta()
{
	struct association_request_management_frame *c =  (struct association_request_management_frame *) malloc(sizeof(struct association_request_management_frame));
	c->capability = NULL;
	c->listen_interval = NULL;
	return c;	
}




struct beacon_management_frame *beacon_management_meta()
{
	struct beacon_management_frame *c =  (struct beacon_management_frame *) malloc(sizeof(struct beacon_management_frame));
	c->capability = NULL;
	c->beacon_interval = NULL;
	return c;	
}

struct authentication_management_frame *auth_management_meta()
{
	struct authentication_management_frame *c =  (struct authentication_management_frame *) malloc(sizeof(struct authentication_management_frame));
	c->sequence = NULL;
	c->status = NULL;
	c->algorithm = NULL;
	return c;	
}




struct association_response_management_frame *assoc_response_meta()
{
	struct association_response_management_frame *c =  (struct association_response_management_frame *) malloc(sizeof(struct association_response_management_frame));
	c->capability = NULL;
	c->status = NULL;
	c->id = NULL;
	return c;	
}



struct libwps_data *libwps_meta()
{
	struct libwps_data *c =  (struct libwps_data *) malloc(sizeof(struct libwps_data));
	return c;
}

/*
int free_authentication_management_frame(struct authentication_management_frame *c)
{
	free(c);
	return 1;	
}

int free_association_response_management_frame(struct association_response_management_frame *c)
{
	free(c);
	return 1;	
}

int free_association_request_management_frame(struct association_request_management_frame *c)
{
	free(c);
	return 1;	
}

int free_authentication_management_frame(struct authentication_management_frame *c)
{
	free(c);
	return 1;	
}

int free_association_request_management_frame(struct association_request_management_frame *c)
{
	free(c);
	return 1;
}


int free_association_response_management_frame(struct association_response_management_frame *c)
{
	free(c);
	return 1;
}



int free_beacon_management_frame(struct beacon_management_frame *c)
{
	free(c);
	return 1;
}

*/

struct libwps_data *get_wps(){
	struct globule *ret;
	return( ret->wps );
}
	
