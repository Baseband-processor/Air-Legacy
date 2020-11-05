// Made by Edoardo Mantovani, 2020
// mainreaver manipulation functions

// export all struct

#include "reaver.h"
#define TIMESTAMP_LEN 64
#define LIBWPS_MAX_STR_LEN 256

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


struct association_response_management_frame *assoc_response_meta()
{
	struct association_response_management_frame *c =  (struct association_response_management_frame *) malloc(sizeof(struct association_response_management_frame));
	c->capability = NULL;
	c->status = NULL;
	c->id = NULL;
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

struct association_request_management_frame *assoc_request_meta()
{
	struct association_request_management_frame *c =  (struct association_request_management_frame *) malloc(sizeof(struct association_request_management_frame));
	c->capability = NULL;
	c->listen_interval = NULL;
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


struct beacon_management_frame *beacon_management_meta()
{
	struct beacon_management_frame *c =  (struct beacon_management_frame *) malloc(sizeof(struct beacon_management_frame));
	c->capability = NULL;
	c->beacon_interval = NULL;
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

/*
