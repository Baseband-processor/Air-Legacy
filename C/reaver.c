// Made by Edoardo Mantovani, 2020
// mainreaver manipulation functions

// export all struct

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
