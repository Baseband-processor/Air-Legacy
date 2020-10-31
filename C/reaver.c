// Made by Edoardo Mantovani, 2020
// mainreaver manipulation functions

// export all struct

typedef struct association_request_management_frame{
	le16 capability;
	le16 listen_interval;
}ASSOCIATION_REQUEST_MANAGEMENT_FRAME;


struct association_response_management_frame{
	le16 capability;
	le16 status;
	le16 id;
}ASSOCIATION_RESP_MANAGEMENT_FRAME;

struct  beacon_management_frame{
	unsigned char timestamp[TIMESTAMP_LEN];
	le16 beacon_interval;
	le16 capability;
}BEACON_MANAGEMENT_FRAME;


struct {
	int proto;
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int capabilities;
	size_t num_pmkid;
	const u8 *pmkid;
	int mgmt_group_cipher;
}wpa_ie_data;

typedef struct wpa_ie_data        WPA_IE_DATA;

struct authentication_management_frame{
	le16 algorithm;
	le16 sequence;
	le16 status;
}AUTH_MANAGEMENT_FRAME;
