#ifndef __REAVER_H
#define __REAVER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#ifndef LE16_DEFINED
#define LE16_DEFINED
typedef uint16_t le16;
typedef uint32_t le32;
#endif

struct association_request_management_frame *assoc_request_meta();
struct association_response_management_frame *assoc_response_meta();
struct beacon_management_frame *beacon_management_meta();
struct authentication_management_frame *auth_management_meta();
struct libwps_data *libwps_meta();
struct libwps_data *get_wps();
uint16_t  get_ap_capability();

#endif
