#include <stdint.h>
#include <lorcon2/lorcon.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// boilerplate

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

// adapted by Edoardo Mantovani, 2020

void 
apitest_packet_hdlr(lorcon_t *context, lorcon_packet_t *packet,  u_char *user) {
	u_char *dot3;
	int len;

	printf("apitest - %s drv %s got packet len %d\n", lorcon_get_capiface(context), lorcon_get_driver_name(context), packet->length);

	if (packet->length_header != 0) {
		printf("decoded length %d\n", packet->length_header);
	}

	if (packet->length_data != 0) {
		printf("decoded data length %d\n", packet->length_data);
	}

	len = lorcon_packet_to_dot3(packet, &dot3);

	printf("dot3 length %d\n", len);

	Safefree(dot3);

	lorcon_packet_free(packet);
}

