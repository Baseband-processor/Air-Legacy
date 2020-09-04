/*
 * $Id: lorcon_driver_t.c 31 2015-02-17 07:04:36Z gomor $
 *
	MODIFIED BY EDOARDO MANTOVANI
 * Copyright (c) 2010-2015 Patrice <GomoR> Auffret
 *
 * LICENSE
 *
 * This program is free software. You can redistribute it and/or modify it
 * under the following terms:
 * - the Perl Artistic License (in the file LICENSE.Artistic)
 *
 */

/*
 * struct lorcon_driver {
 *         char *name;
 *         char *details;
 * 
 *         lorcon_drv_init init_func;
 *         lorcon_drv_probe probe_func;
 * 
 *         struct lorcon_driver *next;
 * };
 */

SV *
lorcon_driver_t_c2sv(AirLorconDriver *entry)
{
   HV *out     = newHV();
   SV *out_ref = newRV_noinc((SV *)out);

   //printf("DEBUG: name: %s\n", entry->name);
   //printf("DEBUG: details: %s\n", entry->details);
   hv_store(out, "name",    4, newSVpv(entry->name, 0), 0);
   hv_store(out, "details", 7, newSVpv(entry->details, 0), 0);

   return out_ref;
}

/*
 *  struct lorcon_multi_t{
 *    	struct lorcon_multi_t *interfaces;
 *	char errstr[LORCON_STATUS_MAX];
 *  	AirLorconHandler handler_cb;
 *	void *handler_user;
 *	};
 *         
 */


SV *
lorcon_multi_t_c2sv(AirLorconMulti *entry)
{

  HV *out = newHV();
  SV *out_ref = newRV_noinc((SV *)out);

  hv_store(out, "interface", 4, newSVpv(entry->interfaces, 0), 0);
  hv_store(out, "handler_user", 7, newSVpv(entry->handler_user, 0), 0);
  return out_ref;
}



/*
*
* struct lorcon_packet_t{
*	TIME ts;
*	int dlt;
*	int channel;
*	int length;
*	int length_header;
*	int length_data;
*	LCPA_META *lcpa;
*	int free_data;
*	const u_char *packet_raw;
*	const u_char *packet_header;
*	const u_char *packet_data;
*	void *extra_info;
*	int extra_type;
*   	lorcon_t *interface;
*   	unsigned int set_tx_mcs;
*    	unsigned int tx_mcs_rate;
*    	unsigned int tx_mcs_short_guard;
*    	unsigned int tx_mcs_40mhz;
* }AirLorconPacket;

*/

SV *
lorcon_packet_t_c2sv(AirLorconPacket *entry) // print the channel, the data length, the raw_packet and the interface
{

  HV *out = newHV();
  SV *out_ref = newRV_noinc((SV *)out);
  printf("channel:  %s\n", entry->channel);
  hv_store(out, "channel", 4, newSVpv(entry->channel, 0), 0);
  printf("length data:  %s\n", entry->length_data);
  hv_store(out, "length_data", 7, newSVpv(entry->length_data, 0), 0);
  printf("extra_type:  %s\n", entry->extra_type);
  hv_store(out, "length_data", 7, newSVpv(entry->extra_type, 0), 0);
  printf("raw packet: %s\n", entry->packet_raw);
  hv_store(out, "packet_raw", 7, newSVpv(entry->packet_raw, 0), 0);
  hv_store(out, "interface", 7, newSVpv(entry->interface, 0), 0);
  return out_ref;
}

//static IntfEntry *
//intf_sv2c(SV *h, IntfEntry *ref)
//{
//   if (ref && h && SvROK(h)) {
//      HV *hv = (HV *)SvRV(h);
//      memset(ref, 0, sizeof(IntfEntry));
//      if (hv_exists(hv, "intf_len", 8)) {
//         SV **len      = hv_fetch((HV *)SvRV(h), "intf_len", 8, 0);
//         ref->intf_len = (SvOK(*len) ? SvIV(*len) : 0);
//      }
//      if (hv_exists(hv, "intf_name", 9)) {
//         SV **name = hv_fetch((HV *)SvRV(h), "intf_name", 9, 0);
//         if (SvOK(*name)) {
//            memcpy(&(ref->intf_name), SvPV(*name, PL_na),
//               sizeof(ref->intf_name));
//         }
//      }
//      if (hv_exists(hv, "intf_type", 9)) {
//         SV **type      = hv_fetch((HV *)SvRV(h), "intf_type", 9, 0);
//         ref->intf_type = (SvOK(*type) ? SvIV(*type) : 0);
//      }
//      if (hv_exists(hv, "intf_flags", 10)) {
//         SV **flags      = hv_fetch((HV *)SvRV(h), "intf_flags", 10, 0);
//         ref->intf_flags = (SvOK(*flags) ? SvIV(*flags) : 0);
//      }
//      if (hv_exists(hv, "intf_mtu", 8)) {
//         SV **mtu      = hv_fetch((HV *)SvRV(h), "intf_mtu", 8, 0);
//         ref->intf_mtu = (SvOK(*mtu) ? SvIV(*mtu) : 0);
//      }
//      if (hv_exists(hv, "intf_addr", 9)) {
//         SV **addr = hv_fetch((HV *)SvRV(h), "intf_addr", 9, 0);
//         if (SvOK(*addr)) {
//            struct addr a;
//            if (addr_aton(SvPV(*addr, PL_na), &a) == 0) {
//               memcpy(&(ref->intf_addr), &a, sizeof(struct addr));
//            }
//         }
//      }
//      if (hv_exists(hv, "intf_dst_addr", 13)) {
//         SV **dstAddr = hv_fetch((HV *)SvRV(h), "intf_dst_addr", 13, 0);
//         if (SvOK(*dstAddr)) {
//            struct addr a;
//            if (addr_aton(SvPV(*dstAddr, PL_na), &a) == 0) {
//               memcpy(&(ref->intf_dst_addr), &a, sizeof(struct addr));
//            }
//         }
//      }
//      if (hv_exists(hv, "intf_link_addr", 14)) {
//         SV **lnkAddr = hv_fetch((HV *)SvRV(h), "intf_link_addr", 14, 0);
//         if (SvOK(*lnkAddr)) {
//            struct addr a;
//            if (addr_aton(SvPV(*lnkAddr, PL_na), &a) == 0) {
//               memcpy(&(ref->intf_link_addr), &a, sizeof(struct addr));
//            }
//         }
//      }
//   }
//   else {
//      ref = NULL;
//   }
//
//   return ref;
//}
