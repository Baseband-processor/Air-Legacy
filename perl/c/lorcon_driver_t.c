/*
 * $Id: lorcon_driver_t.c 31 2015-02-17 07:04:36Z gomor $
 *
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
lorcon_driver_t_c2sv(NetLorconDriver *entry)
{
   HV *out     = newHV();
   SV *out_ref = newRV_noinc((SV *)out);

   //printf("DEBUG: name: %s\n", entry->name);
   //printf("DEBUG: details: %s\n", entry->details);
   hv_store(out, "name",    4, newSVpv(entry->name, 0), 0);
   hv_store(out, "details", 7, newSVpv(entry->details, 0), 0);

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
