actually Working functions
================================================

      lorcon_list_drivers
      lorcon_find_driver
      lorcon_set_datalink
      lorcon_get_datalink
      lorcon_create
      lorcon_free_driver_list
      lorcon_free
      lorcon_set_timeout
      lorcon_get_timeout
      lorcon_open_monitor
      lorcon_open_injmon
      lorcon_set_vap
      lorcon_get_vap
      lorcon_get_capiface
      lorcon_auto_driver
      lorcon_get_driver_name
      lorcon_get_error
      lorcon_open_inject
      lorcon_send_bytes
      lorcon_get_useraux
      lorcon_set_useraux
      lorcon_packet_free
      lorcon_packet_decode
      lorcon_packet_set_channel
      lorcon_packet_get_channel
      lorcon_loop 
      lorcon_packet_to_dot3
      lorcon_set_hwmac
      lorcon_get_hwmac
      lorcon_multi_remove_interface_error_handler
      lorcon_multi_interface_get_lorcon
      lorcon_multi_get_next_interface
      lorcon_multi_get_interfaces
      lorcon_multi_del_interface
      lorcon_multi_add_interface
      lorcon_multi_free
      lorcon_multi_create
      lorcon_get_complex_channel 
      lorcon_set_complex_channel
      lorcon_ifdown
      locon_packet_get_bssid_mac
      lorcon_packet_get_dest_mac
      lcpf_randmac
      lorcon_packet_get_source_mac
      lorcon_ifup
      lorcon_packet_from_dot3
      lorcon_packet_to_dot3
      lorcon_breakloop
      lorcon_set_filter
      lorcon_next_ex
      lorcon_parse_ht_channel
      lorcon_get_selectable_fd
      lorcon_packet_set_freedata
      lorcon_get_pcap
      drv_madwifing_init
      drv_madwifing_listdriver
      lorcon_close
      lorcon_inject
      lorcon_add_wepkey
      aj_recvframe
      aj_xmitframe
      aj_setmac
      aj_setchannel
      aj_setmode
      aj_setmonitor
      lorcon_airjack_listdriver
      lorcon_airjack_init
      iwconfig_set_mode
      iwconfig_get_mode
      iwconfig_set_channel
      iwconfig_get_channel
      iwconfig_get_name
      iwconfig_get_ssid
      iwconfig_set_ssid
      nl80211_find_parent
      nl80211_setfrequency_cache
      nl80211_setfrequency
      nl80211_setchannel
      nl80211_setchannel_cache
      nl80211_createvif
      nl80211_disconnect
      nl80211_connect
      airpcap_setmode
      airpcap_close
      airpcap_setfuncmode
      airpcap_send
      airpcap_open
      tx80211_airpcap_capabilities
      tx80211_airpcap_init 
      drv_file_listdriver
      drv_rtfile_init
      drv_file_init
      drv_tuntap_listdriver
      drv_tuntap_init
      tx80211_hostap_capabilities
      tx80211_hostap_init
      drv_mac80211_listdriver
      drv_mac80211_init
      RMAC_gen
      RString_Gen
      Create
      Version
      Close
      IWconfig
      lcpa_init
      lcpa_append
      lcpa_append_copy
      lcpa_insert
      lcpa_find_name
      lcpa_replace_copy
      lcpa_replace
      lcpa_free
      lcpa_size
      lcpa_freeze
      madwifing_list_vaps
      madwifing_free_vaps
      madwifing_destroy_vap
      madwifing_build_vap
      madwifing_setdevtype
      madwifing_find_parent
      ifconfig_get_sysdriver
      ifconfig_get_sysattr
      ifconfig_set_flags
      ifconfig_delta_flags
      ifconfig_get_flags
      ifconfig_get_hwaddr
      ifconfig_set_hwaddr
      ifconfig_set_mtu
      ifconfig_ifupdown
      wtinj_send
      wtinj_open
      wtinj_close
      wtinj_setchannel
      wtinj_getchannel
      wtinj_setmode
      wtinj_getmode
      wtinj_setfuncmode
      wtinj_selfack 
      tx80211_zd1211rw_init
      tx80211_zd1211rw_send
      tx80211_zd1211rw_capabilities

**TESTED AND WORKING**

- [x]      lorcon_list_drivers
- [x]      lorcon_find_driver
- [x]      lorcon_set_datalink
- [x]      lorcon_get_datalink
- [x]      lorcon_create
- [x]      lorcon_free_driver_list
- [x]      lorcon_free
- [x]      lorcon_set_timeout
- [x]      lorcon_get_timeout
- [x]      lorcon_open_monitor
- [x]      lorcon_open_injmon
- [x]      lorcon_set_vap
- [x]      lorcon_get_vap
- [x]      lorcon_get_capiface
- [x]      lorcon_auto_driver
- [x]      lorcon_get_driver_name
- [x]      lorcon_get_error
- [x]      lorcon_open_inject
- [x]      lorcon_send_bytes
- [x]      lorcon_airjack_init
- [x]      iwconfig_set_mode
- [x]      iwconfig_get_mode
- [x]      iwconfig_set_channel
- [x]      iwconfig_get_channel
- [x]      iwconfig_get_name
- [x]      iwconfig_get_ssid
- [x]      iwconfig_set_ssid
- [x]      drv_madwifing_init
- [x]      drv_madwifing_listdriver
- [x]      lorcon_close
- [x]      lorcon_inject
- [x]      lorcon_add_wepkey
- [x]      lorcon_ifup
- [x]      lorcon_ifdown
- [x]      drv_mac80211_listdriver
- [x]      drv_mac80211_init
- [x]      lorcon_multi_create
- [x]      nl80211_find_parent
- [x]      madwifing_find_parent
- [x]      lcpa_append
- [x]      lcpa_insert


**NOT WORKING FUNCTIONS**

- [ ]      lcpa_append_copy
- [ ]      wtinj_send
- [ ]      wtinj_open
- [ ]      wtinj_close
- [ ]     wtinj_setchannel
- [ ]      wtinj_getchannel
- [ ]     wtinj_setmode
- [ ]     wtinj_getmode
- [ ]     wtinj_setfuncmode
- [ ]      wtinj_selfac
- [ ]      tx80211_zd1211rw_init
	...

**NOTE:**

* the testing is still in progress, this file will updated daily with more in-dept results.

_Edoardo Mantovani, 2020_
