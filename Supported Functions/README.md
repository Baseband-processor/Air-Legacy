actually Working functions
================================================
- [x] is_compatible_with_formal_logic
- [x] lorcon_get_version
- [x] lorcon_list_drivers
- [x] lorcon_find_driver
- [x] lorcon_create
- [x] lorcon_free_driver_list
- [x] lorcon_free
- [x] lorcon_set_timeout
- [x] lorcon_get_timeout
- [x] lorcon_open_monitor
- [x] lorcon_open_injmon
- [x] lorcon_set_vap
- [x] lorcon_get_vap
- [x] lorcon_get_capiface
- [x] lorcon_auto_driver
- [x] lorcon_get_driver_name
- [x] lorcon_get_error
- [x] lorcon_packet_from_pcap
- [x] lorcon_open_inject
- [x] lorcon_send_bytes
- [x] lorcon_get_useraux
- [x] lorcon_set_useraux
- [x] lorcon_packet_free
- [x] lorcon_packet_decode

**still not tested**

      lorcon_packet_set_channel
      lorcon_packet_get_channel
      lorcon_packet_txprep_by_ctx
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
      lorcon_breakloop
      lorcon_set_filter
      lorcon_next_ex
      lorcon_parse_ht_channel
      lorcon_get_selectable_fd
      lorcon_packet_set_freedata
      lorcon_set_compiled_filter
      lorcon_get_pcap
      drv_madwifing_init
      drv_madwifing_listdriver
      lorcon_close
      lorcon_inject
      lorcon_add_wepkey
      aj_xmitframe
      aj_setmac
      aj_setchannel
      aj_setmode
      aj_setmonitor
      _lorcon_copy_driver
      lorcon_set_channel
      lorcon_get_channel
      lorcon_airjack_listdriver
      lorcon_airjack_init
      iwconfig_set_mode
      iwconfig_get_mode
      iwconfig_set_channel
      iwconfig_get_channel
      iwconfig_get_name
      iwconfig_get_ssid
      iwconfig_set_ssid
      iwconfig_set_intpriv
      nl80211_find_parent
      nl80211_setfrequency_cache
      nl80211_setfrequency
      nl80211_setchannel
      nl80211_setchannel_cache
      nl80211_createvif
      nl80211_disconnect
      nl80211_connect
      tx80211_airpcap_capabilities
      tx80211_airpcap_init 
      drv_file_listdriver
      drv_rtfile_init
      drv_file_init
      drv_tuntap_listdriver
      drv_tuntap_init
      tx80211_hostap_capabilities
      tx80211_hostap_init
      tx80211_mac80211_capabilities
      drv_mac80211_listdriver
      drv_mac80211_init
      mac80211_ifconfig_cb
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
      madwifing_getmac_cb
      madwifing_setmac_cb
      madwifing_sendpacket
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
      lcpf_80211headers
      lcpf_qos_data
      lcpf_beacon
      lcpf_deauth
      lcpf_add_ie
      lcpf_disassoc
      lcpf_probereq
      lcpf_proberesp
      lcpf_rts
      lcpf_80211ctrlheaders
      lcpf_authreq
      lcpf_authresq
      lcpf_assocreq
      lorcon_packet_get_interface
      lorcon_packet_get_llc_type
      lorcon_packet_get_bssid_mac
      lorcon_packet_get_dest_mac
      lorcon_packet_get_source_mac
      lorcon_packet_get_dot3_extra
      lorcon_packet_get_dot11_extra
      lorcon_packet_from_dot3
      lorcon_packet_to_dot3
      lorcon_packet_set_mcs
      lorcon_packet_from_lcpa
      Open_Monitor
      Open_Inject
      Open_Injmon
      Inject_Frame
      Send_Bytes
      ChangeMAC
      add_WEPKey
      tuntap_openmon_cb
      tuntap_sendbytes
      lcpa_freeze
      lcpa_size
      Packet_to_hex
      Hex_to_packet
      wginj_send
      tx80211_getcardlist
      tx80211_freecardlist
      drv_mac80211_probe
      drv_file_probe
      mac80211_openmon_cb
      mac80211_setchan_cb
      Detect_Driver
      rtfile_pcap_handler
      file_openmon_cb
      tx80211_rt61_init
      tx80211_rt61_capabilities
      rt61_open
      tx80211_prism54_init
      tx80211_prism54_capabilities
      Channel_to_Frequency
      Frequency_to_Channel      
      channel_to_frequency_HASH
      dissociation_reason_codes_HASH
      association_reason_codes_HASH
      wginj_close
      wginj_open
      mac80211_sendpacket
      nl80211_get_chanlist
      nl80211_error_cb
      bcm43xx_close
      bcm43xx_open
      tx80211_bcm43xx_init
      pcap_get_selectable_fd
      pcap_datalink
      pcap_sendpacket
      pcap_inject
      pcap_can_set_rfmon      
      lorcon_multi_loop
      madwifing_openmon_cb   
      wginj_getchannel
      wginj_setchannel
      wginj_getmode
      wginj_setmode
      tx80211_wlanng_capabilities
      tx80211_wlanng_init     
      tx80211_initpacket
      tx80211_setlocaldlt
      tx80211_getdlt
      tx80211_getdrivername
      tx80211_init
      tx80211_airjack_capabilities
      tx80211_rtl8180_init
      tx80211_get_capabilities
      pcap_set_rfmon
      tx80211_txpacket
      tx80211_setmodulation
      tx80211_getmodulation
      tx80211_setfunctionalmode
      tx80211_setchannel
      tx80211_getchannel
      tx80211_open
      tx80211_close
      tx80211_decodepkt
      nl80211_ack_cb
      floatchan2int
      iwfreq2float
      sha1_process
      sha1_update
      sha1_finish
      sha1_starts
      sha1_hmac_starts
      sha1_hmac_update
      sha1_hmac_finish
      sha1_hmac  
      iwconfig_get_intpriv
      iwconfig_set_charpriv
      tx80211_rt2570_init
      tx80211_rt2570_capabilities
      rt2570_open
      rt2570_send
      tx80211_rt73_init
      tx80211_rt73_capabilities
      rt73_open
      rt73_close
      tx80211_rt2500_init
      tx80211_rt2500_capabilities
      rt2500_open
      rt2500_close
      aj_setnonblock
      aj_getnonblock
      aj_getsocket
      aj_ifupdown
      lorcon_supported_cards
      lorcon_actual_cards
      tx80211_selfack 
      tx80211_gettxrate 
      tx80211_settxrate 
      tx80211_setfunctionalmode 
      tx80211_getmode 
      tx80211_resolvecard 
      tx80211_resolveinterface 
      tx80211_geterrstr 
      tx80211_setmode
      FindLinkage
      tx80211_meta 
      tx80211_packet_meta 
      filter_dissociation_codes
      filter_association_codes
      tx80211_decodepkt
      ajinj_open  
      ajinj_close 
      sha1_process
      sha1_update
      sha1_finish
      sha1_starts
      sha1_hmac_starts
      sha1_hmac_update
      sha1_hmac_finish
      sha1_hmac
      sha1_meta
      sha1_hmac_meta 
      build_radio_tap_header
      get_wps
      get_ap_capability
      set_channel
      get_channel
      set_bssid
      build_wps_probe_request
      build_association_management_frame
      build_authentication_management_frame
      build_snap_packet
      build_eap_packet
      auth_management_meta
      beacon_management_meta
      assoc_response_meta
      assoc_request_meta
      build_dot1X_header
      build_eapol_start_packet
      build_eap_failure_packet
      build_tagged_parameter
      build_wps_tagged_parameter
      reaver_inject
      packet_crc 
      packet_entropy
      wps_data_to_json
      libwps_meta
      send_generic_packet 
      send_packet_internal
      lcpf_assocresp
      lcpf_data
      lcpf_qosheaders
      spawn_crypto_engine
      ac_crypto_engine_supported_features
      ac_crypto_engine_init
      ac_crypto_engine_destroy
      ac_crypto_engine_set_essid
      ac_crypto_engine_thread_init
      ac_crypto_engine_thread_destroy
      ac_crypto_init
      decrypt_wep
      encrypt_wep
      ac_crypto_engine_loader_flags_to_string
      ac_crypto_engine_loader_load
      ac_crypto_engine_loader_unload
      spawn_hashdb
      spawn_ssid_hashdb
      set_hashdb_ssid
      close_free_cowpatty_hashdb
      open_cowpatty_hashdb
      read_next_cowpatty_record
      wait_for_beacon
      capture_ask_packet
      filter_packet
      create_wep_packet
      inject_tcp
      wi_read
      wi_write
      wi_set_channel
      wi_get_channel 
      wi_get_freq
      wi_set_freq
      wi_get_monitor
      wi_get_ifname
      wi_close
      mw_to_dbm
      dbm_to_mw
       
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
