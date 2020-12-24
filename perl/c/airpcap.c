// Made by Edoardo Mantovani, 2020

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include <netlink/route/addr.h>
#include <netlink/route/link.h>


#include "airpcap.h"
#include "../../C/nl80211.h"

static int
nl80211_state_init(PAirpcapHandle handle, PCHAR Ebuf)
{
    handle->nl_socket = nl_handle_alloc();
    /* Allocate the netlink socket.
     */
    if (NULL == handle->nl_socket) {
        setebuf(Ebuf, "Failed to allocate netlink socket.");
        return -1;
    }
    /* Connect to the generic netlink.
     */
    if (genl_connect(handle->nl_socket)) {
        setebuf(Ebuf, "Failed to connect to generic netlink.");
        goto err;
    }

    if (genl_ctrl_alloc_cache(handle->nl_socket,
                              &handle->nl_cache)) {
        setebuf(Ebuf, "Failed to allocate generic netlink cache.");
        goto err;
    }

    /* Find and get a reference to the nl80211 family.
     * Must hand back the reference via genl_family_put. */
    handle->nl80211 = genl_ctrl_search_by_name(handle->nl_cache,
                                               "nl80211");
    if (NULL == handle->nl80211) {
        setebuf(Ebuf, "Netlink module nl80211 not found.");
        goto err;
    }

    if (0 != ifconfig_get_hwaddr(handle->master_ifname,
                                 (uint8_t *)handle->mac.Address)) {
        setebuf(Ebuf, "Failed to get hardware address: %s",
                strerror(errno));
        goto err;
    }

    return 0;

err:
    if (handle->nl80211)
        genl_family_put(handle->nl80211);
    if (handle->nl_cache)
        nl_cache_free(handle->nl_cache);
    if (handle->nl_socket)
        nl_handle_destroy(handle->nl_socket);

    return -1;
}

int
nl80211_device_init(PAirpcapHandle handle, PCHAR Ebuf)
{
    int err;
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    if (!msg) {
        setebuf(Ebuf, "Error allocating netlink message.");
        return -1;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                genl_family_get_id(handle->nl80211), 0,
                /* Get wireless PHY information. */
                /* Why does iw set NLM_F_DUMP here and
                 * still get only one interface?
                 * Even if I do NLM_F_MATCH with
                 * NL80211_ATTR_IFINDEX, I get every
                 * PHY.  Only 0 works here... */
                0, NL80211_CMD_GET_INTERFACE, 0);

    /* We refer to the device by its interface index, not by
     * the PHY interface. */
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, handle->ifindex);

    struct airpcap_interface_dump_data data;
    data.start = NULL;
    data.current = NULL;
    
    err = nl_send_and_recv(handle->nl_socket, msg,
                           interface_dump_handler, &data);
    if (err < 0) {
        setebuf(Ebuf, "Error getting device information from netlink: %s",
                strerror(-err));
    }
    if (NULL == data.start) {
        printf("No matching wiphy...\n");
    } else {
        struct airpcap_interface_list *iface = data.start;
        handle->phyindex = iface->phyindex;
        
        if (0 != nl80211_get_wiphy(handle->nl_socket,
                                   handle->nl80211,
                                   handle)) {
            /* TODO: free memory */
            printf("error getting wiphy: %s\n", handle->last_error);
        }
    }
    struct airpcap_interface_list *iface = data.start;
    while (NULL != iface) {
        struct airpcap_interface_list *next = iface->next;
        free(iface);
        iface = next;
    }

    /* TODO : NL80211_CMD_GET_STATION for NL80211_ATTR_WIPHY_FREQ ? */

    return err;
   }
   
   int nl80211_create_monitor(PAirpcapHandle handle, PCHAR Ebuf)
{
    struct nl_msg *msg;
    int err;

    /* Check if this interface already exists. */
    handle->monitor_ifindex = if_nametoindex(handle->monitor_ifname);
    if (0 != handle->monitor_ifindex) {
        /* TODO: Check to make sure it is the correct wiphy and
         * already in IFTYPE_MONITOR */
        return 0;
    }
    
    msg = nlmsg_alloc();
    if (NULL == msg) {
        setebuf(Ebuf, "Failed to allocate netlink message.");
        return -1;
    }
    
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                genl_family_get_id(handle->nl80211), 0, 0, 
                NL80211_CMD_NEW_INTERFACE, 0);

    NLA_PUT_U32(msg,    NL80211_ATTR_IFINDEX, handle->ifindex);
    NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, handle->monitor_ifname);
    NLA_PUT_U32(msg,    NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

    err = nl_send_and_recv(handle->nl_socket, msg,
                           cmd_new_interface_handler,
                           NULL);

    /* PROTIP: If you get -ENFILE (-23 / Too many open files in system),
     * it's (likely) because the interface already exists.
     * Why doesn't it return -EEXIST?!
     */
    if (err < 0) {
    nla_put_failure:
        setebuf(Ebuf, "Failed to create monitor interface %s from %s: %s",
                handle->monitor_ifname,
                handle->master_ifname,
                strerror(-err));
        return -1;
    }

    /* Save this ifindex */
    handle->monitor_ifindex = if_nametoindex(handle->monitor_ifname);
    if (0 == handle->monitor_ifindex) {
        setebuf(Ebuf,
                "nl80211_create_monitor() thought we made a "
                "monitor interface, but it wasn't there when we looked");
        return -1;
    }
    
    return 0;
    }
    
int nl80211_destroy_monitor(PAirpcapHandle handle)
{
    unsigned monitor_ifindex = if_nametoindex(handle->monitor_ifname);
    if (0 != monitor_ifindex) {
        /* NL80211_CMD_DEL_INTERFACE
         *  - NL80211_ATTR_IFINDEX
         */
        struct nl_msg *msg;
        int err;

        msg = nlmsg_alloc();
        if (NULL == msg) {
            setebuf(handle->last_error, "Failed to allocate netlink message.");
            return -1;
        }
    
        genlmsg_put(msg, 0, 0,//NL_AUTO_PID, NL_AUTO_SEQ,
                    genl_family_get_id(handle->nl80211), 0, 0, 
                    NL80211_CMD_DEL_INTERFACE, 0);

        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, monitor_ifindex);

        err = nl_send_and_recv(handle->nl_socket, msg,
                               cmd_del_interface_handler,
                               NULL);

        if (err < 0) {
        nla_put_failure:
            /* -ESRCH == "No such process"...? if ifindex cannot be found */
            setebuf(handle->last_error,
                    "Failed to delete monitor interface %s(%u): %s",
                    handle->monitor_ifname, monitor_ifindex,
                    strerror(-err));
            return -1;
        }

        handle->monitor_ifindex = 0;
        return 0;
    }
    return -2;
    }
    
PAirpcapDeviceDescription
nl80211_get_all_devices(PCHAR Ebuf)
{
    int err = 0;
    struct nl_msg *msg;
    struct nl_handle *sock = NULL;
    struct nl_cache *cache = NULL;
    struct genl_family *nl80211 = NULL;
    PAirpcapDeviceDescription desc_start = NULL, desc_current;

    sock = nl_handle_alloc();
    /* Allocate the netlink socket.
     */
    if (NULL == sock) {
        setebuf(Ebuf, "Failed to allocate netlink socket.");
        goto Lerr;
    }
    /* Connect to the generic netlink.
     */
    if (genl_connect(sock)) {
        setebuf(Ebuf, "Failed to connect to generic netlink.");
        goto Lerr;
    }
    if (genl_ctrl_alloc_cache(sock, &cache)) {
        setebuf(Ebuf, "Failed to allocate generic netlink cache.");
        goto Lerr;
    }

    /* Find and get a reference to the nl80211 family.
     * Must hand back the reference via genl_family_put. */
    nl80211 = genl_ctrl_search_by_name(cache, "nl80211");
    if (NULL == nl80211) {
        setebuf(Ebuf, "Netlink module nl80211 not found.");
        goto Lerr;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        setebuf(Ebuf, "Error allocating netlink message.");
        goto Lerr;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                genl_family_get_id(nl80211), 0,
                /* Get ALL wireless PHY information. */
                NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0);

    /* Build up the list */
    struct airpcap_interface_dump_data data;
    data.start   = NULL;
    data.current = NULL;

    err = nl_send_and_recv(sock, msg, interface_dump_handler, &data);
    if (err < 0) {
        setebuf(Ebuf, "Error getting interface information from netlink: %s",
                strerror(-err));
    }

    for (struct airpcap_interface_list *iface = data.start; NULL != iface; iface = iface->next) {
        PAirpcapDeviceDescription desc;
        PAirpcapHandle temp_handle = NULL;
        char ifname[IF_NAMESIZE];
        PCHAR d;

        if (NULL == if_indextoname(iface->ifindex, ifname)) {
            printf("BAD!!!\n");
            continue;
        }

        desc = (PAirpcapDeviceDescription)malloc(sizeof(*desc));
        desc->next = NULL;

        /* Update the list */
        if (NULL == desc_start) {
            desc_start = desc_current = desc;
        } else {
            desc_current->next = desc;
            desc_current = desc;
        }

        temp_handle = airpcap_handle_new();
        temp_handle->phyindex = iface->phyindex;
        if (0 != nl80211_get_wiphy(sock, nl80211, temp_handle)) {
            /* TODO: free memory, etc... */
            printf("error getting wiphy: %s\n", temp_handle->last_error);
            strncpy(Ebuf, temp_handle->last_error, AIRPCAP_ERRBUF_SIZE);
            return NULL;
        }

        desc->Name = strndup(ifname, IF_NAMESIZE);
        desc->Description = (PCHAR)malloc(512);
        
        /* Assign Description member based on what
         * Airpcap device we are going to "emulate".
         *
         * This should hopefully someday be filled in with better
         * information about the adapter or driver from the
         * mac80211 / nl80211 layer. */
        switch (temp_handle->cap.AdapterId) {
        case AIRPCAP_ID_N:
        case AIRPCAP_ID_NX:
            d = "Airpcap NX emulation (802.11n)";
            break;

        case AIRPCAP_ID_TX:
            d = "Airpcap TX emulation (802.11bg)";
            break;

        case AIRPCAP_ID_CLASSIC:
            d = "Airpcap Classic emulation (802.11bg)";
            break;

        default:
            d = "BUG: Unspecified Airpcap emulation";
            break;
        }

        strncpy(desc->Description, d, 512);
        if (temp_handle->cap.SupportedBands & AIRPCAP_BAND_5GHZ) {
            size_t s = strlen(desc->Description);
            strncat(desc->Description,
                    " (5 GHz)", 512 - s);
        }
        /* Free the temporary handle. */
        airpcap_handle_free(temp_handle);
    }
    struct airpcap_interface_list *iface = data.start;
    while (NULL != iface) {
        struct airpcap_interface_list *next = iface->next;
        free(iface);
        iface = next;
    }

Lerr:
    if (nl80211)
        genl_family_put(nl80211);
    if (cache)
        nl_cache_free(cache);
    if (sock)
        nl_handle_destroy(sock);

    if (err < 0) {
        return NULL;
    } else {
        return desc_start;
    }
}
 
PAirpcapHandle AirpcapOpen(PCHAR DeviceName, PCHAR Ebuf){
    PAirpcapHandle handle;

    if (NULL != Ebuf) {
        Ebuf[0] = 0;
    }

    unsigned ifindex = if_nametoindex((char *)DeviceName);
    if (ifindex <= 0) {
        setebuf(Ebuf, "Invalid device specified.");
        return NULL;
    }

    handle = airpcap_handle_new();
    if (NULL == handle) {
        setebuf(Ebuf, "Error allocating handle.");
        return NULL;
    }
    /* Assign interface index after allocation. */
    handle->ifindex = ifindex;
    /* FIXME: handle if name + "mon" is too long for IF_NAMESIZE. */
    strncpy(handle->master_ifname, DeviceName, IF_NAMESIZE);

    /* Initialize unique netlink/nl80211 connection and
     * state for this handle. */
    if (-1 == nl80211_state_init(handle, Ebuf)) {
        return NULL;
    }
    /* FIXME: proper deallocation. */
    if (-1 == nl80211_device_init(handle, Ebuf)) {
        return NULL;
    }
    /* if (-1 == nl80211_create_monitor(handle, Ebuf)) { */
    /*     return NULL; */
    /* } */
    /* By default, we must set to accept everything, as noted is the default.
     */
    if (-1 == nl80211_set_monitor(handle, AIRPCAP_VT_ACCEPT_EVERYTHING, Ebuf)) {
        /* We might as well just call close here, since
         * all state is essentially allocated and ready.
         */
        AirpcapClose(handle);
        return NULL;
    }

    /* Finally, bring the device up (and leave it up - do not bring
     * down the interface in AirpcapClose!). */
    if (-1 == ifconfig_ifupdown(handle->master_ifname, 1)) {
        setebuf(Ebuf, "Unable to bring interface up: %s", strerror(errno));
        AirpcapClose(handle);
        return NULL;
    }
    
    if (FALSE == AirpcapSetDeviceChannel(handle, 6)) {
        if (NULL != Ebuf) {
            strncpy(Ebuf, handle->last_error, AIRPCAP_ERRBUF_SIZE);
            Ebuf[AIRPCAP_ERRBUF_SIZE] = 0;
        }
        AirpcapClose(handle);
        return NULL;
    }

    return handle;
}
