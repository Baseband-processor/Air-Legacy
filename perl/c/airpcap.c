// Made by Edoardo Mantovani, 2020

#include "airpcap.h"
#include <linux/nl80211.h>

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
    
    
    
    
