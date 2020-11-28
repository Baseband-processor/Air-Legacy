#include <stdio.h>
#include <stdlib.h>

#define MAX_IFACE_NAME	64

struct tx_info {
        unsigned int     ti_rate;
};

struct rx_info {
        uint64_t ri_mactime;
        int32_t ri_power;
        int32_t ri_noise;
        uint32_t ri_channel;
        uint32_t ri_freq;
        uint32_t ri_rate;
        uint32_t ri_antenna;
} __packed;

struct wif {
        int     (*wi_read)(struct wif *wi, unsigned char *h80211, int len,
                           struct rx_info *ri);
        int     (*wi_write)(struct wif *wi, unsigned char *h80211, int len,
                            struct tx_info *ti);
        int     (*wi_set_channel)(struct wif *wi, int chan);
        int     (*wi_get_channel)(struct wif *wi);
        int     (*wi_set_freq)(struct wif *wi, int freq);
        int     (*wi_get_freq)(struct wif *wi);
	void	(*wi_close)(struct wif *wi);
	int	(*wi_fd)(struct wif *wi);
	int	(*wi_get_mac)(struct wif *wi, unsigned char *mac);
	int	(*wi_set_mac)(struct wif *wi, unsigned char *mac);
	int	(*wi_set_rate)(struct wif *wi, int rate);
	int	(*wi_get_rate)(struct wif *wi);
	int	(*wi_set_mtu)(struct wif *wi, int mtu);
	int	(*wi_get_mtu)(struct wif *wi);
        int     (*wi_get_monitor)(struct wif *wi);

        void	*wi_priv;
        char	wi_interface[MAX_IFACE_NAME];
};

