
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"


#include "Ctxs.h"
#ifdef HAVE_LINUX_NETLINK
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#define NETLINK_GENERIC 16


MODULE = Air::Lorcon2   PACKAGE = Air::Lorcon2::80211
PROTOTYPES: DISABLE

// Create the socket

NL_SOCK *
nl_socket_alloc() 

	
uint32_t
nl_socket_get_local_port(sk)
	NL_SOCK *sk
	
void
nl_socket_set_local_port(sk, port)
	NL_SOCK *sk
	uint32_t port
	
int 
nl_connect(sk, protocol)
	NL_SOCK *sk
	int protocol

void
nl_close(sk)
	NL_SOCK *sk

int 
genl_connect(sk)
	struct nl_sock *sk
CODE:
	return( newSVpv( nl_connect(sk, NETLINK_GENERIC), 0 ) );

int
genl_send_simple(sk, family, cmd, version, flags)
	NL_SOCK *sk
	int family
	int cmd
	int version
	int flags

// define BUG and BUG 

#ifndef HAVE_ARCH_BUG
#define BUG() do { \
    printk("BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
    panic("BUG!"); \
} while (0)
#endif

#ifndef HAVE_ARCH_BUG_ON
#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while(0)
#endif

// pthread_rwlock_wrlock will used only for nl_write_lock, not intended as user defined function
int 
pthread_rwlock_wrlock(rwlock)
	pthread_rwlock_t *rwlock
	
// pthread_rwlock_unlock will used only for nl_write_lock, not intended as user defined function
int 
pthread_rwlock_unlock(rwlock)
	pthread_rwlock_t *rwlock


void 
nl_write_lock(lock)
	pthread_rwlock_t *lock
CODE:
	pthread_rwlock_wrlock(lock);

void 
nl_write_unlock(lock)
	pthread_rwlock_t *lock
CODE:
	pthread_rwlock_unlock(lock);



 void 
 release_local_port(port)
	uint32_t port
CODE:
	int nr;
	uint32_t mask;
	BUG_ON(port == 0);
	nr = port >> 22;
	mask = 1UL << (nr % 32);
	nr /= 32;
	nl_write_lock(&port_map_lock);
	BUG_ON((used_ports_map[nr] & mask) != mask);
	used_ports_map[nr] &= ~mask;
	nl_write_unlock(&port_map_lock);


#endif
