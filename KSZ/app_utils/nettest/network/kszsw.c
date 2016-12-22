#include "wnp.h"
#include "unpifi.h"
#include "datatype.h"

#ifndef _SYS_SOCKET_H
#include <sys\timeb.h>
#include <process.h>
#include "ip_icmp.h"

#else
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/
#include <linux/if_ether.h>
#include <sys/timeb.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include "wrapthread.h"
#ifndef IPV6_TCLASS
#define IPV6_TCLASS		67
#endif

#define _PATH_PROCNET_IFINET6           "/proc/net/if_inet6"

struct ipv6_info {
	char devname[20];
	struct sockaddr_in6 addr;
	int plen;
	int scope;
	int if_idx;
};

#define _PATH_SYSNET_DEV		"/sys/class/net/"

#define NETDEV_ADDRESS			"address"
#define NETDEV_FLAGS			"flags"
#define NETDEV_IFINDEX			"ifindex"
#define NETDEV_OPERSTATE		"operstate"

#endif


#if defined(_MSC_VER)
typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;

#include <packon.h>
#define __packed;
#endif

#if defined(__GNUC__)
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#endif

#ifdef _SYS_SOCKET_H

#if 0
#define USE_NET_IOCTL
#endif
#if 1
#define USE_DEV_IOCTL
#endif

#include "ksz_dlr_api.c"
#else
#include "ksz_dlr_api.h"
#endif

struct dlr_hdr {
	u8 id;
	u16 sequenceId;
	u16 messageLength;
} __packed;

struct dlr_msg {
	struct dlr_hdr hdr;
	union dlr_data data;
} __packed;

#if defined(_MSC_VER)
#include <packoff.h>
#endif


int gWaitDelay = 100;

char *KSZ_ip_addr = "224.0.1.123";
char *KSZ_ip_addr6_const = "ff02::0123";
char KSZ_ip_addr6[20];

#define KSZ_EVENT_PORT			123

int ip_family;
int ipv6_interface = 0;
int dbg_rcv = 0;

SOCKET event_fd;

SOCKET *sockptr;
char devname[20];
struct dev_info dlrdev;

struct sockaddr_in event_addr;
struct sockaddr_in client_addr;
struct sockaddr_in6 event_addr6;
struct sockaddr_in6 client_addr6;

pthread_mutex_t disp_mutex = PTHREAD_MUTEX_INITIALIZER;

u8 host_addr[16];
u8 host_addr6[16];

typedef struct {
	int fTaskStop;
	int multicast;

#if defined(_WIN32)
	HANDLE hevTaskComplete;
#endif
} TTaskParam, *PTTaskParam;


static void print_topology(u8 topology)
{
	printf("topology: %s\n", DLR_TOPOLOGY_RING == topology ?
		"ring" : "linear");
}

static void print_network(u8 network)
{
	printf("network: ");
	switch (network) {
	case DLR_NET_NORMAL:
		printf("normal\n");
		break; 
	case DLR_NET_RING_FAULT:
		printf("ring fault\n");
		break; 
	case DLR_NET_UNEXPECTED_LOOP_DETECTED:
		printf("unexpected loop\n");
		break; 
	case DLR_NET_PARTIAL_FAULT:
		printf("partial fault\n");
		break; 
	case DLR_NET_RAPID_FAULT:
		printf("rapid fault\n");
		break; 
	}
}

static void print_status(u8 status)
{
	printf("status: ");
	switch (status) {
	case DLR_STAT_BACKUP_SUPERVISOR:
		printf("backup supervisor\n");
		break;
	case DLR_STAT_ACTIVE_SUPERVISOR:
		printf("active supervisor\n");
		break;
	case DLR_STAT_RING_NODE:
		printf("ring node\n");
		break;
	case DLR_STAT_NO_SUPERVISOR:
		printf("no supervisor\n");
		break;
	case DLR_STAT_NODE_NOT_SUPPORTED:
		printf("not supported\n");
		break;
	}
}

static void print_super_cfg(struct ksz_dlr_super_cfg *cfg)
{
	printf("E:%u  P:%u  I:%u  T:%u  V:%u\n",
		cfg->enable, cfg->prec, cfg->beacon_interval,
		cfg->beacon_timeout, cfg->vid);
}

static void print_cap(u32 flags)
{
	printf("caps: %08x\n", flags);
	printf("%08x\tannounce based\n",
		DLR_CAP_ANNOUNCE_BASED);
	printf("%08x\tbeacon based\n",
		DLR_CAP_BEACON_BASED);
	printf("%08x\tsupervisor capable\n",
		DLR_CAP_SUPERVISOR_CAPABLE);
	printf("%08x\tgateway capable\n",
		DLR_CAP_GATEWAY_CAPABLE);
	printf("%08x\tflush table capable\n",
		DLR_CAP_FLUSH_TABLE_CAPABLE);
}

static void print_node(struct ksz_dlr_active_node *node)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x  ",
		node->addr[0],
		node->addr[1],
		node->addr[2],
		node->addr[3],
		node->addr[4],
		node->addr[5]);
	printf("%u.%u.%u.%u\n",
		(u8)(node->ip_addr),
		(u8)(node->ip_addr >> 8),
		(u8)(node->ip_addr >> 16),
		(u8)(node->ip_addr >> 24));
}

static void print_all(struct ksz_dlr_gateway_capable *capable)
{
	print_topology(capable->net_topology);
	print_network(capable->net_status);
	print_status(capable->super_status);
	print_super_cfg(&capable->super_cfg);
	print_node(&capable->last_active[0]);
	print_node(&capable->last_active[1]);
	print_node(&capable->active_super_addr);
	print_cap(capable->cap);
}

static void print_dlr_msg(u8 err)
{
	switch (err) {
	case STATUS_INVALID_ATTRIB_VALUE:
		printf("invalid attrib\n");
		break;
	case STATUS_OBJECT_STATE_CONFLICT:
		printf("object conflict\n");
		break;
	case STATUS_REPLY_DATA_TOO_LARGE:
		printf("data too large\n");
		break;
	}
}

static void print_sw_help(void)
{
	printf("\tv\tRevision\n");
	printf("\tc\tCapabilities\n");
	printf("\tt\tTopology\n");
	printf("\tn\tNetwork\n");
	printf("\ts\tStatus\n");
	printf("\tr\tRing participant count\n");
	printf("\tl\tRing participant list\n");
	printf("\te [p]\tActive node at port\n");
	printf("\td\tActive supervisor address\n");
	printf("\tp\tActive supervisor precedence\n");
	printf("\tib [#]\tBeacon interval\n");
	printf("\ttb [#]\tBeacon timeout\n");
	printf("\tpb [#]\tPrecedence\n");
	printf("\tvb [#]\tVLAN id\n");
	printf("\ta\tAll\n");
	printf("\tC [#]\tSupervisor config\n");
	printf("\tF [#]\tRing fault count\n");
	printf("\tV\tVerify Fault\n");
	printf("\tR\tClear Rapid Fault\n");
	printf("\tS\tRestart SignOn\n");
	printf("\tG\tClear Gateway Fault\n");
	printf("\th\thelp\n");
	printf("\tq\tquit\n");
}

int get_cmd(FILE *fp)
{
	int count;
	int hcount;
	unsigned int num[8];
	unsigned int hex[8];
	int cont = 1;
	u8 err = 0;
	u8 prec = 0;
	u32 flags = 0;
	struct ksz_dlr_active_node node;
	struct ksz_dlr_active_node nodes[10];
	struct ksz_dlr_gateway_capable capable;
	struct ksz_dlr_super_cfg cfg;
	u16 cnt = 0;
	u16 rev = 0;
	u16 size;
	u8 network = 0;
	u8 port;
	u8 status = 0;
	u8 topology = 0;
	char cmd[80];
	char line[80];
	int rc;
	u8 precedence = 0;
	u16 beacon_interval = 400;
	u16 beacon_timeout = 1960;
	u16 vid = 0;
	void *fd = &dlrdev;

	node.ip_addr = (host_addr[0]) | (host_addr[1] << 8) |
		(host_addr[2] << 16) | (host_addr[3] << 24);
	rc = set_dlr_ip_addr(&dlrdev, &node, &err);
	if (rc)
		print_dlr_err(rc);
	do {
		printf("> ");
		if (fgets(line, 80, fp) == NULL)
			break;
		cmd[0] = '\0';
		count = sscanf(line, "%s %d %d %d %d", cmd,
			(unsigned int *) &num[0],
			(unsigned int *) &num[1],
			(unsigned int *) &num[2],
			(unsigned int *) &num[3]);
		hcount = sscanf(line, "%s %x %x %x %x", cmd,
			(unsigned int *) &hex[0],
			(unsigned int *) &hex[1],
			(unsigned int *) &hex[2],
			(unsigned int *) &hex[3]);
		if ('b' == line[1]) {
			switch (line[0]) {
			case 'i':
				if (count >= 2)
					beacon_interval = (u16) num[0];
				else
					printf("beacon interval = %u\n",
						beacon_interval);
				break;
			case 't':
				if (count >= 2)
					beacon_timeout = (u16) num[0];
				else
					printf("beacon timeout = %u\n",
						beacon_timeout);
				break;
			case 'p':
				if (count >= 2)
					precedence = (u8) num[0];
				else
					printf("precedence = %u\n",
						precedence);
				break;
			case 'v':
				if (count >= 2)
					vid = (u16) num[0];
				else
					printf("VLAN id = %u\n",
						vid);
				break;
			}
		} else
		switch (line[0]) {
		case 't':
			rc = get_dlr_topology(fd, &topology);
			if (rc)
				print_dlr_err(rc);
			else
				print_topology(topology);
			break;
		case 'n':
			rc = get_dlr_network(fd, &network);
			if (rc)
				print_dlr_err(rc);
			else
				print_network(network);
			break;
		case 'a':
			rc = get_dlr_all(fd, &capable);
			if (rc)
				print_dlr_err(rc);
			else
				print_all(&capable);
			break;
		case 'v':
			rc = get_dlr_revision(fd, &rev);
			if (rc)
				print_dlr_err(rc);
			else
				printf("revision: %u\n", rev);
			break;
		case 's':
			rc = get_dlr_super_status(fd, &status);
			if (rc)
				print_dlr_err(rc);
			else
				print_status(status);
			break;
		case 'C':
			if (count >= 2) {
				cfg.enable = !!num[0];
				cfg.beacon_interval = beacon_interval;
				cfg.beacon_timeout = beacon_timeout;
				cfg.prec = precedence;
				cfg.vid = vid;
				rc = set_dlr_super_cfg(fd, &cfg, &err);
				if (rc)
					print_dlr_err(rc);
				print_dlr_msg(err);
			} else {
				rc = get_dlr_super_cfg(fd, &cfg);
				if (rc)
					print_dlr_err(rc);
				else
					print_super_cfg(&cfg);
			}
			break;
		case 'F':
			if (count >= 2) {
				cnt = num[0];
				rc = set_dlr_ring_fault_cnt(fd, cnt, &err);
				if (rc)
					print_dlr_err(rc);
				print_dlr_msg(err);
			} else {
				rc = get_dlr_ring_fault_cnt(fd, &cnt);
				if (rc)
					print_dlr_err(rc);
				else
					printf("ring fault cnt: %u\n", cnt);
			}
			break;
		case 'e':
			if (count < 2)
				break;
			port = num[0];
			rc = get_dlr_active_node(fd, port, &node);
			if (rc)
				print_dlr_err(rc);
			else
				print_node(&node);
			break;
		case 'r':
			rc = get_dlr_ring_part_cnt(fd, &cnt);
			if (rc)
				print_dlr_err(rc);
			else
				printf("ring part cnt: %u\n", cnt);
			break;
		case 'l':
			size = sizeof(nodes);
			rc = get_dlr_ring_part_list(fd, nodes, &size, &err);
			if (rc)
				print_dlr_err(rc);
			else {
				if (err) {
					print_dlr_msg(err);
					break;
				}
				for (err = 0; err < size /
				     sizeof(struct ksz_dlr_active_node); err++)
					print_node(&nodes[err]);
			}
			break;
		case 'd':
			rc = get_dlr_active_super_addr(fd, &node);
			if (rc)
				print_dlr_err(rc);
			else
				print_node(&node);
			break;
		case 'p':
			rc = get_dlr_active_super_prec(fd, &prec);
			if (rc)
				print_dlr_err(rc);
			else
				printf("precedence: %u\n", prec);
			break;
		case 'c':
			rc = get_dlr_cap(fd, &flags);
			if (rc)
				print_dlr_err(rc);
			else
				print_cap(flags);
			break;
		case 'V':
			rc = set_dlr_verify_fault(fd, &err);
			if (rc)
				print_dlr_err(rc);
			print_dlr_msg(err);
			break;
		case 'R':
			rc = set_dlr_clear_rapid_fault(fd, &err);
			if (rc)
				print_dlr_err(rc);
			print_dlr_msg(err);
			break;
		case 'S':
			rc = set_dlr_restart_sign_on(fd, &err);
			if (rc)
				print_dlr_err(rc);
			print_dlr_msg(err);
			break;
		case 'G':
			rc = set_dlr_clear_gateway_fault(fd, &err);
			if (rc)
				print_dlr_err(rc);
			print_dlr_msg(err);
			break;
		case 'h':
			print_sw_help();
			break;
		case 'q':
			cont = 0;
			break;
		}
	} while (cont);
	return 0;
}  /* get_cmd */

static SOCKET create_sock(char *devname, char *multi_ip, char *local_ip,
	int port, int multi_loop)
{
	SOCKET sockfd;
	struct sockaddr_in servaddr;
	struct sockaddr_in6 servaddr6;
#if 0
	struct in_addr local;
#endif
	char *sockopt;
	int family = AF_INET;
	int reuse = 1;

	bzero(&servaddr, sizeof(servaddr));
	bzero(&servaddr6, sizeof(servaddr6));
	if (inet_pton(AF_INET, local_ip, &servaddr.sin_addr) > 0)
		family = AF_INET;
	else if (inet_pton(AF_INET6, local_ip, &servaddr6.sin6_addr) > 0)
		family = AF_INET6;

	sockfd = Socket(family, SOCK_DGRAM, 0);

	if (AF_INET6 == family) {
		servaddr6.sin6_family = family;
		memcpy(servaddr6.sin6_addr.s6_addr, &in6addr_any,
			sizeof(in6addr_any));
		servaddr6.sin6_port = htons((short) port);
	} else {
		servaddr.sin_family = family;
		servaddr.sin_addr.s_addr = INADDR_ANY;
		servaddr.sin_port = htons((short) port);
	}

	sockopt = (char *) &reuse;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, sockopt,
			sizeof(reuse)) < 0) {
		printf("reuse\n");
		return -1;
	}
	if (AF_INET6 == family) {
		struct ipv6_mreq mreq;
		u_int iface;
		int hop;
		u_int loop;

		Bind(sockfd, (SA *) &servaddr6, sizeof(servaddr6));
#ifdef IPV6_CLASS
		if (KSZ_EVENT_PORT == port) {
			u_int tclass;

			tclass = 0xff;
			sockopt = (char *) &tclass;
			if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS,
					sockopt, sizeof(tclass)) < 0) {
				err_ret("no tclass");
			}
		}
#endif

		if (!multi_ip)
			return sockfd;

		inet_pton(AF_INET6, multi_ip, &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = ipv6_interface;
		sockopt = (char *) &mreq;
		if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				sockopt, sizeof(mreq)) < 0) {
			err_ret("add member");
			return -1;
		}
		if (ipv6_interface) {
			iface = ipv6_interface;
			sockopt = (char *) &iface;
			if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
					sockopt, sizeof(iface)) < 0) {
				err_ret("multi if");
				return -1;
			}
		}
		hop = 1;
		sockopt = (char *) &hop;
		if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
				sockopt, sizeof(hop)) < 0) {
			err_ret("hop");
			return -1;
		}
		loop = 0;
		if (multi_loop)
			loop = 1;
		sockopt = (char *) &loop;
		if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
				sockopt, sizeof(loop)) < 0) {
			err_ret("loop");
			return -1;
		}
	} else {
		struct ip_mreqn mreq;
		u_char hop;
		u_char loop;
		int tos;

		Bind(sockfd, (SA *) &servaddr, sizeof(servaddr));
		if (KSZ_EVENT_PORT == port) {
			tos = 0xb8;
			sockopt = (char *) &tos;
			if (setsockopt(sockfd, IPPROTO_IP, IP_TOS,
					sockopt, sizeof(tos)) < 0) {
				err_ret("tos");
				return -1;
			}
		}

		if (!multi_ip)
			return sockfd;

		mreq.imr_multiaddr.s_addr = inet_addr(multi_ip);
		mreq.imr_address.s_addr = inet_addr(local_ip);
		mreq.imr_ifindex = ipv6_interface;
		sockopt = (char *) &mreq;
		if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, sockopt,
				sizeof(mreq)) < 0) {
			err_ret("add member");
			return -1;
		}
		mreq.imr_ifindex = ipv6_interface;
		sockopt = (char *) &mreq;
		if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, sockopt,
				sizeof(mreq)) < 0) {
			err_ret("multi if");
			return -1;
		}
		hop = 1;
		sockopt = (char *) &hop;
		if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, sockopt,
				sizeof(hop)) < 0) {
			err_ret("hop");
			return -1;
		}
		loop = 0;
		if (multi_loop)
			loop = 1;
		sockopt = (char *) &loop;
		if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, sockopt,
				sizeof(loop)) < 0) {
			err_ret("loop");
			return -1;
		}
		if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
		    devname, strlen(devname))) {
			err_ret("bindtodev");
			return -1;
		}
	}
	return sockfd;
}  /* create_sock */

void send_msg(struct dlr_msg *msg, int family, int len, struct sockaddr *addr,
	socklen_t addrlen)
{
	char *buf = (char *) msg;

	if (!addr) {
		if (AF_INET6 == family) {
			addr = (SA *) &event_addr6;
			addrlen = sizeof(event_addr6);
		} else {
			addr = (SA *) &event_addr;
			addrlen = sizeof(event_addr);
		}
	}
	Sendto(event_fd, buf, len, 0, addr, addrlen);
}  /* send_msg */

struct sock_buf {
	struct sockaddr *from;
	u8 *buf;
	int len;
};

static int check_loop(struct sockaddr *sa, int salen)
{
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;

	if (AF_INET6 == sa->sa_family) {
		addr6 = (struct sockaddr_in6 *) sa;
		if (memcmp(&addr6->sin6_addr, host_addr6, 16) == 0)
			return 1;
		if (memcmp(&addr6->sin6_addr.s6_addr[12], host_addr, 4) == 0)
			return 2;
	} else if (AF_INET == sa->sa_family) {
		addr4 = (struct sockaddr_in *) sa;
		if (memcmp(&addr4->sin_addr, host_addr, 4) == 0)
			return 1;
	} else {
	}
	return 0;
}

static int check_dup(struct sock_buf *cur, struct sock_buf *last, int len)
{
	if (cur->len == last->len &&
			memcmp(cur->from, last->from, len) == 0 &&
			memcmp(cur->buf, last->buf, cur->len) == 0)
		return 1;
	return 0;
}

#ifdef _SYS_SOCKET_H
void *

#else
void
#endif
ReceiveTask(void *param)
{
	PTTaskParam pTaskParam;
	u8 *recvbuf;
	SOCKET sockfd;
	SOCKET fd[1];
	struct sock_buf buf[2];
	struct sockaddr_in6 cliaddr[2];
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	struct timeval timer;
	fd_set rset;
	fd_set allrset;
	socklen_t len;
	int maxfdp1;
	struct dlr_msg *msg;
	int i;
	char in_addr[80];
	int cur;
	int last;
	int nsel;
	int looped;
	int msglen;

	pTaskParam = (PTTaskParam) param;
	fd[0] = (SOCKET) pTaskParam->multicast;
	len = (MAXBUFFER + 3) & ~3;
	recvbuf = malloc(len * 2);
	buf[0].len = buf[1].len = 0;
	buf[0].buf = recvbuf;
	buf[1].buf = recvbuf + len;
	buf[0].from = (struct sockaddr *) &cliaddr[0];
	buf[1].from = (struct sockaddr *) &cliaddr[1];
	cur = 0;
	last = 1;

#ifdef _WIN32
	SetEvent( pTaskParam->hevTaskComplete );
#endif

	bzero(cliaddr, sizeof(cliaddr));

	FD_ZERO(&allrset);
	FD_SET(fd[0], &allrset);
	maxfdp1 = fd[0];
	maxfdp1++;
	FOREVER {
		if ( pTaskParam->fTaskStop ) {
			break;
		}

		rset = allrset;
		sockfd = 0;

		timerclear( &timer );
		timer.tv_usec = gWaitDelay * 1000;

		nsel = Select( maxfdp1, &rset, NULL, NULL, &timer );

		/* socket is not readable */
		if (!nsel) {
			if (pTaskParam->fTaskStop) {
				break;
			}
			continue;
		}

		for (i = 0; i < 1; i++) {
			if (nsel <= 0)
				break;

			len = sizeof(struct sockaddr_in6);
			if (FD_ISSET(fd[i], &rset) && sockfd != fd[i])
				sockfd = fd[i];
			else
				continue;

			buf[cur].len = Recvfrom(sockfd, buf[cur].buf,
				MAXBUFFER, 0, buf[cur].from, &len);
			--nsel;
			if (AF_INET6 == buf[cur].from->sa_family) {
				addr6 = (struct sockaddr_in6 *) buf[cur].from;
				inet_ntop(AF_INET6, &addr6->sin6_addr,
					in_addr, sizeof(in_addr));
				memcpy(&client_addr6, addr6,
					sizeof(struct sockaddr_in6));
			} else if (AF_INET == buf[cur].from->sa_family) {
				addr4 = (struct sockaddr_in *) buf[cur].from;
				inet_ntop(AF_INET, &addr4->sin_addr,
					in_addr, sizeof(in_addr));
				memcpy(&client_addr, addr4,
					sizeof(struct sockaddr_in));
			}
			if (dbg_rcv)
				Pthread_mutex_lock(&disp_mutex);
			if (dbg_rcv >= 4)
				printf("r: %d=%d %d=%s\n", sockfd,
					buf[cur].len, len, in_addr);
			msglen = buf[cur].len;
			msg = (struct dlr_msg *) buf[cur].buf;
			looped = check_loop(buf[cur].from, len);
			if (looped) {
				int ignored = 1;

				if (ignored) {
					if (dbg_rcv >= 4)
						printf("(ignored)\n");
					if (dbg_rcv)
						Pthread_mutex_unlock(
							&disp_mutex);
					continue;
				}
			}
			if (check_dup(&buf[cur], &buf[last], len)) {
				if (dbg_rcv >= 4)
					printf("(dup)\n");
				if (dbg_rcv)
					Pthread_mutex_unlock(&disp_mutex);
				continue;
			} else {
				if (looped && dbg_rcv >= 4)
					printf("(looped)\n");
				cur = !cur;
				last = !last;
			}
			if (dbg_rcv)
				Pthread_mutex_unlock(&disp_mutex);
		}
	}
	free(recvbuf);
	pTaskParam->fTaskStop = TRUE;

#ifdef _WIN32
	SetEvent( pTaskParam->hevTaskComplete );
#endif

#ifdef _SYS_SOCKET_H
	return NULL;
#endif
}  /* ReceiveTask */

static void handle_dlr_msg(u16 cmd, void *data, int len)
{
	u32 *dword = data;

	switch (cmd) {
	case DEV_INFO_QUIT:
		printf("quit\n");
		break;
	case DEV_INFO_DLR_LINK:
	{

		len -= 4;
		printf("link status: %x\n", *dword);
		if (len >= 4 + sizeof(struct ksz_dlr_active_node)) {
			struct ksz_dlr_active_node *active =
				(struct ksz_dlr_active_node *)(dword + 1);

			print_node(active);
		}
		break;
	}
	case DEV_INFO_DLR_CFG:
		printf("cfg: %x\n", *dword);
		break;
	}
}

void *NotificationTask(void *param)
{
	int len;
	u8 data[MAX_REQUEST_SIZE];
	PTTaskParam pTaskParam = param;

	pTaskParam->fTaskStop = FALSE;
	do {
		len = dlr_recv(&dlrdev, data, MAX_REQUEST_SIZE);
		if (len > 0) {
			struct ksz_resp_msg *msg = (struct ksz_resp_msg *)
				data;
			switch (msg->module) {
			case DEV_MOD_DLR:
				handle_dlr_msg(msg->cmd, msg->resp.data, len);
				break;
			default:
				printf("[%d] ", len);
				fflush(stdout);
			}
		}
	} while (!pTaskParam->fTaskStop);
	return NULL;
}

struct ip_info {
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	u8 hwaddr[8];
	int plen;
	int scope;
	int if_idx;
};

int get_host_info(char *devname, struct ip_info *info)
{
	struct ifi_info *ifi;
	struct ifi_info *ifihead;

	ifihead = get_ifi_info(AF_INET, 1);
	for (ifi = ifihead; ifi != NULL; ifi = ifi->ifi_next) {
		if (!strcmp(devname, ifi->ifi_name)) {
			info->if_idx = ifi->ifi_index;
			if (ifi->ifi_addr != NULL)
				memcpy(&info->addr, ifi->ifi_addr,
					sizeof(struct sockaddr_in));
			memset(info->hwaddr, 0, 8);
			if (ifi->ifi_hlen > 0)
				memcpy(info->hwaddr, ifi->ifi_haddr,
					ifi->ifi_hlen);
			info->plen = 0;
			if (ifi->ifi_addr6 != NULL) {
				memcpy(&info->addr6, ifi->ifi_addr6,
					sizeof(struct sockaddr_in6));
				info->plen = ifi->ifi_plen;
				info->scope = ifi->ifi_scope;
			} else if (ifi->ifi_hlen > 0) {
				u8 *data = (u8 *) &info->addr6.sin6_addr;

				memset(data, 0, 16);
				data[0] = 0xfe;
				data[1] = 0x80;
				memcpy(&data[8], ifi->ifi_haddr, 3);
				data[8] ^= 0x02;
				data[11] = 0xff;
				data[12] = 0xfe;
				memcpy(&data[13], &ifi->ifi_haddr[3], 3);
				info->addr6.sin6_family = AF_INET6;
				info->plen = 64;
				info->scope = 0x20;
			}
			return 1;
		}
	}
	free_ifi_info(ifihead);
	return 0;
}

#ifdef _SYS_SOCKET_H
int get_dev_info(char *devname, struct ip_info *info)
{
	FILE *f;
	int dad_status;
	int count;
	int rc;
	char addr6[40];
	char addr6p[8][5];

	struct ipv6_info *ipv6;
	struct ipv6_info *ipv6head = NULL;

	char path[80];
	char file[40];
	int num[6];
	int found = FALSE;

	/* No IP address. */
	info->addr.sin_family = AF_UNSPEC;

	/* Assume no IPv6 address. */
	info->plen = 0;
	memset(info->hwaddr, 0, 8);

	f = fopen(_PATH_PROCNET_IFINET6, "r");
	if (!f)
		goto get_dev_raw;
	count = 10;
	ipv6head = calloc(count, sizeof(struct ipv6_info));
	ipv6 = ipv6head;
	while (fscanf(f, "%4s%4s%4s%4s%4s%4s%4s%4s %02x %02x %02x %02x %20s\n",
			addr6p[0], addr6p[1], addr6p[2], addr6p[3], addr6p[4],
			addr6p[5], addr6p[6], addr6p[7],
			&ipv6->if_idx, &ipv6->plen, &ipv6->scope, &dad_status,
			ipv6->devname) != EOF) {
		sprintf(addr6, "%s:%s:%s:%s:%s:%s:%s:%s",
			addr6p[0], addr6p[1], addr6p[2], addr6p[3],
			addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
		inet_pton(AF_INET6, addr6,
			(struct sockaddr *) &ipv6->addr.sin6_addr);
		ipv6->addr.sin6_family = AF_INET6;
		if (!strcmp(devname, ipv6->devname)) {
			memcpy(&info->addr6, &ipv6->addr,
				sizeof(struct sockaddr_in6));
			info->if_idx = ipv6->if_idx;
			info->plen = ipv6->plen;
			info->scope = ipv6->scope;
			found = TRUE;
			break;
		}
		ipv6++;
		count--;
		if (1 == count)
			break;
	}
	free(ipv6head);
	fclose(f);

get_dev_raw:
	if (found)
		goto get_dev_addr;

	sprintf(path, "%s%s/%s", _PATH_SYSNET_DEV, devname, NETDEV_FLAGS);
	f = fopen(path, "r");
	if (!f)
		goto get_dev_done;
	rc = fscanf(f, "%x", &num[0]);
	fclose(f);

	sprintf(path, "%s%s/%s", _PATH_SYSNET_DEV, devname, NETDEV_OPERSTATE);
	f = fopen(path, "r");
	if (!f)
		goto get_dev_addr;
	rc = fscanf(f, "%s", file);
	fclose(f);
	if ((!strcmp(file, "up") && !(num[0] & IFF_UP)) ||
	    (!strcmp(file, "down") && (num[0] & IFF_UP)))
		printf(" ? %s 0x%04x\n", file, num[0]);

	/* Device not running. */
	if (!(num[0] & IFF_UP))
		goto get_dev_done;

get_dev_addr:
	sprintf(path, "%s%s/%s", _PATH_SYSNET_DEV, devname, NETDEV_IFINDEX);
	f = fopen(path, "r");
	if (f) {
		rc = fscanf(f, "%u", &num[0]);
		fclose(f);
		if (!found)
			info->if_idx = num[0];
		else if (info->if_idx != num[0])
			printf(" ? %d %d\n", info->if_idx, num[0]);
	}

	found = TRUE;

	sprintf(path, "%s%s/%s", _PATH_SYSNET_DEV, devname, NETDEV_ADDRESS);
	f = fopen(path, "r");
	if (!f)
		goto get_dev_done;
	rc = fscanf(f, "%x:%x:%x:%x:%x:%x",
		&num[0], &num[1], &num[2], &num[3], &num[4], &num[5]);
	fclose(f);
	for (count = 0; count < 6; count++)
		info->hwaddr[count] = (u8) num[count];

get_dev_done:
	return found;
}
#endif

int main(int argc, char *argv[])
{
	TTaskParam param[2];

#ifdef _SYS_SOCKET_H
	pthread_t tid[2];
	void *status;

#elif defined( _WIN32 )
	DWORD rc;
#endif
	char dest_ip[40];
	char host_ip4[40];
	char host_ip6[40];
	char *host_ip;
	int family;
	char *multi_ip = NULL;
	int i;
	struct ip_info info;
	int multi_loop = 0;

#ifdef USE_DEV_IOCTL
	if (dlr_init(&dlrdev)) {
		printf("cannot access device\n");
		return 1;
	}
#endif

	SocketInit(0);

	if (argc < 2) {
		printf("usage: %s <local_if> [-6[0..f]] [-p]",
			argv[0]);
		printf(" [-u <dest_ip>] [-m (unicast socket)]\n\t");
		printf("[-d[#] (debug rx)] [-l (multicast loop)]\n");
		printf("\t[-r[#] (redundancy)] [-v reserved]\n");
		return 1;
	}
	family = AF_INET;
	dest_ip[0] = '\0';
	strcpy(KSZ_ip_addr6, KSZ_ip_addr6_const);
	if (argc > 2) {
		i = 2;
		while (i < argc) {
			if ('-' == argv[i][0]) {
				switch (argv[i][1]) {
				case '6':
					family = AF_INET6;
					if (argv[i][2]) {
						KSZ_ip_addr6[3] = argv[i][2];
					}
					break;
				case 'd':
					dbg_rcv = 5;
					if ('0' <= argv[i][2] &&
							argv[i][2] <= '9')
						dbg_rcv = argv[i][2] - '0';
					break;
				case 'l':
					multi_loop = 1;
					break;
				case 'u':
					++i;
					strcpy(dest_ip, argv[i]);
					break;
				case 'v':
					++i;
					break;
				}
			}
			++i;
		}
	}
	strncpy(devname, argv[1], sizeof(devname));
	host_ip = strchr(devname, '.');
	if (host_ip != NULL)
		*host_ip = 0;
#ifdef USE_NET_IOCTL
	strncpy(dlrdev.name, devname, sizeof(dlrdev.name));
#endif

	if (get_host_info(argv[1], &info)) {
		memcpy(host_addr, &info.addr.sin_addr, 4);
		inet_ntop(AF_INET, &info.addr.sin_addr,
			host_ip4, sizeof(host_ip4));
		printf("%s\n", host_ip4);
		ipv6_interface = info.if_idx;
		if (info.plen) {
			inet_ntop(AF_INET6, &info.addr6.sin6_addr,
				host_ip6, sizeof(host_ip6));
			printf("%s\n", host_ip6);
			memcpy(host_addr6, &info.addr6.sin6_addr, 16);
			ipv6_interface = info.if_idx;
		}
	} else {
		printf("cannot locate IP address\n");
		exit(1);
	}

	ip_family = family;
	if (AF_INET6 == family) {
		host_ip = host_ip6;
		event_addr6.sin6_family = family;
		event_addr6.sin6_port = htons(KSZ_EVENT_PORT);

		multi_ip = KSZ_ip_addr6;

		inet_pton(family, multi_ip, &event_addr6.sin6_addr);
	} else {
		family = AF_INET;
		host_ip = host_ip4;
		event_addr.sin_family = family;
		event_addr.sin_port = htons(KSZ_EVENT_PORT);

		multi_ip = KSZ_ip_addr;

		event_addr.sin_addr.s_addr = inet_addr(multi_ip);
	}

	event_fd = create_sock(argv[1], multi_ip, host_ip, KSZ_EVENT_PORT, 0);
	if (event_fd < 0) {
		printf("Cannot create socket\n");
		return 1;
	}
	sockptr = &event_fd;
#ifdef USE_NET_IOCTL
	dlrdev.sock = event_fd;
#endif

	i = 0;
	param[i].fTaskStop = FALSE;
	param[i].multicast = event_fd;

#ifdef _SYS_SOCKET_H
	Pthread_create(&tid[i], NULL, ReceiveTask, &param[i]);
	Pthread_create(&tid[1], NULL, NotificationTask, &param[1]);

#elif defined( _WIN32 )
	param[i].hevTaskComplete =
		CreateEvent( NULL, TRUE, FALSE, NULL );
	if ( NULL == param[i].hevTaskComplete ) {

	}
	_beginthread( ReceiveTask, 4096, &param[i] );

	// wait for task to start
	rc = WaitForSingleObject( param[i].hevTaskComplete, INFINITE );
	if ( WAIT_FAILED == rc ) {

	}
	ResetEvent( param[i].hevTaskComplete );
	Sleep( 1 );
#endif

	if ( !param[0].fTaskStop ) {
		int rc;

		rc = dlr_dev_init(&dlrdev, 0, &dlr_version, &dlr_ports);
		if (rc) {
			print_dlr_err(rc);
			return rc;
		}
		printf("version=%d ports=0x%x\n", dlr_version, dlr_ports);
		rc = get_cmd(stdin);
		rc = dlr_dev_exit(&dlrdev);
		param[0].fTaskStop = TRUE;
	}
	param[1].fTaskStop = TRUE;

	// wait for task to end
	i = 0;

#ifdef _SYS_SOCKET_H
	Pthread_join( tid[i], &status );
	Pthread_join(tid[1], &status);

#elif defined( _WIN32 )
	rc = WaitForSingleObject( param[i].hevTaskComplete, INFINITE );
	if ( WAIT_FAILED == rc ) {

	}
	ResetEvent( param[i].hevTaskComplete );
	Sleep( 1 );

#else
	DelayMillisec( 200 );
#endif

	closesocket(event_fd);
	SocketExit();

#ifdef USE_DEV_IOCTL
	dlr_exit(&dlrdev);
#endif

	return 0;
}
