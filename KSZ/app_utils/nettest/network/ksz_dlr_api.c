/**
 * Micrel DLR driver API code
 *
 * Copyright (c) 2014-2016 Microchip Technology Inc.
 *	Tristram Ha <Tristram.Ha@microchip.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>

#ifndef KSZ_DLR_API_H

/* Data types used in the DLR header file. */

typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;

/* Pack structure as necessary. */

#ifndef __packed
#define __packed __attribute__((packed))
#endif

/* Define this for ksz_request. */
#define MAX_REQUEST_SIZE		2000

#include "ksz_req.h"
#include "ksz_dlr_api.h"
#endif

#ifdef USE_DEV_IOCTL
#define DEV_IO_DLR			0

#define DEV_IOC_DLR			\
	_IOW(DEV_IOC_MAGIC, DEV_IO_DLR, struct ksz_request)

struct dev_info {
	int fd;
	u8 *buf;
	int len;
	int index;
	int left;
};

static int dlr_recv(struct dev_info *info, u8 data[], int len)
{
	struct ksz_read_msg *msg;
	int n;

	/* There are data left. */
	if (info->left) {
		msg = (struct ksz_read_msg *) &info->buf[info->index];

		/* But not enough. */
		if (info->left < msg->len) {
			memcpy(info->buf, &info->buf[info->index],
				info->left);
			info->index = info->left;
			info->left = 0;
		}
	} else
		info->index = 0;

	/* No more data. */
	if (!info->left) {

		/* Read from device. */
		do {
			/* This will be blocked if no data. */
			n = read(info->fd, &info->buf[info->index],
				info->len - info->index);
#if 0
printf("r: %d %d\n", n, info->index);
#endif
			if (n < 0) {
				printf("read failure\n");
				exit(1);
			}
			info->index += n;
		} while (!n && !info->index);
		info->left = info->index;
		info->index = 0;
#if 0
printf("l: %d i: %d\n", info->left, info->index);
#endif
	}
	msg = (struct ksz_read_msg *) &info->buf[info->index];
	if (msg->len > len) {
printf("  ??  %d; %d, %d %d\n", msg->len, len, info->index, info->left);
		exit(1);
	}
	info->index += msg->len;
	info->left -= msg->len;
#if 0
printf("left: i: %d l: %d; u: %d\n", info->index, info->left, msg->len);
#endif
	msg->len -= 2;

	if (len > msg->len)
		len = msg->len;
	memcpy(data, msg->data, len);
	return len;
}

int dlr_init(struct dev_info *dev)
{
	char device[20];

	sprintf(device, "/dev/sw_dev");
	dev->fd = open(device, O_RDWR);
	if (dev->fd < 0) {
		printf("cannot open sw device\n");
		return - 1;
	}
	dev->len = MAX_REQUEST_SIZE;
	dev->buf = malloc(dev->len);
	dev->index = 0;
	dev->left = 0;
	return 0;
}

void dlr_exit(struct dev_info *dev)
{
	if (dev->fd <= 0)
		return;
	usleep(10 * 1000);
	close(dev->fd);
	dev->fd = 0;
	free(dev->buf);
}

int dlr_ioctl(void *fd, void *req)
{
	struct dev_info *info = fd;

	return ioctl(info->fd, DEV_IOC_DLR, req);
}
#endif

#ifdef USE_NET_IOCTL
struct dev_info {
	int sock;
	char name[20];
};

int dlr_ioctl(void *fd, void *req)
{
	struct dev_info *info = fd;
	struct ifreq dev;

	memset(&dev, 0, sizeof(struct ifreq));
	strncpy(dev.ifr_name, info->name, sizeof(dev.ifr_name));
	dev.ifr_data = (char *) req;
	return ioctl(info->sock, SIOCDEVPRIVATE + 13, &dev);
}
#endif


/* Used to indicate which APIs are supported. */
static int dlr_version;

/* Used to indicate how many ports are in the switch. */
static int dlr_ports;


static void dlr_exit_req(void *ptr)
{
	struct ksz_request *req = ptr;

	req->size = SIZEOF_ksz_request;
	req->cmd = DEV_CMD_INFO;
	req->cmd |= DEV_MOD_DLR << 16;
	req->subcmd = DEV_INFO_EXIT;
	req->output = 0;
}  /* dlr_exit_req */

static void dlr_init_req(void *ptr,
	int capability)
{
	struct ksz_request *req = ptr;

	req->size = SIZEOF_ksz_request + 8;
	req->cmd = DEV_CMD_INFO;
	req->cmd |= DEV_MOD_DLR << 16;
	req->subcmd = DEV_INFO_INIT;
	req->output = capability;
	req->param.data[0] = 'C';
	req->param.data[1] = 'I';
	req->param.data[2] = 'P';
	req->param.data[3] = 'D';
	req->param.data[4] = 'L';
	req->param.data[5] = 'R';
}  /* dlr_init_req */

static void set_dlr_req(void *ptr, int cmd,
	u8 svc, u8 class, u8 code, u8 id, void *dlr, size_t dlr_size)
{
	struct ksz_request *req = ptr;

	req->size = SIZEOF_ksz_request;
	req->size += dlr_size;
	cmd |= DEV_MOD_DLR << 16;
	req->cmd = cmd;
	req->subcmd = (svc << CIP_SVC_S) | (class << CIP_CLASS_S) |
		(code << CIP_ATTR_S) | id;
	req->output = 0;
	if (dlr)
		memcpy(&req->param, dlr, dlr_size);
}  /* set_dlr_req */


int dlr_dev_exit(void *fd)
{
	struct ksz_request_actual req;
	int rc;

	dlr_exit_req(&req);
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	return rc;
}

int dlr_dev_init(void *fd,
	int capability, int *version, int *ports)
{
	struct ksz_request_actual req;
	int rc;

	dlr_init_req(&req, capability);
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		if ('M' == req.param.data[0] &&
		    'i' == req.param.data[1] &&
		    'c' == req.param.data[2] &&
		    'r' == req.param.data[3]) {
			*version = req.param.data[4];
			*ports = req.param.data[5];
		}
	}
	return rc;
}

static int get_dlr_revision(void *fd,
	u16 *rev)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_CLASS_ATTRIBUTES, DLR_GET_REVISION,
		NULL, sizeof(u16));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		union dlr_data *data = (union dlr_data *) &req.param;

		*rev = data->word;
	}
	return rc;
}  /* get_dlr_revision */

static int get_dlr_all(void *fd,
	struct ksz_dlr_gateway_capable *capable)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTES_ALL,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES, 0,
		NULL, sizeof(struct ksz_dlr_gateway_capable));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		memcpy(capable, &req.param, req.size - SIZEOF_ksz_request);
	}
	return rc;
}  /* get_dlr_all */

static int get_dlr_topology(void *fd,
	u8 *topology)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_GET_NETWORK_TOPOLOGY,
		NULL, sizeof(u8));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		union dlr_data *data = (union dlr_data *) &req.param;

		*topology = data->byte;
	}
	return rc;
}  /* get_dlr_topology */

static int get_dlr_network(void *fd,
	u8 *network)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_GET_NETWORK_STATUS,
		NULL, sizeof(u8));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		union dlr_data *data = (union dlr_data *) &req.param;

		*network = data->byte;
	}
	return rc;
}  /* get_dlr_network */

static int get_dlr_super_status(void *fd,
	u8 *status)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_GET_RING_SUPERVISOR_STATUS,
		NULL, sizeof(u8));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		union dlr_data *data = (union dlr_data *) &req.param;

		*status = data->byte;
	}
	return rc;
}  /* get_dlr_super_status */

static int get_dlr_super_cfg(void *fd,
	struct ksz_dlr_super_cfg *cfg)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_SET_RING_SUPERVISOR_CONFIG,
		NULL, sizeof(struct ksz_dlr_super_cfg));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		memcpy(cfg, &req.param, req.size - SIZEOF_ksz_request);
	}
	return rc;
}  /* get_dlr_super_cfg */

static int set_dlr_super_cfg(void *fd,
	struct ksz_dlr_super_cfg *cfg, u8 *err)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_PUT, SVC_SET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_SET_RING_SUPERVISOR_CONFIG,
		cfg, sizeof(struct ksz_dlr_super_cfg));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		*err = (u8) req.output;
	}
	return rc;
}  /* set_dlr_super_cfg */

static int get_dlr_ring_fault_cnt(void *fd,
	u16 *cnt)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_SET_RING_FAULT_COUNT,
		NULL, sizeof(u16));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		union dlr_data *data = (union dlr_data *) &req.param;

		*cnt = data->word;
	}
	return rc;
}  /* get_dlr_ring_fault_cnt */

static int set_dlr_ring_fault_cnt(void *fd,
	u16 cnt, u8 *err)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_PUT, SVC_SET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_SET_RING_FAULT_COUNT,
		&cnt, sizeof(u16));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		*err = (u8) req.output;
	}
	return rc;
}  /* set_dlr_ring_fault_cnt */

static int get_dlr_active_node(void *fd,
	u8 port, struct ksz_dlr_active_node *node)
{
	struct ksz_request_actual req;
	int rc;
	u8 id;

	if (1 == port)
		id = DLR_GET_LAST_ACTIVE_NODE_ON_PORT_2;
	else
		id = DLR_GET_LAST_ACTIVE_NODE_ON_PORT_1;
	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		id,
		NULL, sizeof(struct ksz_dlr_active_node));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		memcpy(node, &req.param, req.size - SIZEOF_ksz_request);
	}
	return rc;
}  /* get_dlr_active_node */

static int get_dlr_ring_part_cnt(void *fd,
	u16 *cnt)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_GET_RING_PARTICIPANTS_COUNT,
		NULL, sizeof(u16));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		union dlr_data *data = (union dlr_data *) &req.param;

		*cnt = data->word;
	}
	return rc;
}  /* get_dlr_ring_part_cnt */

static int get_dlr_ring_part_list(void *fd,
	struct ksz_dlr_active_node *node, u16 *size, u8 *err)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_GET_RING_PARTICIPANTS_LIST,
		NULL, *size);
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		*err = (u8) req.output;
		*size = req.size - SIZEOF_ksz_request;
		memcpy(node, &req.param, *size);
	}
	return rc;
}  /* get_dlr_ring_part_list */

static int get_dlr_active_super_addr(void *fd,
	struct ksz_dlr_active_node *node)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_GET_ACTIVE_SUPERVISOR_ADDRESS,
		NULL, sizeof(struct ksz_dlr_active_node));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		memcpy(node, &req.param, req.size - SIZEOF_ksz_request);
	}
	return rc;
}  /* get_dlr_active_super_addr */

static int get_dlr_active_super_prec(void *fd,
	u8 *prec)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_GET_ACTIVE_SUPERVISOR_PRECEDENCE,
		NULL, sizeof(u8));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		union dlr_data *data = (union dlr_data *) &req.param;

		*prec = data->byte;
	}
	return rc;
}  /* get_dlr_active_super_prec */

static int get_dlr_cap(void *fd,
	u32 *flags)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_GET, SVC_GET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_GET_CAPABILITY_FLAGS,
		NULL, sizeof(u32));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		union dlr_data *data = (union dlr_data *) &req.param;

		*flags = data->dword;
	}
	return rc;
}  /* get_dlr_cap */

static int set_dlr_verify_fault(void *fd,
	u8 *err)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_PUT, SVC_DLR_VERIFY_FAULT_LOCATION,
		CLASS_DLR_OBJECT, 0, 0,
		NULL, 0);
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		*err = (u8) req.output;
	}
	return rc;
}  /* set_dlr_verify_fault */

static int set_dlr_clear_rapid_fault(void *fd,
	u8 *err)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_PUT, SVC_DLR_CLEAR_RAPID_FAULTS,
		CLASS_DLR_OBJECT, 0, 0,
		NULL, 0);
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		*err = (u8) req.output;
	}
	return rc;
}  /* set_dlr_clear_rapid_fault */

static int set_dlr_restart_sign_on(void *fd,
	u8 *err)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_PUT, SVC_DLR_RESTART_SIGN_ON,
		CLASS_DLR_OBJECT, 0, 0,
		NULL, 0);
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		*err = (u8) req.output;
	}
	return rc;
}  /* set_dlr_restart_sign_on */

static int set_dlr_clear_gateway_fault(void *fd,
	u8 *err)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_PUT, SVC_DLR_CLEAR_GATEWAY_PARTIAL_FAULT,
		CLASS_DLR_OBJECT, 0, 0,
		NULL, 0);
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		*err = (u8) req.output;
	}
	return rc;
}  /* set_dlr_clear_gateway_fault */

static int set_dlr_ip_addr(void *fd,
	struct ksz_dlr_active_node *node, u8 *err)
{
	struct ksz_request_actual req;
	int rc;

	set_dlr_req(&req, DEV_CMD_PUT, SVC_SET_ATTRIBUTE_SINGLE,
		CLASS_DLR_OBJECT, CIP_INSTANCE_ATTRIBUTES,
		DLR_SET_IP_ADDRESS,
		node, sizeof(struct ksz_dlr_active_node));
	rc = dlr_ioctl(fd, &req);
	if (!rc)
		rc = req.result;
	if (!rc) {
		*err = (u8) req.output;
	}
	return rc;
}  /* set_dlr_ip_addr */

#include <errno.h>

int print_dlr_err(int rc)
{
	if (rc < 0) {
		switch (-rc) {
		case EAGAIN:
			break;
		case EINVAL:
			printf("  invalid value\n");
			break;
		default:
			printf("err: %d\n", rc);
		}
	} else if (rc > 0) {
		switch (rc) {
		case DEV_IOC_INVALID_SIZE:
			printf("  invalid size\n");
			break;
		case DEV_IOC_INVALID_CMD:
			printf("  invalid cmd\n");
			break;
		case DEV_IOC_INVALID_LEN:
			printf("  invalid len\n");
			break;
		}
	}
	return rc;
}  /* print_dlr_err */

