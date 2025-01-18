/*
 * Copyright 2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <pthread.h>
#include <errno.h>

#define MORSE_OUI (0x0CBF74)
#define MORSE_COMMAND_OCS_REQ (0xA017)

enum morse_vendor_attributes {
	MORSE_VENDOR_ATTR_DATA,
	MORSE_VENDOR_ATTR_MAX
};

struct command_hdr
{
	uint16_t flags;
	uint16_t message_id;
	uint16_t len;
	uint16_t host_id;
	uint16_t vif_id;
	uint16_t pad;
} __attribute__((packed));

struct command_ocs_req_subcmd
{
	uint32_t subcmd;
	uint32_t operating_channel_freq_hz;
	uint8_t operating_channel_bw_mhz;
	uint8_t primary_channel_bw_mhz;
	uint8_t primary_1mhz_channel_index;
} __attribute__((packed));

struct command_ocs_req
{
	struct command_hdr hdr;
	struct command_ocs_req_subcmd subcmd;
} __attribute__((packed));

struct command_ocs_resp {
	struct command_hdr hdr;
	uint32_t status;
	uint8_t running;
} __attribute__((packed));

struct ocs_done_evt
{
	uint64_t time_listen;
	uint64_t time_rx;
	int8_t noise;
	uint8_t metric;
} __attribute__((packed));

static int ack(struct nl_msg *msg, void *arg) {
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

static int finish(struct nl_msg *msg, void *arg) {
	int *err = arg;
	*err = 0;
	return NL_SKIP;
}

static int error(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
	int *ret = arg;
	*ret = err->error;
	return NL_SKIP;
}

static int resp_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) < 0)
		return NL_SKIP;

	switch(gnlh->cmd) {
		case NL80211_CMD_VENDOR:
		{
			struct command_ocs_resp *resp = nla_data(tb[NL80211_ATTR_VENDOR_DATA]);
			if (resp == NULL)
				break;

			if (resp->status != 0) {
				fprintf(stderr, "OCS command failed\n");
				return NL_STOP;
			}
			break;
		}
		default:
			fprintf(stderr, "Unexpected netlink command 0x%x, expected 0x%x\n", gnlh->cmd, NL80211_CMD_VENDOR);
			break;
	}

	return NL_OK;
}

static int trigger_off_channel_scan(const char *ifname, struct command_ocs_req_subcmd *config)
{
	int family;
	int err, ret = -1;
	struct command_ocs_req req = {
		.hdr = {
			.message_id = htole16(MORSE_COMMAND_OCS_REQ),
			.flags = htole16(0x1),
			.len = htole16(sizeof(struct command_ocs_req_subcmd)),
		},
		.subcmd = *config
    };

	int ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
		return ret;

	struct nl_cb *cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		goto nocb;

	err = 1;
	if (nl_cb_err(cb, NL_CB_CUSTOM, error, &err) < 0)
		goto nocb;
	if (nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish, &err) < 0)
		goto nocb;
	if (nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack, &err) < 0)
		goto nocb;
	if (nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, resp_handler, NULL) < 0)
		goto nocb;

	struct nl_sock *sk = nl_socket_alloc();
	if (!sk)
		goto nosk;

	if(genl_connect(sk) < 0)
		goto nosk;

	family = genl_ctrl_resolve(sk, "nl80211");
	if (family < 0)
		goto nosk;

	struct nl_msg *msg = nlmsg_alloc();
	if (!msg)
		goto nomsg;

	if (genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0,
	            0, NL80211_CMD_VENDOR, 0) == NULL)
	    goto nomsg;

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) < 0)
		goto nomsg;
	if (nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MORSE_OUI) < 0)
		goto nomsg;
	if (nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, 0) < 0)
		goto nomsg;

	if (nla_put(msg, NL80211_ATTR_VENDOR_DATA, sizeof(req), &req) < 0)
		goto nomsg;

	if (nl_send_auto(sk, msg) < 0)
		goto nomsg;

	while (err > 0)
		if (nl_recvmsgs(sk, cb) < 0)
			goto nomsg;

	ret = 0;
nomsg:
	nlmsg_free(msg);
nosk:
	nl_socket_free(sk);
nocb:
	nl_cb_put(cb);

	return ret;
}

struct ocs_handler_data {
	struct ocs_done_evt ocs;
	uint8_t done;
};

static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static int event_handler(struct nl_msg *msg, void *arg)
{
	struct ocs_handler_data *data = (struct ocs_handler_data *) arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *morse[MORSE_VENDOR_ATTR_MAX + 1];
	if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) < 0)
		return NL_SKIP;

	static const struct nla_policy morse_policy[MORSE_VENDOR_ATTR_MAX + 1] = {
		[MORSE_VENDOR_ATTR_DATA] = { .type = NLA_UNSPEC },
	};

	if (!tb[NL80211_ATTR_VENDOR_DATA] ||
		nla_parse_nested(morse, MORSE_VENDOR_ATTR_MAX, tb[NL80211_ATTR_VENDOR_DATA], morse_policy) ||
		!morse[MORSE_VENDOR_ATTR_DATA])
		return NL_SKIP;

	memcpy(&data->ocs, nla_data(morse[MORSE_VENDOR_ATTR_DATA]), nla_len(morse[MORSE_VENDOR_ATTR_DATA]));
	data->done = 1;
	return NL_OK;
}

void *ocs_event_listener(void *arg) {
	struct nl_sock *sk;
	struct nl_cb *cb;
	int family, mcid;
	struct command_ocs_req_subcmd *config = (struct command_ocs_req_subcmd *) arg;
	struct ocs_handler_data data = {.done = 0};

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		return NULL;

	if (nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL) < 0)
		goto nocb;
	if (nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, event_handler, &data) < 0)
		goto nocb;

	sk = nl_socket_alloc();
	if (!sk)
		goto nocb;

	if(genl_connect(sk) < 0)
		goto nosk;

	family = genl_ctrl_resolve(sk, "nl80211");
	if (family < 0)
		goto nosk;

	mcid = genl_ctrl_resolve_grp(sk, "nl80211", "vendor");
	if (mcid < 0)
		goto nosk;

	if (nl_socket_add_membership(sk, mcid) < 0)
		goto nosk;

	while(!data.done) {
		nl_recvmsgs(sk, cb);
	}

	printf("%u kHz (bw: %d, pw: %d, pi: %d):\n", le32toh(config->operating_channel_freq_hz) / 1000,
	       config->operating_channel_bw_mhz, config->primary_channel_bw_mhz, config->primary_1mhz_channel_index);
	printf("\tListen time: %llu us\n", data.ocs.time_listen);
	printf("\tRX time: %llu us\n", data.ocs.time_rx);
	printf("\tNoise: %d dBm\n", data.ocs.noise);

nosk:
	nl_socket_free(sk);
nocb:
	nl_cb_put(cb);

	return NULL;
}

int main(int argc, char **argv)
{
	char *ifname;
	struct command_ocs_req_subcmd config;
	pthread_t tid;
	uint32_t frequency;

	if (argc != 6) {
		fprintf(stderr, "Usage: ocs [<frequency> <bandwidth> <prim width> <prim index>]\n");
		return -1;
	}


	ifname = argv[1];
	config.subcmd = htole32(1);
	frequency = config.operating_channel_freq_hz = (uint32_t) strtoul(argv[2], NULL, 10);
	config.operating_channel_freq_hz = htole32(config.operating_channel_freq_hz * 1000);
	config.operating_channel_bw_mhz = (uint8_t) strtoul(argv[3], NULL, 10);
	config.primary_channel_bw_mhz = (uint8_t) strtoul(argv[4], NULL, 10);
	config.primary_1mhz_channel_index = (uint8_t) strtoul(argv[5], NULL, 10);

	printf("Triggering off-channel scan on %s at %d kHz...\n", ifname, frequency);
	pthread_create(&tid, NULL, ocs_event_listener, &config);
	trigger_off_channel_scan(ifname, &config);

	pthread_join(tid, NULL);

	return 0;
}