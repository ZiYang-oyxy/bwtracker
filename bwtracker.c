/*
 * monitor LAN clients bandwidth usage
 *
 * Author: Ouyang Xiongyi <hh123okbb@gmail.com>
 *
 * Changes:
 *         OuyangXY: Create file, 2014-02-23
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <net/route.h>
#include <linux/netfilter_ipv4.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

#define DEF_WAN "pppoe-wan"
#define DEF_LAN "br-lan"
#define DUMPPACKETS
#define BW_AGING
#define INTERVAL 3
#define AGING_TIME (4 * (1 << INTERVAL))

static LIST_HEAD(bw_list);
static char wan_if[16];
static char lan_if[16];
static int dbg = 0;
static spinlock_t bw_lock;

struct bw {
	struct list_head bw_link;
	__be32 addr;
	u16 up_pkts;
	u16 down_pkts;
	u32 up_byte;
	u32 down_byte;
	u32 old_up_bw; /* kB/s */
	u32 old_down_bw;
#ifdef BW_AGING
	int aging;
#endif
};

static struct proc_dir_entry *bwt_dir;
static struct timer_list bw_timer;

#ifdef DUMPPACKETS
void dump_data(unsigned char *Data, int length)
{
	int i, j;
	unsigned char s[255], sh[10];
	if (length > 64) {
		length = 64;
	}
	printk(KERN_INFO "---Packet start---\n");
	for (i = 0, j = 0; i < length / 8; i++, j += 8)
		printk(KERN_INFO "%02x %02x %02x %02x %02x %02x %02x %02x\n",
		       Data[j + 0], Data[j + 1], Data[j + 2], Data[j + 3],
		       Data[j + 4], Data[j + 5], Data[j + 6], Data[j + 7]);
	strcpy(s, "");
	for (i = 0; i < length % 8; i++) {
		sprintf(sh, "%02x ", Data[j + i]);
		strcat(s, sh);
	}
	printk(KERN_INFO "%s\n", s);
	printk(KERN_INFO "------------------\n");
}				// dump_data
#else
#define dump_data(data,len)
#endif				// DUMPPACKETS

static struct bw* find_bw_entry(__be32 addr)
{
	struct bw *bw;

	list_for_each_entry(bw, &bw_list, bw_link)
		if (bw->addr == addr)
			return bw;

	return NULL;
}

static struct bw* create_bw_entry(__be32 addr)
{
	struct bw *bw;

	bw = kmalloc(sizeof(struct bw), GFP_KERNEL);
	if (!bw)
		return NULL;

	bw->addr = addr;
	bw->up_pkts = 0;
	bw->down_pkts = 0;
	bw->up_byte = 0;
	bw->down_byte = 0;
	bw->old_up_bw = 0;
	bw->old_down_bw = 0;
#ifdef BW_AGING
	bw->aging = 0;
#endif
	list_add_tail(&bw->bw_link, &bw_list);
	//pr_info("[bwtracker] Add a new entry. IP: %pI4", &bw->addr);

	return bw;
}

static void bw_timer_fn(unsigned long data)
{
	struct bw *bw, *bwtmp;

	spin_lock(&bw_lock);
	list_for_each_entry_safe(bw, bwtmp, &bw_list, bw_link) {
#ifdef BW_AGING
		if (bw->up_byte == 0) {
			if (++(bw->aging) >= AGING_TIME) {
				list_del(&bw->bw_link);
				kfree(bw);
			}
			continue;
		}
		bw->aging = 0;
#endif
		bw->old_up_bw = bw->up_byte >> (10 + INTERVAL); /* kB/s */
		bw->old_down_bw = bw->down_byte >> (10 + INTERVAL);
		bw->up_byte = 0;
		bw->down_byte = 0;
	}
	spin_unlock(&bw_lock);
	mod_timer(&bw_timer, jiffies + (1 << INTERVAL) * HZ);
}
static unsigned int bandwidth_tracker(unsigned int hooknum,
						struct sk_buff *skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
	struct iphdr _iph;
	const struct iphdr *ih;
	struct bw *bw;

	//if (skb->protocol != htons(ETH_P_IP))
	//	goto out;

	ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (ih == NULL) { /* truncated */
		goto out;
	}

	spin_lock(&bw_lock);
	/* downstream first */
	if (!strcmp((out ? out->name : ""), lan_if) &&
			!strcmp((in ? in->name : ""), wan_if)) {
		bw = find_bw_entry(ih->daddr);
		if (!bw) {
			if ((bw = create_bw_entry(ih->daddr)) == NULL)
				goto out;
		}

		bw->down_pkts++;
		/* TODO skb->len == null? Add length of ethernet and pppoe header. */
		bw->down_byte += skb->data_len;
	} else if (!strcmp((out ? out->name : ""), wan_if) &&
			!strcmp((in ? in->name : ""), lan_if)) {
		bw = find_bw_entry(ih->saddr);
		if (!bw) {
			if ((bw = create_bw_entry(ih->saddr)) == NULL)
				goto out;
		}

		bw->up_pkts++;
		bw->up_byte += skb->data_len;
	}
	spin_unlock(&bw_lock);

out:
	return NF_ACCEPT;
}

/* The uplink bandwidth may be inaccurate when you set up a output qdisc,
 * because qdisc is executed in dev_queue_xmit which is after netfilter
 * hook point */
static struct nf_hook_ops bwt_nf_ops[] __read_mostly = {
	{
		.hook = bandwidth_tracker,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FIRST + 1,
	}
};

static int bwt_read_proc_bw(char *page, char **start, off_t off,
					  int count, int *eof, void *data) {
	struct bw *bw;
	int ret = 0;

	*eof = 1;
	list_for_each_entry(bw, &bw_list, bw_link) {
		ret += sprintf(page + ret, "%pI4/%d/%d\n", &bw->addr,
				bw->old_down_bw, bw->old_up_bw);
	}

	return ret;
}

static int bwt_proc_init()
{
	bwt_dir = proc_mkdir("bwt", init_net.proc_net);
	if (!bwt_dir) {
		pr_err("Failed to mkdir /proc/net/bwt\n");
		return -ENOMEM;
	}

	/* read only proc entries */
	if (create_proc_read_entry("bw", 0, bwt_dir,
				bwt_read_proc_bw, NULL) == NULL) {
		pr_err("Unable to create /proc/bwt/bw entry");
		return -ENOMEM;
	}

	return 0;
}

static int __init bwt_init(void)
{
	int rc = -ENOMEM;

	if (rc = bwt_proc_init())
		goto fail;

	sprintf(lan_if, "%s", DEF_LAN);
	sprintf(wan_if, "%s", DEF_WAN);
	pr_info("[bwtracker] lan:%s wan:%s", lan_if, wan_if);

	rc = nf_register_hooks(bwt_nf_ops, ARRAY_SIZE(bwt_nf_ops));

	setup_timer(&bw_timer, bw_timer_fn, 0);
	bw_timer.expires = jiffies + 4 * HZ;
	add_timer(&bw_timer);

	return rc;
fail:
	remove_proc_entry("bw", bwt_dir);
	remove_proc_entry("bwt", init_net.proc_net);
	return rc;
}

static void __exit bwt_exit(void)
{
	remove_proc_entry("bw", bwt_dir);
	remove_proc_entry("bwt", init_net.proc_net);

	del_timer(&bw_timer);
	nf_unregister_hooks(bwt_nf_ops, ARRAY_SIZE(bwt_nf_ops));
}

module_init(bwt_init);
module_exit(bwt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ouyang Xiongyi <hh123okbb@gmail.com>");
MODULE_DESCRIPTION("Bandwidth Tracker");
