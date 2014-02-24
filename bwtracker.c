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

//#define DEF_WAN "wlan0"
//#define DEF_LAN "br-lan"
#define DEF_WAN "pppoe-wan"
#define DEF_LAN "br-lan"
#define DUMPPACKETS

static LIST_HEAD(bw_list);
static char wan_if[16];
static char lan_if[16];
static int dbg = 0;

struct bw {
	struct list_head bw_link;
	__be32 addr;
	u16 up_pkts;
	u16 down_pkts;
	u32 up_byte;
	u32 down_byte;
	u32 old_up_bw; /* kB/s */
	u32 old_down_bw;
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
	list_add_tail(&bw->bw_link, &bw_list);
	pr_info("[bwtracker] Add a new entry. IP: %pI4", &bw->addr);

	return bw;
}

static void bw_timer_fn(unsigned long data)
{
	struct bw *bw;

	list_for_each_entry(bw, &bw_list, bw_link) {
		bw->old_up_bw = bw->up_byte >> 12;
		bw->old_down_bw = bw->down_byte >> 12;
		bw->up_byte = 0;
		bw->down_byte = 0;
		pr_info("[bwtracker] %pI4: up:%d kB/s down:%d kB/s",
				&bw->addr, bw->old_up_bw, bw->old_down_bw);
	}
	mod_timer(&bw_timer, jiffies + 4 * HZ);
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

	//if (dbg < 2) {
	//	dump_data(skb->data, skb->data_len);
	//	dbg++;
	//}

	//if (skb->protocol != htons(ETH_P_IP))
	//	goto out;

	/* TODO how to find the pointer, ip_hdr didn't take effect */
	ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	//ih = skb_header_pointer(skb, iphoff, sizeof(_iph), &_iph);
	if (ih == NULL) { /* truncated */
		goto out;
	}

	//if (dbg < 5) {
	//	pr_info("src:%pI4 dst:%pI4 in:%s out:%s", &ih->saddr, &ih->daddr,
	//			(in ? in->name : ""), (out ? out->name : ""));
	//	dbg++;
	//}

	/* downstream first */
	if (!strcmp((out ? out->name : ""), lan_if) &&
			!strcmp((in ? in->name : ""), wan_if)) {
		bw = find_bw_entry(ih->daddr);
		if (!bw) {
			if ((bw = create_bw_entry(ih->daddr)) == NULL)
				goto out;
		}

		bw->down_pkts++;
		/* TODO skb->len == null? */
		bw->down_byte += skb->data_len;
		//if (dbg < 20) {
		//	pr_info("D src:%pI4 dst:%pI4 dlen:%d, l:%d", &ih->saddr, &ih->daddr,
		//			skb->data_len, skb->len);
		//	dbg++;
		//}
	} else if (!strcmp((out ? out->name : ""), wan_if) &&
			!strcmp((in ? in->name : ""), lan_if)) {
		bw = find_bw_entry(ih->saddr);
		if (!bw) {
			if ((bw = create_bw_entry(ih->saddr)) == NULL)
				goto out;
		}

		bw->up_pkts++;
		bw->up_byte += skb->data_len;
		//pr_info("U src:%pI4 dst:%pI4", &ih->saddr, &ih->daddr);
	}

out:
	return NF_ACCEPT;
}

static struct nf_hook_ops bwt_nf_ops[] __read_mostly = {
	{
		.hook = bandwidth_tracker,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		//.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_FIRST + 1,
	}
};

static int bwt_read_proc_bw(char *page, char **start, off_t off,
					  int count, int *eof, void *data) {
	struct bw *bw;
	int ret = 0;

	*eof = 1;
	list_for_each_entry(bw, &bw_list, bw_link) {
		ret += sprintf(page + ret, "%pI4/%d/%d\n", &bw->addr,  bw->old_down_bw, bw->old_up_bw);
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
