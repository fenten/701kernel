/*
 * drivers/misc/netmeter.c
 *
 * Copyright (C) 2010 Motorola Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/string.h>

#define DEVICE_NAME	"netmeter"

struct netmeter_data {
	struct miscdevice *device;
	int started;
	unsigned long long cdma_in;
	unsigned long long cdma_out;
	unsigned long long gsm_in;
	unsigned long long gsm_out;
	struct nf_hook_ops nfho_in;
	struct nf_hook_ops nfho_out;
	struct nf_hook_ops nfho_forward;
};

struct netmeter_data *g_dev;
static char *gsm_devname = "rmnet0";
static char *cdma_devname = "ppp0";
static char *cdma_dun_devname = "ppp1";
static char *wifi_devname = "tiwlan0";

static spinlock_t spin_cdma_in;
static spinlock_t spin_cdma_out;
static spinlock_t spin_gsm_in;
static spinlock_t spin_gsm_out;

static void set_cdma_in(unsigned long long , bool);
static void set_cdma_out(unsigned long long , bool);
static void set_gsm_in(unsigned long long , bool);
static void set_gsm_out(unsigned long long , bool);

/*=========================================================================*/
static unsigned int netmeter_nf_hook_in(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	if (0 == strncmp(gsm_devname, in->name, sizeof(gsm_devname)))
		set_gsm_in((unsigned long long)(skb->len), false);
	else if (0 == strncmp(cdma_devname, in->name, sizeof(cdma_devname)))
		set_cdma_in((unsigned long long)(skb->len), false);
	return NF_ACCEPT;
}

static unsigned int netmeter_nf_hook_out(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	if (0 == strncmp(gsm_devname, out->name, sizeof(gsm_devname)))
		set_gsm_out((unsigned long long)(skb->len), false);
	else if (0 == strncmp(cdma_devname, out->name, sizeof(cdma_devname)))
		set_cdma_out((unsigned long long)(skb->len), false);
	return NF_ACCEPT;
}

static unsigned int netmeter_nf_hook_forward(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	if ((0 == strncmp(cdma_devname, in->name, sizeof(cdma_devname))) &&
		((0 == strncmp(cdma_dun_devname, out->name,
			sizeof(cdma_dun_devname))) ||
		(0 == strncmp(wifi_devname, out->name,
			sizeof(wifi_devname)))))

		set_cdma_in((unsigned long long)(skb->len), false);

	else if (((0 == strncmp(cdma_dun_devname, in->name,
		sizeof(cdma_dun_devname))) ||
		(0 == strncmp(wifi_devname, in->name, sizeof(wifi_devname)))) &&
		(0 == strncmp(cdma_devname, out->name, sizeof(cdma_devname))))

		set_cdma_out((unsigned long long)(skb->len), false);

	return NF_ACCEPT;
}

static void set_cdma_in(unsigned long long data, bool reset_data)
{
	spin_lock(&spin_cdma_in);
	if (reset_data)
		g_dev->cdma_in = data;
	else
		g_dev->cdma_in += data;
	spin_unlock(&spin_cdma_in);

}

static void set_gsm_in(unsigned long long data, bool reset_data)
{
	spin_lock(&spin_gsm_in);
	if (reset_data)
		g_dev->gsm_in = data;
	else
		g_dev->gsm_in += data;
	spin_unlock(&spin_gsm_in);

}
static void set_cdma_out(unsigned long long data, bool reset_data)
{
	spin_lock(&spin_cdma_out);
	if (reset_data)
		g_dev->cdma_out = data;
	else
		g_dev->cdma_out += data;
	spin_unlock(&spin_cdma_out);
}

static void set_gsm_out(unsigned long long data, bool reset_data)
{
	spin_lock(&spin_gsm_out);
	if (reset_data)
		g_dev->gsm_out = data;
	else
		g_dev->gsm_out += data;
	spin_unlock(&spin_gsm_out);
}


static int update_nf_hooks(void)
{
	if (g_dev->started) {
		nf_register_hook(&(g_dev->nfho_in));
		nf_register_hook(&(g_dev->nfho_out));
		nf_register_hook(&(g_dev->nfho_forward));
	} else {
		nf_unregister_hook(&(g_dev->nfho_in));
		nf_unregister_hook(&(g_dev->nfho_out));
		nf_unregister_hook(&(g_dev->nfho_forward));
	}

	return 0;
}

/*==========================================================================*/

static ssize_t show_start(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", g_dev->started);
}

static ssize_t store_start(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long start;
	int r;

	r = strict_strtoul(buf, 10, &start);

	if (r < 0 || (start != 0 && start != 1))
		return -EINVAL;

	if (g_dev->started != start) {
		g_dev->started = start;
		r = update_nf_hooks();
	}
	if (r)
		return r;

	return count;
}



static ssize_t show_cdma_in(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", g_dev->cdma_in);
}

static ssize_t store_cdma_in(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long cdma_in;
	int r;

	r = strict_strtoul(buf, 10, &cdma_in);
	if (r < 0)
		return -EINVAL;
	set_cdma_in((unsigned long long)cdma_in, true);
	return count;
}


static ssize_t show_cdma_out(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", g_dev->cdma_out);
}

static ssize_t store_cdma_out(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long cdma_out;
	int r;

	r = strict_strtoul(buf, 10, &cdma_out);
	if (r < 0)
		return -EINVAL;
	set_cdma_out((unsigned long long)cdma_out, true);
	return count;
}


static ssize_t show_gsm_in(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", g_dev->gsm_in);
}

static ssize_t store_gsm_in(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long gsm_in;
	int r;

	r = strict_strtoul(buf, 10, &gsm_in);
	if (r < 0)
		return -EINVAL;
	set_gsm_in((unsigned long long)gsm_in, true);
	return count;
}

static ssize_t show_gsm_out(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", g_dev->gsm_out);
}

static ssize_t store_gsm_out(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long gsm_out;
	int r;

	r = strict_strtoul(buf, 10, &gsm_out);
	if (r < 0)
		return -EINVAL;
	set_gsm_out((unsigned long long)gsm_out, true);
	return count;
}


static struct device_attribute netmeter_attrs[] = {
	__ATTR(start, S_IRUGO | S_IWUGO, show_start, store_start),
	__ATTR(cdma_in, S_IRUGO | S_IWUGO, show_cdma_in, store_cdma_in),
	__ATTR(cdma_out, S_IRUGO | S_IWUGO, show_cdma_out, store_cdma_out),
	__ATTR(gsm_in, S_IRUGO | S_IWUGO, show_gsm_in, store_gsm_in),
	__ATTR(gsm_out, S_IRUGO | S_IWUGO, show_gsm_out, store_gsm_out),
};

int netmeter_create_sysfs(void)
{
	int r;
	int t;

	printk(KERN_DEBUG "create sysfs for netmeter\n");
	for (t = 0; t < ARRAY_SIZE(netmeter_attrs); t++) {
		r = device_create_file(g_dev->device->this_device,
				&netmeter_attrs[t]);

		if (r) {
			printk(KERN_ERR "failed to create sysfs file\n");
			return r;
		}
	}

	return 0;
}

void netmeter_remove_sysfs(void)
{
	int t;

	printk(KERN_DEBUG "remove sysfs\n");
	for (t = 0; t < ARRAY_SIZE(netmeter_attrs); t++)
		device_remove_file(g_dev->device->this_device,
				&netmeter_attrs[t]);
}


/*===========================================================================*/

static int netmeter_open(struct inode *inode, struct file *filp)
{
	printk(KERN_DEBUG "netmeter_open\n");
	return 0;
}

static int netmeter_release(struct inode *inode, struct file *filp)
{
	printk(KERN_DEBUG "netmeter_release\n");
	return 0;
}

static ssize_t netmeter_read(struct file *fp, char __user *buf,
						size_t count, loff_t *ppos)
{
	printk(KERN_DEBUG "netmeter_read\n");
	return 0;
}

static ssize_t netmeter_write(struct file *file, const char __user *buf,
						size_t count, loff_t *ppos)
{
	printk(KERN_DEBUG "netmeter_write\n");
	return 0;
}

static int netmeter_ioctl(struct inode *inode, struct file *filp,
						u_int cmd, u_long arg)
{
	return 0;
}

static const struct file_operations netmeter_fops = {
	.owner = THIS_MODULE,
	.open = netmeter_open,
	.release = netmeter_release,
	.read = netmeter_read,
	.write = netmeter_write,
	.ioctl = netmeter_ioctl,
};

static struct miscdevice netmeter_misc_device = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= DEVICE_NAME,
	.fops	= &netmeter_fops,
};

static int __init netmeter_init(void)
{
	int rc = 0;
	printk(KERN_DEBUG "netmeter_init\n");

	g_dev = kzalloc(sizeof(struct netmeter_data), GFP_KERNEL);
	if (g_dev == NULL)
		return -ENOMEM;

	rc = misc_register(&netmeter_misc_device);
	if (rc) {
		printk(KERN_ERR "netmeter: misc register failed (%d)\n", rc);
		goto failed_misc;
	}
	g_dev->device = &netmeter_misc_device;

	g_dev->nfho_in.hook = netmeter_nf_hook_in;
	g_dev->nfho_in.pf = PF_INET;
	g_dev->nfho_in.hooknum = NF_INET_LOCAL_IN;
	g_dev->nfho_in.priority = NF_IP_PRI_FIRST;

	g_dev->nfho_out.hook = netmeter_nf_hook_out;
	g_dev->nfho_out.pf = PF_INET;
	g_dev->nfho_out.hooknum = NF_INET_LOCAL_OUT;
	g_dev->nfho_out.priority = NF_IP_PRI_FIRST;

	g_dev->nfho_forward.hook = netmeter_nf_hook_forward;
	g_dev->nfho_forward.pf = PF_INET;
	g_dev->nfho_forward.hooknum = NF_INET_FORWARD;
	g_dev->nfho_forward.priority = NF_IP_PRI_FIRST;

	g_dev->started = 1;

	spin_lock_init(&spin_cdma_in);
	spin_lock_init(&spin_cdma_out);
	spin_lock_init(&spin_gsm_in);
	spin_lock_init(&spin_gsm_out);
	update_nf_hooks();
	rc = netmeter_create_sysfs();
	if (rc)
		printk(KERN_ERR "netmeter: create sysfs failed");

	return 0;

failed_misc:
	printk(KERN_ERR "netmeter register failed (%d)\n", rc);
	kfree(g_dev);
	g_dev = NULL;
	return -ENODEV;
}

static void __exit netmeter_exit(void)
{
	printk(KERN_DEBUG "netmeter_exit\n");

	if (g_dev->started) {
		nf_unregister_hook(&(g_dev->nfho_in));
		nf_unregister_hook(&(g_dev->nfho_out));
	}

	netmeter_remove_sysfs();
	misc_deregister(&netmeter_misc_device);
	kfree(g_dev);
	g_dev = NULL;

}

module_init(netmeter_init);
module_exit(netmeter_exit);

MODULE_AUTHOR("Motorola");
MODULE_LICENSE("GPL");
