// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET     An implementation of the TCP/IP protocol suite for the LINUX
 *      operating system.  INET is implemented using the  BSD Socket
 *      interface as the means of communication with the user level.
 *
 *      Paravirt driver for rvc. Based on loopback.c.
 *
 */
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/of_device.h>
#include <asm/csr.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <net/sch_generic.h>
#include <net/sock.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/percpu.h>
#include <net/net_namespace.h>

#define CSR_NET_TX_BUF_ADDR 0x0c0
#define CSR_NET_TX_BUF_SIZE_AND_SEND 0x0c1
#define CSR_NET_RX_BUF_ADDR 0x0c2
#define CSR_NET_RX_BUF_READY 0x0c3
#define MAX_BUF_SIZE 4096

/* #define DEBUG */

struct rvcnet_priv {
    union {
        uint8_t *rx_buf_raw;
        uint32_t *rx_buf_size;
    };
    uint8_t *rx_buf;
    uint8_t *tx_buf;
};

#ifdef DEBUG
static void pkt_hex_dump(struct sk_buff *skb, const char *info)
{
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch;

    data = (uint8_t *) skb_mac_header(skb);

    if (skb_is_nonlinear(skb)) {
        len = skb->data_len;
        pr_info("%s (nonlinear)", info);
    } else {
        len = skb->len;
        pr_info("%s (linear)", info);
    }

    remaining = len;
    for (i = 0; i < len; i += rowsize) {
        printk("%06d\t", li);

        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++) {
            ch = data[l];
            printk(KERN_CONT "%02X ", (uint32_t) ch);
        }

        data += linelen;
        li += 10;

        printk(KERN_CONT "\n");
    }
}
#endif

static netdev_tx_t rvcnet_xmit(struct sk_buff *skb,
                               struct net_device *dev)
{
    int len;
    uint8_t *data;
    struct rvcnet_priv *priv = netdev_priv(dev);

    skb_tx_timestamp(skb);

    data = (uint8_t *) skb_mac_header(skb);
    if (skb_is_nonlinear(skb)) {
        len = skb->data_len;
    } else {
        len = skb->len;
    }

    skb_tx_timestamp(skb);

#ifdef DEBUG
    pr_info("rvcnet_xmit: len %d\n", len);
    pkt_hex_dump(skb, "rvcnet_tx:\n");
#endif

    memcpy_toio(priv->tx_buf, data, len);
    csr_set(CSR_NET_TX_BUF_SIZE_AND_SEND, len);

    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static void rvcnet_get_stats64(struct net_device *dev,
                 struct rtnl_link_stats64 *stats)
{
    stats->rx_packets = 0;
    stats->tx_packets = 0;
    stats->rx_bytes   = 0;
    stats->tx_bytes   = 0;
}

static u32 always_on(struct net_device *dev)
{
    return 1;
}

static const struct ethtool_ops rvcnet_ethtool_ops = {
    .get_link           = always_on,
    .get_ts_info        = ethtool_op_get_ts_info,
};

static int rvcnet_dev_init(struct net_device *dev)
{
    return 0;
}

static void rvcnet_dev_free(struct net_device *dev)
{
    struct rvcnet_priv *priv = netdev_priv(dev);
    iounmap(priv->rx_buf_raw);
    iounmap(priv->tx_buf);
}

static const struct net_device_ops rvcnet_ops = {
    .ndo_init        = rvcnet_dev_init,
    .ndo_start_xmit  = rvcnet_xmit,
    .ndo_get_stats64 = rvcnet_get_stats64,
    .ndo_set_mac_address = eth_mac_addr,
};

static void rvcnet_setup(struct net_device *dev)
{
    struct rvcnet_priv *priv = netdev_priv(dev);
    phys_addr_t addr_tmp;

    dev->mtu = 1024 - ETH_HLEN;
    dev->hard_header_len = ETH_HLEN; /* 14 */
    dev->min_header_len = ETH_HLEN; /* 14 */
    dev->addr_len = ETH_ALEN; /* 6 */
    dev->type = ARPHRD_ETHER;
    dev->flags = 0;
    dev->priv_flags |= IFF_NO_QUEUE | IFF_BROADCAST;
    dev->hw_features = NETIF_F_GSO_SOFTWARE;
    dev->features = 0;
    dev->ethtool_ops = &rvcnet_ethtool_ops;
    dev->header_ops = &eth_header_ops;
    dev->netdev_ops = &rvcnet_ops;
    dev->needs_free_netdev  = true;

    eth_hw_addr_random(dev);
    memset(dev->broadcast, 0xFF, MAX_ADDR_LEN);

    dev->priv_destructor = rvcnet_dev_free;

    addr_tmp = (phys_addr_t)csr_read(CSR_NET_RX_BUF_ADDR);
    priv->rx_buf_raw = ioremap(addr_tmp, MAX_BUF_SIZE);
    priv->rx_buf = priv->rx_buf_raw + sizeof(priv->rx_buf_size);
    addr_tmp = (phys_addr_t)csr_read(CSR_NET_TX_BUF_ADDR);
    priv->tx_buf = ioremap(addr_tmp, MAX_BUF_SIZE);

    csr_set(CSR_NET_RX_BUF_READY, 1);
}

static irqreturn_t rvcnet_interrupt(int irq, void *dev_id)
{
    int ret;
    struct sk_buff *skb;
    struct net_device *dev = (struct net_device*) dev_id;
    struct rvcnet_priv *priv = netdev_priv(dev);

    // data in priv is available via MMIO
    skb = netdev_alloc_skb(dev, *priv->rx_buf_size);
    skb->dev = dev;
    memcpy_fromio(skb_put(skb, ETH_HLEN), priv->rx_buf, ETH_HLEN);
    memcpy_fromio(skb_put(skb, *priv->rx_buf_size), priv->rx_buf + ETH_HLEN, *priv->rx_buf_size - ETH_HLEN);
    skb->protocol = eth_type_trans(skb, dev);

#ifdef DEBUG
    pkt_hex_dump(skb, "rvcnet_rx:\n");
    pr_info("rvcnet_interrupt: rx_buf_size %d\n", *priv->rx_buf_size);
#endif
    ret = netif_rx(skb);

    csr_set(CSR_NET_RX_BUF_READY, 1);
    return IRQ_HANDLED;
}

/* Setup and register the rvcnet device. */
static int rvcnet_probe(struct platform_device *pdev)
{
    struct net_device *dev;
    struct device_node *dn;
    struct irq_domain *domain;
    int err;
    int irq;

    err = -ENOMEM;
    dev = alloc_netdev(sizeof(struct rvcnet_priv), "rvcnet", NET_NAME_UNKNOWN, rvcnet_setup);
    if (!dev)
        goto out;

    platform_set_drvdata(pdev, dev);
    SET_NETDEV_DEV(dev, &pdev->dev);

    err = register_netdev(dev);
    if (err)
        goto out_free_netdev;

    pr_info("rvcnet: registered netdevice '%s' (%02x:%02x:%02x:%02x:%02x:%02x)\n", dev->name,
            dev->dev_addr[0], dev->dev_addr[1], dev->dev_addr[2],
            dev->dev_addr[3], dev->dev_addr[4], dev->dev_addr[5]);

    dn = of_cpu_device_node_get(0);
    if (!dn) {
        pr_err("rvcnet: failed to get device node\n");
        err = -ENODEV;
        goto out_free_netdev;
    }

    dn = of_get_compatible_child(dn, "riscv,cpu-intc");
    if (!dn) {
        pr_err("rvcnet: failed to find INTC node\n");
        err = -ENODEV;
        goto out_free_netdev;
    }
    domain = irq_find_host(dn);
    of_node_put(dn);
    if (!domain) {
        pr_err("rvcnet: failed to find IRQ domain for node\n");
        err = -ENODEV;
        goto out_free_netdev;
    }

    irq = irq_create_mapping(domain, RV_IRQ_EXT);
    if (!irq) {
        pr_err("rvcnet: failed to map RV_IRQ_EXT interrupt\n");
        err = -ENODEV;
        goto out_free_netdev;
    }

    err = request_percpu_irq(irq, rvcnet_interrupt,
                             "rvcnet", dev);
    if (err) {
        pr_err("rvcnet: registering percpu irq failed: %d\n", err);
        goto out_free_netdev;
    }

    enable_percpu_irq(irq, irq_get_trigger_type(irq));

    pr_info("rvcnet: registered IRQ %d\n", irq);

    return 0;

out_free_netdev:
    free_netdev(dev);
out:
    return err;
}

static int rvcnet_remove(struct platform_device *pdev)
{
    struct net_device *dev;

    dev = platform_get_drvdata(pdev);

    if (dev) {
        unregister_netdev(dev);
        free_percpu_irq(dev->irq, dev);
        free_netdev(dev);
    }

    return 0;
}

static const struct of_device_id __maybe_unused rvcnet_of_match[] = {
    { .compatible = "pi,rvcnet", },
    { }
};
MODULE_DEVICE_TABLE(of, rvcnet_of_match);

static struct platform_driver rvcnet_driver = {
    .probe  = rvcnet_probe,
    .remove = rvcnet_remove,
    .driver = {
        .name = "rvcnet",
    },
};

module_platform_driver(rvcnet_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RVCNET virtual network driver");
MODULE_AUTHOR("_pi_ <pi@pimaker.at>");
