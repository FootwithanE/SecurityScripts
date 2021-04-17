#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <linux/inet.h>

/*Hook function structure for outgoing*/
static struct nf_hook_ops out_packets;
static struct nf_hook_ops in_packets;

/*Hook function for netfilter*/
unsigned int hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    __be32 this_machine;
    in4_pton("10.0.2.15", strlen("10.0.2.15"), (__u8 *)&this_machine, -1, NULL);
    struct iphdr *iph = ip_hdr(skb);
    // Dont allow ICMP req to machine A
    if (iph->daddr == this_machine && iph->protocol == IPPROTO_ICMP)
    {
        struct icmphdr *icmph = icmp_hdr(skb);
        if (icmph->type == ICMP_ECHO)
        {
            printk("Got an ICMP Echo request from: %pI4!", &iph->saddr);
            return NF_DROP;
        }
    }
    // If TCP packet checks
    if (iph->protocol == IPPROTO_TCP)
    {
        __be32 bad_web;
        in4_pton("93.184.216.34", strlen("93.184.216.34"), (__u8 *)&bad_web, -1, NULL);
        __be32 target_IP;
        in4_pton("10.0.2.5", strlen("10.0.2.5"), (__u8 *)&target_IP, -1, NULL);
        // Create TCP header structure
        struct tcphdr *tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
        // Prevent outgoing telent session to machine B
        if (tcph->dest == ntohs(23) && iph->daddr == target_IP)
        {
            printk("Telnet Connection attempted from IP: %pI4 to port: %d\n", &iph->saddr, htons(tcph->dest));
            return NF_DROP;
        }
        // Prevent incoming telent session to machine A
        if (tcph->dest == ntohs(23) && iph->saddr == target_IP)
        {
            printk("Telnet Connection attempted from IP: %pI4 to port: %d\n", &iph->saddr, htons(tcph->dest));
            return NF_DROP;
        }
        // Prevent access to example.com
        if (iph->daddr == bad_web)
        {
            printk("Connection to example.com attempted!!");
            return NF_DROP;
        }
        // Prevent SSH session from A to B
        if (tcph->dest == ntohs(22) && iph->daddr == target_IP)
        {
            printk("SSH Session attempted from IP: %pI4 to port: %d\n", &iph->saddr, htons(tcph->dest));
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

/*Initialization Routine*/
int __init hook_init(void)
{
    // Set and register outgoing hook
    out_packets.hook = hook_function;
    out_packets.hooknum = NF_INET_LOCAL_OUT;
    out_packets.pf = PF_INET;
    out_packets.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &out_packets);
    // Set and register incoming hook
    in_packets.hook = hook_function;
    in_packets.hooknum = NF_INET_PRE_ROUTING;
    in_packets.pf = PF_INET;
    in_packets.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &in_packets);

    return 0;
}

/*Cleanup Routine*/
void __exit hook_cleanup(void)
{
    nf_unregister_net_hook(&init_net, &out_packets);
    nf_unregister_net_hook(&init_net, &in_packets);
}

module_init(hook_init);
module_exit(hook_cleanup);