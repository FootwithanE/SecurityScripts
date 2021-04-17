#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <string.h>

#define SIZE_ETHERNET 14
#define PACKET_LEN 512

// Ethernet header
struct eth_header
{
    u_char ether_dhost[ETHER_ADDR_LEN]; // Destination address
    u_char ether_shost[ETHER_ADDR_LEN]; // Source address
    u_short ether_type;
};

// IP header
struct ip_header
{
    u_char ip_ihl : 4, // version
        ip_ver : 4;    // internet header length
    u_char ip_tos;     // type of service
    u_short ip_len;    // length
    u_short ip_id;     // id
    u_short ip_flagf : 3,
        ip_off : 13;       // fragment offset field
    u_char ip_ttl;         // time to live
    u_char ip_protocol;    // protocol
    u_short ip_sum;        // checksum
    struct in_addr ip_src; // source address
    struct in_addr ip_dst; // dest address
};

// Calculate header length (*4) and Version from ihl
#define IP_HL(ip) (((ip)->ip_ihl) & 0x0f)
#define IP_V(ip) (((ip)->ip_ihl) >> 4)

// TCP header
struct tcp_header
{
    u_short th_sport; // source port
    u_short th_dport; // destination port
    u_int th_seq;     // sequence number
    u_int th_ack;     // acknowledgement number
    u_char th_offx2;  // data offset, rsvd
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; // window
    u_short th_sum; // checksum
    u_short th_urp; // urgent pointer
};

// ICMP header
struct icmp_header
{
    u_char icmp_type;    // message type
    u_char icmp_code;    // error code
    u_short icmp_chksum; // checksum for icmp data
    u_short icmp_id;     // id request
    u_short icmp_seq;    // seq number
};

// used in checksum calc
unsigned short in_cksum(u_short *buf, int length)
{
    u_short *w = buf;
    int nleft = length;
    int sum = 0;
    u_short temp = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (u_short)(~sum);
};

// pseudo TCP header
struct pseudo_tcp
{
    unsigned saddr, daddr;
    u_char mbz;
    u_char ptcl;
    u_short tcpl;
    struct tcp_header tcp;
    char payload[PACKET_LEN];
};

// calculate TCP checksum
unsigned short calculate_tcp_checksum(struct ip_header *ip)
{
    struct tcp_header *tcp = (struct tcp_header *)((u_char *)ip + sizeof(struct ip_header));
    int tcp_len = ntohs(ip->ip_len) - sizeof(struct ip_header);

    struct pseudo_tcp p_tcp;
    memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

    p_tcp.saddr = ip->ip_src.s_addr;
    p_tcp.daddr = ip->ip_dst.s_addr;
    p_tcp.mbz = 0;
    p_tcp.ptcl = IPPROTO_TCP;
    p_tcp.tcpl = htons(tcp_len);
    memcpy(&p_tcp.tcp, tcp, tcp_len);

    return (u_short)in_cksum((u_short *)&p_tcp, tcp_len + 12);
};

// send a raw packet
void send_raw_packet(struct ip_header *ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // create new socket
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0)
    {
        fprintf(stderr, "Failed to create socket");
    }
    // set socket options
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    // destination information
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->ip_dst;
    // send packet
    sendto(sd, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sd);
};

// Parse packet information
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // buffer for packet creation
    char buffer[1500];
    // set buffer to 0
    memset(buffer, 0, 1500);

    struct icmp_header *icmp = (struct icmp_header *)(buffer + sizeof(struct ip_header));
    icmp->icmp_type = 8; // 8 request, 0 reply

    // calc checksum
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((u_short *)icmp, sizeof(struct icmp_header));

    struct ip_header *ip = (struct ip_header *)buffer;
    ip->ip_ver = 4;
    ip->ip_ihl = 4;
    ip->ip_ttl = 20;
    ip->ip_src.s_addr = inet_addr("10.0.2.5");
    ip->ip_dst.s_addr = inet_addr("10.0.2.15");
    ip->ip_protocol = IPPROTO_ICMP;
    ip->ip_len = htons(sizeof(struct ip_header) + sizeof(struct icmp_header));

    send_raw_packet(ip);

    return;
};

void spoof_packet(struct ip_header *ip)
{
    const char buffer[1500];
    int ip_header_len = ip->ip_ihl * 4;
    struct icmp_header *icmp = (struct icmp_header *)((u_char *)ip + ip_header_len);

    //copy original ip header
    memset((char *)buffer, 0, 1500);
    memcpy((char *)buffer, ip, ntohs(ip->ip_len));
    printf("Length: %d\n", ntohs(ip->ip_len));

    struct ip_header *new_ip = (struct ip_header *)buffer;
    struct icmp_header *new_icmp = (struct icmp_header *)(buffer + sizeof(struct ip_header));
    new_icmp->icmp_type = 0;

    // calc checksum
    new_icmp->icmp_chksum = 0;
    new_icmp->icmp_chksum = in_cksum((u_short *)icmp, sizeof(ip));

    new_ip->ip_src = ip->ip_dst;
    new_ip->ip_dst = ip->ip_src;
    new_ip->ip_ttl = 50;
    new_ip->ip_len = ip->ip_len;

    printf("   Sent From: %s\n", inet_ntoa(new_ip->ip_src));
    printf("     Sent To: %s\n", inet_ntoa(new_ip->ip_dst));

    send_raw_packet(new_ip);
};

// Deconstruct packet for information
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    u_int size_ip;
    u_int size_tcp;
    u_int size_payload;
    struct eth_header *eth = (struct eth_header *)(packet);
    if (ntohs(eth->ether_type) == 0x0800)
    {
        struct ip_header *ip = (struct ip_header *)(packet + SIZE_ETHERNET);
        //printf("        From: %s\n", inet_ntoa(ip->ip_src));
        //printf("          To: %s\n", inet_ntoa(ip->ip_dst));

        switch (ip->ip_protocol)
        {
        case IPPROTO_TCP:
            //		printf("    Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            //		printf("    Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("    Protocol: ICMP\n");
            spoof_packet(ip);
            return;
        default:
            //		printf("    Protocol: Other\n");
            return;
        }

        //size_ip = IP_HL(ip)*4;
        //printf("     IP Size: (%d bytes)\n", size_ip);
        //struct tcp_header *tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
        //size_tcp = TH_OFF(tcp)*4;
        //printf("    TCP Size: (%d bytes)\n", size_tcp);
        //const char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        //printf("  IP Len tot: (%d bytes)\n", ntohs(ip->ip_len));
        //size_payload = ntohs(ip->ip_len)-(size_ip + size_tcp);
        //printf("Payload Size: (%d bytes)\n", size_payload);
        //if (size_payload > 0){
        //	print_payload(payload, size_payload);
        //}
    }
};

// Main sniffs for ICMP Echo request and send spoofed Reply
int main(int argc, char *argv[])
{
    char *device = argv[1];
    char *filter = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;

    //Get network info from net and mask lookup
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
    }

    //Open net work device based on dev interface (i.e. eth0)
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
    }

    // compile the filter expression
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return (2);
    }

    // apply filter
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't set filter %s: %s\n", filter, pcap_geterr(handle));
        return (2);
    }

    // retrieve packet and send it to handler
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
