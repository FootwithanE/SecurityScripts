#include <stdio.h>
#include <pcap.h>

// ethernet headers are 14 bytes
#define SIZE_ETHERNET 14
// Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN 6
// Bytes per packet to capture
#define SNAP_LEN 1064

// Print ASCII chars
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;
    /* offset */
    printf("%05d   ", offset);
    /* hex */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("   ");
        }
    }
    printf("   ");
    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(" ");
        ch++;
    }
    printf("\n");
    return;
};

// Print payloads
void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16; /* number of bytes per line */
    int line_len;
    int offset = 0; /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (;;)
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    return;
};

// Ethernet header
struct eth_header
{
    u_char ether_dhost[ETHER_ADDR_LEN]; // dest address
    u_char ether_shost[ETHER_ADDR_LEN]; // source address
    u_short ether_type;
};

// IP header
struct ip_header
{
    u_char ip_vhl;                 // header length
    u_char ip_tos;                 // type of service
    u_short ip_len;                // length
    u_short ip_id;                 // id
    u_short ip_off;                // fragment offset field
#define IP_RF 0x8000               // reserved fragment flag
#define IP_DF 0x4000               // don't fragment flag
#define IP_MF 0x2000               // more fragments flag
#define IP_OFFMASK 0x1fff          // mask for fragmenting bits
    u_char ip_ttl;                 // time to live
    u_char ip_protocol;            // protocol
    u_short ip_sum;                // checksum
    struct in_addr ip_src, ip_dst; // source and dest address
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

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
        printf("        From: %s\n", inet_ntoa(ip->ip_src));
        printf("          To: %s\n", inet_ntoa(ip->ip_dst));

        switch (ip->ip_protocol)
        {
        case IPPROTO_TCP:
            printf("    Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("    Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("    Protocol: ICMP\n");
            return;
        default:
            printf("    Protocol: Other\n");
            return;
        }

        size_ip = IP_HL(ip) * 4;
        printf("     IP Size: (%d bytes)\n", size_ip);
        struct tcp_header *tcp = (struct tcp_header *)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;
        printf("    TCP Size: (%d bytes)\n", size_tcp);
        const char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        printf("  IP Len tot: (%d bytes)\n", ntohs(ip->ip_len));
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        printf("Payload Size: (%d bytes)\n", size_payload);
        if (size_payload > 0)
        {
            print_payload(payload, size_payload);
        }
    }
};

int main(int argc, char *argv[])
{
    char *dev = argv[1];
    char *filter_exp = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;

    //Get network info from net and mask lookup
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    //Open net work device based on dev interface (i.e. eth0)
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    }
    //"compile" the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    //Apply filter expression
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't set filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    //Retrieve a packet -1 for continuous loop
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_freecode(&fp);
    //Print packet length
    pcap_close(handle);
    printf("Device: %s\nFilter: %s\n", dev, filter_exp);
    return 0;
}