#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

void main()
{
    int PACKET_LEN = 512;
    char buffer[PACKET_LEN];
    struct sockaddr saddr;
    struct packet_mreq mr;
    // create RAW socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    // turn on promiscuous mode
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    // Getting captured packets from socket
    while (1)
    {
        int data_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr, (socklen_t *)sizeof(saddr));
        if (data_size)
            printf("Got one packet\n");
    }
    close(sock);
}