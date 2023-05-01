#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>

#define NO_PORT 0
#define PACKET_SIZE 16
#define HEADER_SIZE 8
#define MESSAGE_SIZE 8

struct icmp_pkt
{
    struct icmphdr hdr;
    char msg[MESSAGE_SIZE];
};

uint16_t calcChecksum(struct icmp_pkt *pkt);

uint16_t calcChecksum(struct icmp_pkt *pkt)
{
    int len = sizeof(*pkt);
    unsigned short *buf = (unsigned short*) pkt;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char const *argv[])
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == -1) {
        printf("Socket error\n");
        return;
    }

    uint32_t IPv4Address = htonl(0x88246801);

    // Create packet
    // RFC 792
    struct icmp_pkt pkt;

    memset(&pkt, 0x00, sizeof(pkt));

    pkt.hdr.type = ICMP_ECHO;
    pkt.hdr.code = 0x0;
    pkt.hdr.un.echo.id = 0x1234;
    pkt.hdr.un.echo.sequence = 0x4321;
    memcpy(pkt.msg, "01234567", MESSAGE_SIZE);
    pkt.hdr.checksum = calcChecksum(&pkt);

    // Send packet
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(NO_PORT);
    dest_addr.sin_addr.s_addr = IPv4Address;

    printf("%s\n", inet_ntoa(dest_addr.sin_addr));

    printf("host: %ld\nnetwork: %ld\n", IPv4Address, htonl(IPv4Address));

    if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1)
    {
        printf("%i\n", errno);
        printf("Socket send error\n");
        return;
    }

    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    return;
}