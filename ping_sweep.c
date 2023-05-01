#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
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

#define NUM_OF_IPV4_ADDRESS 4294967296

#define IP_ADDR_STRING_LEN 16
#define IP_ADDR_ZEROES 0x00000000
#define IP_ADDR_TWO_FIVE_FIVE 0xffffffff

#define MAXPACKET 4096
#define TIMEOUT_SEC 10
#define MAX_WORKERS 64
#define DEFAULT_WORKERS 16

#define PACKET_SIZE 16
#define HEADER_SIZE 8
#define MESSAGE_SIZE 8

#define USAGE_STRING "ping_sweep [workers] [output file]\n"

int main(int argc, char *argv[]);

struct icmp_pkt
{
    struct icmphdr hdr;
    char msg[MESSAGE_SIZE];
};

char *get_uint32_tasIPAddressString(uint32_t IPv4Address);
void printUint32_tAsIPAddressString(uint32_t IPv4Address);
uint32_t getEndAddress(int processIndex, int numOfProcesses);
uint32_t getStartAddress(int processIndex, int numOfProcesses);
suseconds_t getLatencyOfAddress(struct in_addr addr, int socket);
int pingAddressRange(uint32_t startIPv4Address, uint32_t endIPv4Address, FILE *output);
int pingAddress(struct in_addr addr, int sock);
void writeLatencyToFile(uint32_t IPv4Address, suseconds_t latency, FILE *output);
uint16_t calcChecksum(struct icmp_pkt *pkt);

// According to RFC 792
// Never going to be odd
//
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

char *get_uint32_tasIPAddressString(uint32_t IPv4Address)
{
    char *IPv4AddressString = malloc(IP_ADDR_STRING_LEN);

    for (uint8_t i = 0; i < IP_ADDR_STRING_LEN; ++i)
    {
        IPv4AddressString[i] = 0x00;
    }
    unsigned char firstOctet = IPv4Address >> 24;
    unsigned char secondOctet = (IPv4Address << 8) >> 24;
    unsigned char thirdOctet = (IPv4Address << 16) >> 24;
    unsigned char fourthOctet = (IPv4Address << 24) >> 24;

    sprintf(IPv4AddressString, "%i.%i.%i.%i", firstOctet, secondOctet, thirdOctet, fourthOctet);

    return IPv4AddressString;
}

void printUint32_tAsIPAddressString(uint32_t IPv4Address)
{
    unsigned char firstOctet = IPv4Address >> 24;

    unsigned char secondOctet = (IPv4Address << 8) >> 24;

    unsigned char thirdOctet = (IPv4Address << 16) >> 24;

    unsigned char fourthOctet = (IPv4Address << 24) >> 24;

    printf("%i.%i.%i.%i", (unsigned int)firstOctet, (unsigned int)secondOctet, (unsigned int)thirdOctet, (unsigned int)fourthOctet);
}

/* main.c */
int main(int argc, char *argv[])
{
    int numOfProcess = DEFAULT_WORKERS;
    FILE *outputFile;

    if (argc == 3)
    {
        numOfProcess = atoi(argv[1]);
        outputFile = fopen(argv[2], "w");
    }
    else
    {
        printf(USAGE_STRING);
        return 0;
    }

    if (numOfProcess > MAX_WORKERS)
    {
        printf(USAGE_STRING);
        printf("\tError: max of 32 workers\n");
    }

    __pid_t *pids = malloc(numOfProcess * sizeof(__pid_t));
    __pid_t parentPID = getpid();
    __pid_t childPID;

    int i = 0;
    // Fork processes
    while (i < numOfProcess - 1)
    {
        childPID = fork();

        if (childPID == 0)
        {
            break;
        }

        pids[i] = childPID;

        ++i;
    }

    // Generate IP ranges
    uint32_t startIPv4Address = getStartAddress(i, numOfProcess);
    uint32_t endIPv4Address = getEndAddress(i, numOfProcess);

    printf("Process number %i with pid %i is pinging: ", i, getpid());
    printUint32_tAsIPAddressString(startIPv4Address);
    printf("-");
    printUint32_tAsIPAddressString(endIPv4Address);
    printf("\n");

    if (!pingAddressRange(startIPv4Address, endIPv4Address, outputFile))
    {
        printf("Unknown error occured\n");
    }

    return 0;
}

int pingAddressRange(uint32_t startIPv4Address, uint32_t endIPv4Address, FILE *output)
{
    suseconds_t latency;
    struct in_addr curr_addr;
    curr_addr.s_addr = startIPv4Address;

    // Creating socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    struct timeval timeoutVal;
    timeoutVal.tv_sec = TIMEOUT_SEC;
    timeoutVal.tv_usec = 0;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               &timeoutVal, sizeof timeoutVal);

    if (sock == -1)
    {
        perror("Socket creation error\n");
        exit(1);
    }

    while (curr_addr.s_addr != endIPv4Address)
    {
        // Print out indicator
        if (curr_addr.s_addr % (1 << 8) == 0)
        {
            printf("%u: %s\n", getpid(), inet_ntoa(curr_addr));
            fflush(stdout);
        }

        // Actual latency measurement
        latency = getLatencyOfAddress(curr_addr, sock);

        fprintf(output, "%s,%u\n", inet_ntoa(curr_addr), latency);
        fflush(output);

        curr_addr.s_addr += 1;
    }

    return 1;
}

uint32_t getEndAddress(int processIndex, int numOfProcesses)
{
    uint64_t sectionSize = (((float)IP_ADDR_TWO_FIVE_FIVE) / (float)numOfProcesses);
    uint32_t startAddress = sectionSize * processIndex + sectionSize - 1;

    return startAddress;
}

uint32_t getStartAddress(int processIndex, int numOfProcesses)
{
    uint32_t sectionSize = (((float)IP_ADDR_TWO_FIVE_FIVE) / (float)numOfProcesses);
    uint32_t startAddress = sectionSize * processIndex;

    return startAddress;
}

suseconds_t getLatencyOfAddress(struct in_addr addr, int socket)
{
    printf("%u\n", addr.s_addr);
    struct timeval ping_start, ping_end;

    ping_start.tv_sec = 0;
    ping_start.tv_usec = 0;
    ping_end.tv_sec = 0;
    ping_end.tv_usec = 0;

    gettimeofday(&ping_start, NULL);
    if (pingAddress(addr, socket) == -1)
    {
        perror("Ping error\n");
        printf("Ping error\n");
        return 0;
    }
    gettimeofday(&ping_end, NULL);
    long elapsed_time = (ping_end.tv_sec - ping_start.tv_sec) * 1000 +
                        ((ping_end.tv_usec - ping_start.tv_usec) / 1000);
    return ping_end.tv_usec - ping_start.tv_usec;
}

// 0 is success
// -1 is error
//  1 is timeout
int pingAddress(struct in_addr addr, int socket)
{
    addr.s_addr = ntohl(addr.s_addr);       // Why does this work not htonl
    printf("%s sent\n", inet_ntoa(addr));

    // Create packet
    // RFC 792
    struct icmp_pkt pkt;

    memset(&pkt, 0x00, sizeof(pkt));

    pkt.hdr.type = ICMP_ECHO;
    pkt.hdr.code = 0x0;
    pkt.hdr.un.echo.id = 0x1234;
    pkt.hdr.un.echo.sequence = 0x4321;
    memcpy(pkt.msg, "01234567", MESSAGE_SIZE);
    pkt.hdr.checksum = 0x0000;
    pkt.hdr.checksum = calcChecksum(&pkt);

    // Send packet
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = (in_addr_t) htons(NO_PORT);
    dest_addr.sin_addr.s_addr = addr.s_addr;

    // printf("host: %ld\nnetwork: %ld\n", IPv4Address, htonl(IPv4Address));

    int sendtoResult = sendto(socket, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (sendtoResult == -1)
    {
        printf("Socket send error\n");
        return -1;
    }

    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    int recvResult = recvfrom(socket, &pkt, PACKET_SIZE, 0, (struct sockaddr *)&src_addr, &src_addr_len);

    // TIMEOUT
    if (errno == EAGAIN)
    {
        printf("Timeout\n");
        return 1;
    }

    if (recvResult == -1)
    {
        printf("Socket receive error\n");
        return -1;
    }

    printf("%s received\n", inet_ntoa(addr));

    return 0;
}

void writeLatencyToFile(uint32_t IPv4Address, suseconds_t latency, FILE *output)
{
    return;
}
