#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>
static uint32_t xorshift_state = 2463534242u;
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DNSHeader;
typedef struct {
	unsigned char qname[12];
	uint16_t qtype;
	uint16_t qclass;
} Query;

uint32_t random32();
static uint16_t ip_checksum(struct iphdr *iph);
static uint16_t udp_checksum(
    const struct iphdr  *ip,
    const struct udphdr *udp,
    const DNSHeader      *header,
    const Query *query);
unsigned short csum (unsigned short *buf, int nwords);
void dns();
int main(){
	
	dns();
}
void dns(){
	int fd;
	fd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW); //IPPROTO_UDP
	if(fd<0){
		perror("socket");
	}
	int on = 1;
  	setsockopt (fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (int));
  	uint8_t *buf = calloc(1, 300); 
  	struct iphdr *iph = (struct iphdr*)buf;
  	struct udphdr *udph = (struct udphdr*)(buf+20);
	DNSHeader *header = (DNSHeader*)(buf+20+8);
	Query *query = (Query*)(buf+20+8+12);
	unsigned char enc[] = { 6,'g','o','o','g','l','e', 3,'c','o','m', 0 };
  	iph->ihl = 5;
  	iph->version = 4;
  	iph->tos = 0;
  	iph->tot_len = htons (20+8+12+12+4);
  	iph->id = htons(random32() & 0xffff);
  	iph->frag_off = 0;
  	iph->check = 0;
  	iph->protocol = IPPROTO_UDP;
  	iph->saddr = inet_addr([redacted]);
  	iph->daddr = inet_addr("8.8.8.8");
  	iph->check = ip_checksum(iph);
	udph->source=htons(random32()&0xffff);
	udph->dest=htons(53);
	udph->len=htons(8+12+12+4);
	udph->check=0;
	header->id=htons(666);
	header->flags=htons(0x0100);
	header->qdcount=htons(1);
	header->ancount=htons(0);
	header->nscount=htons(0);
	header->arcount=htons(0);
	memcpy(query->qname,enc,sizeof(enc));
	query->qtype=htons(1);
	query->qclass=htons(1);
	udph->check=udp_checksum(iph,udph,header,query);
	struct sockaddr_in dst;
	memset(&dst,0,sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = udph->dest;
	dst.sin_addr.s_addr = iph->daddr;
	int i = sendto(fd,buf,iph->tot_len,0,(struct sockaddr*)&dst,sizeof(dst));
	if(i<0){
		printf("FAILED");
		perror("sendto");
	}

}
uint32_t
random32()
{
  uint32_t x = xorshift_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  xorshift_state = x;
  return x;

}
static uint16_t ones_complement_sum(const void *buf, size_t len) {
    const uint8_t *b = buf;
    uint32_t sum = 0;
    while (len > 1) {
        sum += (b[0] << 8) | b[1];
        b += 2;
        len -= 2;
    }
    if (len) sum += (uint16_t)(b[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)sum;
}

static uint16_t ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    uint16_t s = ones_complement_sum(iph, iph->ihl * 4);
    return ~s;
}
static uint16_t udp_checksum(
    const struct iphdr  *ip,
    const struct udphdr *udp,
    const DNSHeader      *header,
    const Query *query)
{
    typedef struct __attribute__((packed)) {
        uint32_t source;
        uint32_t dest;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t udp_length;
    } pseudo_hdr;

    pseudo_hdr ps;
    ps.source = ip->saddr;
    ps.dest = ip->daddr;
    ps.zero = 0;
    ps.protocol = IPPROTO_UDP;
    ps.udp_length = udp->len;
    int udplen = ntohs(udp->len);
    int total_bytes = sizeof(pseudo_hdr) + udplen;
    uint8_t *buf = malloc(total_bytes + 1);
    if (!buf) return 0;

    
    memcpy(buf, &ps, sizeof(pseudo_hdr));
    memcpy(buf + sizeof(pseudo_hdr), udp, sizeof(struct udphdr));
    
    const uint8_t *udp_payload = (const uint8_t *)udp + sizeof(struct udphdr);
    int payload_len = udplen - sizeof(struct udphdr);
    if (payload_len > 0) memcpy(buf + sizeof(pseudo_hdr) + sizeof(struct udphdr), udp_payload, payload_len);
    if (total_bytes & 1) buf[total_bytes] = 0;
	int nwords = (total_bytes + 1) / 2;
    uint16_t sum = csum((uint16_t *)buf, nwords);
    free(buf);
    return sum;
}



unsigned short csum (unsigned short *buf, int nwords)
{
    unsigned long sum;

    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

