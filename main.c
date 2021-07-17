#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

#define PAYLOAD_PRINT_LENGTH 8

struct packet {
  struct pcap_pkthdr* header;
  uint8_t* data;
};

void print_help();
char* ip_ntoa(uint32_t);
char* mac_ntoa(uint8_t*);
char* payload_ntoa(uint8_t*, uint32_t);
pcap_t* _pcap_open(char*);
struct packet* _pcap_next(pcap_t*);

int main (int argc, char **argv) {
  if (argc != 2) {
    print_help();
    return -1;
  }

  pcap_t* pcap = _pcap_open(argv[1]);
  if (pcap == NULL) return -1;

  for (;;) {
    struct packet* pkt = _pcap_next(pcap);
    if (pkt == NULL) continue;
    
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *) pkt->data;
    if (eth_hdr->ether_type != htons(ETHERTYPE_IP)) continue;

    struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *) (pkt->data + LIBNET_ETH_H);
    if (ip_hdr->ip_p != IPPROTO_TCP) continue;

    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *) (pkt->data + LIBNET_ETH_H + LIBNET_IPV4_H);

    uint32_t payload_start = LIBNET_ETH_H + (ip_hdr->ip_hl + tcp_hdr->th_off) * 4;
    uint32_t payload_len = pkt->header->caplen - payload_start;
    uint8_t* payload_data = pkt->data + payload_start;

    char* src_mac = mac_ntoa(eth_hdr->ether_shost);
    char* dst_mac = mac_ntoa(eth_hdr->ether_dhost);
    char* src_ip = ip_ntoa(ip_hdr->ip_src.s_addr);
    char* dst_ip = ip_ntoa(ip_hdr->ip_dst.s_addr);
    char* payload = payload_ntoa(payload_data, payload_len);
    uint16_t src_port = ntohs(tcp_hdr->th_sport);
    uint16_t dst_port = ntohs(tcp_hdr->th_dport);

    printf("src mac:  %s\n", src_mac);
    printf("dst mac:  %s\n", dst_mac);
    printf("src ip:   %s\n", src_ip);
    printf("dst ip:   %s\n", dst_ip);
    printf("src port: %d\n", src_port);
    printf("dst port: %d\n", dst_port);
    printf("payload:  %s (total: %d)\n", payload, payload_len);

    printf("\n");
    
    free(pkt);
    free(src_mac);
    free(dst_mac);
    free(src_ip);
    free(dst_ip);
    free(payload);
  }
}

void print_help() {
  printf("syntax: pcap-test <interface>\n");
  printf("sample: pcap-test wlan0\n");
}

char* mac_ntoa(uint8_t* mac) {
  char* result = malloc(18);

  for (int i = 0; i < 6 ; i++)
    sprintf(result + (i * 3), "%02x%s", mac[i], i<5?":":"");

  return result;
}

char* ip_ntoa(uint32_t ip) {
  ip = htonl(ip);
  char* result = malloc(20);
  sprintf(result, "%d.%d.%d.%d", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
  return result;
}

char* payload_ntoa(uint8_t* payload, uint32_t len) {
  if (len > PAYLOAD_PRINT_LENGTH) len = PAYLOAD_PRINT_LENGTH;
  if (len < 1) {
    char* result = malloc(2);
    sprintf(result, "_");
    return result;
  }

  char* result = malloc(len * 4);

  for (int i = 0; i < len; i++)
    sprintf(result + (i * 3), "%02x%s", payload[i], i<len?" ":"");

  return result;
}

pcap_t* _pcap_open(char *interface) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

  if (pcap == NULL) {
    fprintf(stderr, "pcap_open_live() return null - %s\n", errbuf);
    exit(-1);
  }

  return pcap;
}

struct packet* _pcap_next(pcap_t* pcap) {
  struct pcap_pkthdr *pkt_header;
  const uint8_t *pkt_data;
  int res = pcap_next_ex(pcap, &pkt_header, &pkt_data);

  if (res == 0) return NULL;
  if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
    fprintf(stderr, "pcap_next_ex return %d - %s\n", res, pcap_geterr(pcap));
    exit(-1);
  }

  struct packet *pkt = malloc(sizeof(struct packet));
  pkt->header = pkt_header;
  pkt->data = (uint8_t*) pkt_data;

  return pkt;
}
