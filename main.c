#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

#define PAYLOAD_PRINT_LENGTH 8
#define TCP_OPTION_SIZE 12

void printHelp();
char* mac_ntoa(uint8_t*);
char* payload_ntoa(uint8_t*);
pcap_t* pcapOpen(char*);
uint8_t* pcapNext(pcap_t*);

int main (int argc, char **argv) {
  if (argc != 2) {
    printHelp();
    return -1;
  }

  pcap_t* pcap = pcapOpen(argv[1]);
  if (pcap == NULL) return -1;

  for (;;) {
    uint8_t* pkt_data = pcapNext(pcap);
    
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *) pkt_data;
    if (eth_hdr->ether_type != htons(ETHERTYPE_IP)) continue;

    struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *) (pkt_data + LIBNET_ETH_H);
    if (ip_hdr->ip_p != IPPROTO_TCP) continue;

    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *) (pkt_data + LIBNET_ETH_H + LIBNET_IPV4_H);

    uint8_t* payload = pkt_data + LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H + TCP_OPTION_SIZE;

    printf("src mac: %s\n", mac_ntoa(eth_hdr->ether_shost));
    printf("dst mac: %s\n", mac_ntoa(eth_hdr->ether_dhost));
    printf("src ip: %s\n",  inet_ntoa(ip_hdr->ip_src));
    printf("dst ip: %s\n",  inet_ntoa(ip_hdr->ip_dst));
    printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
    printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));
    printf("data: %s\n", payload_ntoa(payload));

    printf("\n");
  }
}

void printHelp() {
  printf("syntax: pcap-test <interface>\n");
  printf("sample: pcap-test wlan0\n");
}

char* mac_ntoa(uint8_t* mac) {
  char* result = malloc(18);

  for (int i = 0; i < 6 ; i++)
    sprintf(result + (i * 3), "%02x%s", mac[i], i<5?":":"");

  return result;
}

char* payload_ntoa(uint8_t* payload) {
  char* result = malloc(PAYLOAD_PRINT_LENGTH * 4);

  for (int i = 0; i < PAYLOAD_PRINT_LENGTH; i++)
    sprintf(result + (i * 3), "%02x%s", payload[i], i<PAYLOAD_PRINT_LENGTH?" ":"");

  return result;
}

pcap_t* pcapOpen(char *interface) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

  if (pcap == NULL) {
    fprintf(stderr, "pcap_open_live() return null - %s\n", errbuf);
    return NULL;
  }

  return pcap;
}

uint8_t* pcapNext(pcap_t* pcap) {
  struct pcap_pkthdr *pkt_header;
  const uint8_t *pkt_data;
  int res = pcap_next_ex(pcap, &pkt_header, &pkt_data);

  if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
    fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
    return NULL;
  }

  return (uint8_t*)pkt_data;
}
