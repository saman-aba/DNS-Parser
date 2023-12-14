#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include "parser.h"

const char req[] ={
        0x01, 0x63, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x05, 0x61, 0x6c, 0x69, 0x76,
        0x65, 0x06, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00,
        0x01, 0x00, 0x00, 0x29, 0x05, 0xc0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
};

const char resp[] ={0xc0};

<<<<<<< HEAD
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char *argv[]) {
    int res;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */
    bpf_u_int32 ip_raw, net_msk_raw;
    pcap_if_t *devs;

    if (pcap_findalldevs(&devs, error_buffer) == -1 || !devs ) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    for(pcap_if_t *dev = devs ; dev ; dev = dev->next )
    {   
        if(dev->addresses)
        {
            pcap_

            inet_ntoa(dev->addresses->addr);
            printf("Device : %10s , Family : %2d, Address : %30s\n ",
                dev->name , dev->addresses->addr->sa_family, dev->description);
        }
    }




    // handle = pcap_open_live(
    //         device,
    //         BUFSIZ,
    //         packet_count_limit,
    //         timeout_limit,
    //         error_buffer
    //     );

    //  packet = pcap_next(handle, &packet_header);
    //  if (packet == NULL) {
    //     printf("No packet found.\n");
    //     return 2;
    // }

    // print_packet_info(packet, packet_header);

    // return 0;
}

void print_packet_info(const char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

// int main(int argc, char **argv)
// {
//     dns_msg_t *dns = malloc(sizeof(dns_msg_t));

//     uint32_t offset = 0;
//     dns_header_parser(req, &offset, dns);
// //    print_dns_header(dns);
//     dns_rr_parser(req, &offset, dns);

//     printf("Name: %s",dns->question->name);
// //    dns_header_t *header;
// //    dns_parser(0, &dns_header, pload);

// //    printf("TransactionId : %04x", ntohs(dns_header.id));
//     return 0;
// }
=======
int main(int argc, char **argv)
{
    uint32_t offset = 0;
    dns_msg_t *dns = parse_dns(req, offset);
    print_dns_header(dns);
    print_dns_question(dns);
    return 0;
}
>>>>>>> 04afa359d5e99dcc25947138df4fddb3ab4113fd
