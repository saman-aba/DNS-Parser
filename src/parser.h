#include <stdint.h>

typedef struct _dns_header dns_header_t;
typedef struct _dns_msg dns_msg_t;
struct _dns_header{
    uint16_t id;
    uint8_t QR;
    uint8_t opcode;
    uint8_t AA;
    uint8_t TC;
    uint8_t RD;
    uint8_t RA;
    uint8_t res;
    uint8_t AD;
    uint8_t CD;
    uint8_t rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    char *rest;
};

struct _dns_rr{
    char *name;

};

struct _dns_msg{
    dns_header_t *dheader;

};

void dns_header_parser(const char *in, uint32_t offt, dns_msg_t *out);

