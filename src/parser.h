#include <stdint.h>
#include <stdlib.h>


#define OP_QUERY    0   //  Standard query
#define OP_IQUERY   1   //  Inverse query
#define OP_STATUS   2   //  DNS status request
#define OP_NSID     3
#define OP_NOTIFY   4
#define OP_DDNS     5

#define R_NOERR     0
#define R_FORMERR1  1   //  Format Error. Name server was unable to interpret the query
#define R_SERVFAIL  2   //  Server failure
#define R_NOTIMP    4   //  The name server does not support the requested operation
#define R_REFUSED   5   //  The name server refuses to perform the specified operation for policy reasons

typedef struct dns_header dns_header_t;
typedef struct dns_msg_ dns_msg_t;

struct dns_header_{
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

struct dns_rr_{
    char *name;

};

struct dns_msg_{
    dns_header_t *dheader;

};


void parse_dns          (const char *in, uint32_t offt, dns_msg_t *out);
void dns_header_parser  (const char *in, uint32_t offt, dns_msg_t *out);



