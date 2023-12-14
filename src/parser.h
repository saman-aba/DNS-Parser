#include <stdint.h>
#include <stdlib.h>

typedef struct dns_msg_ dns_msg_t;
typedef struct dns_header_ dns_header_t;
typedef struct dns_rr_ dns_rr_t;
typedef struct dns_question_ dns_question_t;

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

#define RR_CLS_IN   1   //  Internet
#define RR_CLS_CH   2    //  CHAOS
#define RR_CLS_HS   3    //  HESIOD

#define RR_TYP_NS       2
#define RR_TYP_A        1   
#define RR_TYP_QA       28   
#define RR_TYP_CNAME    5
#define RR_TYP_NAPTR    35


struct dns_question_{
    char *qname;
    uint32_t nameln;
    uint32_t lblcount;
    uint16_t qtype;
    uint16_t qclass;
    dns_question_t *next;
};

struct dns_rr_{
    char *name;
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    uint16_t rdlength;
    char *rdata;
    dns_rr_t *next;
};

struct dns_msg_{
    dns_header_t *dheader;
    dns_question_t *question;
    dns_rr_t *answer;
    dns_rr_t *authority;
    dns_rr_t *additional;
};


dns_msg_t *parse_dns (const char *in, uint32_t offt);

dns_header_t *dns_header_parser   (const char *in, uint32_t *offt);
uint32_t    dns_question_parser   (const char *in, uint32_t *offt, dns_msg_t *out);
uint32_t    dns_rr_parser       (const char *in, uint32_t *offt, dns_msg_t *out);

char *rr_name_parser (const char *in, uint32_t *offt, uint32_t *name_ln, uint32_t *lbl_count);

void print_dns_header   (dns_msg_t *msg);
void print_dns_question (dns_msg_t *msg);
void print_dns_rr       (dns_rr_t *rr);

