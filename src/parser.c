#include "parser.h"
#include "gutils.h"
void parse_dns(const char *in, uint32_t offt, dns_msg_t *out)
{
    if(out == NULL)
        out = malloc(sizeof(dns_msg_t));
    dns_header_parser(in,&offt,out);
    
}

uint32_t dns_header_parser  (const char *in, uint32_t *offt, dns_msg_t *out)
{
    if(out->dheader == NULL)
        out->dheader = malloc(sizeof(dns_header_t));
    dns_header_t *hdr = out->dheader;

    uint32_t position = *offt;
    
    hdr->id = (in[position] << 8) + in[position + 1];
    position += 2;

    hdr->QR     =   (in[position] & 0x80)   >> 7;
    hdr->opcode =   (in[position] & 0x70)   >> 4; 
    hdr->AA     =   (in[position] & 0x04)   >> 2;
    hdr->TC     =   (in[position] & 0x02)  >> 1;
    hdr->RD     =   in[position] & 0x01;
    position++;

    hdr->RA     =   (in[position] & 0x80)  >> 7;
    hdr->res    =   (in[position] & 0x40)  >> 6;
    hdr->AD     =   (in[position] & 0x20)  >> 5;
    hdr->CD     =   (in[position] & 0x10)  >> 4;
    hdr->rcode  =   in[position] & 0x0f;
    position++;

    hdr->qdcount =  (in[position] << 8) + in[position + 1] ;
    position += 2;
    hdr->ancount =  (in[position] << 8) + in[position + 1];
    position += 2;
    hdr->nscount =  (in[position] << 8) + in[position + 1];
    position += 2;
    hdr->arcount=   (in[position] << 8) + in[position + 1];   
    position += 2;

    *offt = position;

    return 0;
}

void print_dns_header(dns_msg_t *msg)
{
    char *operation;
    switch (msg->dheader->opcode) {
        case OP_QUERY:  operation = "standard";
            break;
        case OP_IQUERY: operation = "Inverse Query";
            break;
        case OP_NOTIFY: operation = "Notify";
            break;
        case OP_STATUS: operation = "Status";
            break;
        case OP_DDNS:   operation = "Dynamic DNS";
            break;
        case OP_NSID:   operation = "NSID";
            break;
        default:
            break;
    }
    char *rcode;
    switch(msg->dheader->rcode)
    {
        case R_NOERR: rcode = "No error";
            break;
        case R_FORMERR1: rcode = "Format error";

    }
    LINE;
    printf("Q/R : %s\tOp Code : %s\tRCode : %s\n",
           (msg->dheader->QR ? "Response": "Question"),
           operation,
           rcode);
    printf("Questions: %u\tAnswers: %u\tAuthorities: %u\tAdditionals %u\t",
           msg->dheader->qdcount,
           msg->dheader->ancount,
           msg->dheader->qdcount,
           msg->dheader->arcount);
}