#include "parser.h"
#include "gutils.h"
void parse_dns          (const char *in, uint32_t offt, dns_msg_t *out)
{

    
}

uint32_t dns_header_parser  (const char *in, uint32_t *offt, dns_msg_t *out)
{
    if(!out->dheader)
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
    LINE;
    printf("Op Code\t: %d\n", msg->dheader->opcode);
    printf("Q/R\t: %s\n", (msg->dheader->QR ? "Response": "Question") );
}