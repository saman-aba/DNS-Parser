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

uint32_t    dns_rr_parser       (const char *in, uint32_t *offt, dns_msg_t *out)
{
    if(out == NULL)
        return -1;

    uint32_t position = *offt;

    for(int i= 0 ; i < out->dheader->qdcount; i++)
    {
        dns_rr_t *rr = malloc(sizeof(dns_rr_t));
        uint32_t name_len = 0;
        uint32_t lbl_count = 0;
        uint32_t lbl_len = 0;
        while(in[position] != 0x00)
        {
            if((in[position] & 0xc0) == 0xc0)
            {
                position = in[position + 1] & 0x3f;
            }
            lbl_len = in[position] & 0x3f;
            position++;
            name_len += lbl_len;
            position += lbl_len;
            lbl_count++;
        }
        name_len += (lbl_count - 1);
        position -= (name_len + 1);

        char name[name_len];
        uint32_t name_pos = 0;
        while(in[position] != 0X00)
        {
            lbl_len = in[position] & 0x3f;
            position++;
            for(int j = 0 ; j < lbl_len ; j++)
            {
                name[name_pos] = in[position];
                name_pos++;
                position++;
            }
            if(name_pos != name_len)
            {
                name[name_pos] = '.';
                name_pos++;
            }

        }
        rr->name = name;

        out->question = rr;

    }
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