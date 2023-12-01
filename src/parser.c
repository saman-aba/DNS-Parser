#include "parser.h"
#include "gutils.h"
dns_msg_t *parse_dns(const char *in, uint32_t offt)
{
    dns_msg_t *dns = malloc(sizeof(dns_msg_t));
    dns->dheader = dns_header_parser(in, &offt);
    dns_question_parser(in, &offt, dns);
}

dns_header_t *dns_header_parser  (const char *in, uint32_t *offt)
{
    dns_header_t *hdr = malloc(sizeof(dns_header_t));

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
    return hdr;
}

uint32_t dns_question_parser (const char *in, uint32_t *offt, dns_msg_t *out)
{
    if(out == NULL)
        return -1;
    uint32_t offset = *offt;
    dns_question_t *q = malloc(sizeof(dns_question_t));

    
    uint32_t name_ln = 0, label_count = 0;
    q->qname = rr_name_parser(in, &offset, &name_ln, &label_count);
    q->lblcount = name_ln;
    q->nameln = label_count;
    q->qtype  = (in[offset] << 8) + in[offset + 1];
    offset += 2;
    q->qclass = (in[offset] << 8) + in[offset + 1];
    offset += 2;
    q->next = NULL;

    *offt = offset;
    out->question = q;
}

uint32_t dns_rr_parser (const char *in, uint32_t *offt, dns_msg_t *out)
{
    // if(out == NULL)
    //     return -1;
    
    // dns_rr_t *rr = malloc(sizeof(dns_rr_t));
    
    // rr->name = rr_name_parser(in, offt);

    // out->question = rr;

    
     return 0;
}

char *rr_name_parser (const char *in, uint32_t *offt, uint32_t *ln, uint32_t *lbl_cnt)
{
    uint32_t    name_ln = 0,
                lbl_count = 0,
                lbl_len = 0, 
                position = *offt;
    
    if((in[position] & 0xc0) == 0xc0)
        position = in[position + 1] & 0x3f;

    while(in[position] != 0x00)
    {
        lbl_len = in[position] & 0x3f;
        position++;
        name_ln += lbl_len;
        position += lbl_len;
        lbl_count++;
    }
    name_ln += (lbl_count - 1);
    position -= (name_ln + 1);

    char *name = malloc(sizeof(char) * (name_ln));

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
        if(name_pos != name_ln)
        {
            name[name_pos] = '.';
            name_pos++;
        }
    }

    if((in[*offt] & 0xc0) == 0xc0)
        *offt += 2;
    else
        *offt = position + 1;
     *ln = name_ln;
     *lbl_cnt = lbl_count;
    return name;
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
            break;

    }
    LINE;
    printf("Q/R : %s\tOp Code : %s\tRCode : %s\n",
           (msg->dheader->QR ? "Response": "Question"),
           operation,
           rcode);
    printf("Questions: %u\tAnswers: %u\tAuthorities: %u\tAdditionals %u\n",
           msg->dheader->qdcount,
           msg->dheader->ancount,
           msg->dheader->qdcount,
           msg->dheader->arcount);
}

void print_dns_question (dns_msg_t *msg)
{
    char *qtype;
    switch (msg->question->qtype) {
        case RR_TYP_A:      qtype = "A";
            break;
        case RR_TYP_QA:     qtype = "AAAA";
            break;
        case RR_TYP_CNAME:  qtype = "CNAME";
            break;
        case RR_TYP_NAPTR:  qtype = "NAPTR";
            break;
        case RR_TYP_NS:     qtype = "NS";
            break;
        default:
            break;
    }

    char *qclass;
    switch(msg->question->qclass)
    {
        case RR_CLS_CH: qclass = "CHAOS";
            break;
        case RR_CLS_HS: qclass = "HESIOD";
            break;
        case RR_CLS_IN: qclass = "IN";
            break;

    }
    LINE;
    printf("Name : %s\nName Length : %u\tLable Count : %u\nClass : %s\tType : %s\n",
            msg->question->qname,
            msg->question->lblcount,
            msg->question->nameln,
            qclass,
            qtype);
}


void print_dns_rr (dns_msg_t *msg)
{
    char *qtype;
    switch (msg->question->qtype) {
        case RR_TYP_A:      qtype = "A";
            break;
        case RR_TYP_QA:     qtype = "AAAA";
            break;
        case RR_TYP_CNAME:  qtype = "CNAME";
            break;
        case RR_TYP_NAPTR:  qtype = "NAPTR";
            break;
        case RR_TYP_NS:     qtype = "NS";
            break;
        default:
            break;
    }

    char *qclass;
    switch(msg->question->qclass)
    {
        case RR_CLS_CH: qclass = "CHAOS";
            break;
        case RR_CLS_HS: qclass = "HESIOD";
            break;
        case RR_CLS_IN: qclass = "IN";
            break;

    }
    LINE;
    printf("Name : %s\tLength : %u\tLable Count : %u\nClass : %s\tType : %s\n",
            msg->question->qname,
            msg->question->lblcount,
            msg->question->nameln,
            qclass,
            qtype);
}