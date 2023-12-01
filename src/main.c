#include <stdlib.h>
#include <stdio.h>

#include "parser.h"

const char pload[] ={0x61, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x69, 
                    0x70, 0x76, 0x34, 0x6f, 0x6e, 0x6c, 0x79,
                    0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 
                    0x1c, 0x00, 0x01, 0x00, 0x00, 0x29, 0x05, 
                    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

typedef struct A{
    uint8_t one:1;
    uint8_t two:2;
    uint8_t three:2;
    uint8_t four:4;
} A_t;

typedef union B{
    A_t a;
    uint16_t b;
} B_t;

int main(int argc, char **argv)
{
    B_t b;

    b.b = 0x103f;
    printf("A one : %d\n" ,b.a.one);
    printf("A two : %d\n" ,b.a.two);
    printf("A three : %hu\n" ,b.a.three);
    printf("A four : %hu\n" ,b.a.four);
    printf("A Size : %lu\n" ,sizeof(b.a));
//    dns_header_t *header;
//    dns_parser(0, &dns_header, pload);

//    printf("TransactionId : %04x", ntohs(dns_header.id));
    return 0;
}