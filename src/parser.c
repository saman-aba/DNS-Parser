#include "dns_parser.h"

void dns_parser(uint32_t pos, dns_header_t *dns, char *payload)
{
    uint32_t id_pos = pos;
    dns->id = payload[id_pos];
}
