#include <windows.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <winsock2.h>

#define SIO_RCVALL 0x98000001

typedef struct IPHeader {
    unsigned char iph_verlen;
    unsigned char iph_tos;
    unsigned short iph_length;
    unsigned short iph_id;
    unsigned short iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short iph_xsum;
    unsigned long iph_src;
    unsigned long iph_dest;
}IPHeader;

typedef struct UDP {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short lenght;
    unsigned short CRC;
    unsigned char *data;
}UDP;

typedef struct TCP {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned long sequence_number;
    unsigned long accept_number;

    //unsigned short data_shift:4;
    //unsigned short reserved:6;
    //unsigned short flags:6;
    unsigned short drf;

    unsigned short frame;
    unsigned short CRC;
    unsigned short important;
    unsigned long data;
}TCP;

typedef struct ICMP {
    unsigned char type;
    unsigned char code;
    unsigned short CRC;
    char *data;
}ICMP;

typedef union UADDR {
    unsigned long ip;
    struct
    {
        unsigned char a, b, c, d;
    }oct;
}uaddr;
