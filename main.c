#include <windows.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include "net.h"
#include <stdio.h>
#include <winbase.h>

#define MAX_PACKET_SIZE 0x10000

typedef struct FILETER {
    unsigned long sip;
    unsigned long smask;
    unsigned short sport;
    unsigned long sbcast;
    unsigned long snetwork;
    unsigned long dip;
    unsigned long dmask;
    unsigned long dbcast;
    unsigned long dnetwork;
    unsigned short dport;
    unsigned char protocol;
    unsigned char decode;
}FILTER;
FILTER filter;

char Buffer[MAX_PACKET_SIZE];

WSADATA wsadata;
SOCKET s;
char name[128];
SOCKADDR_IN sa;
IN_ADDR sa1, sa2;
unsigned long iface = 0;
unsigned long flag = 1;
char filename[MAX_PATH] = "\0";
HANDLE hFile;
int breakflag;

unsigned long optval = 1, bytesret = 1;

CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;
HANDLE hStdout;

void usage(void) {
    printf("USAGE: -i [options]\n");
    printf(" -i interface_ip - IP address of interface for listening\n");
    printf(" -p - protocols for listening (icmp igmp ggp tcp pup udp idp nd raw)\n");
    printf(" -v - print packet to console\n");
    printf(" -f filename - dump packet to file\n");
    printf(" -x - print packet in hex-view. Use with -v and -f\n");
    printf(" -srcip ip- source IP address (default: 0.0.0.0)\n");
    printf(" -srcp port - source port (default: 0 (all))\n");
    printf(" -srcm mask - source BIT-mask (default: 0.0.0.0)\n");
    printf(" -dstip ip - destination IP address (default: 0.0.0.0)\n");
    printf(" -dstp port - destination port (default: 0 (all))\n");
    printf(" -dstm mask - destination BIT-mask (default: 0.0.0.0)\n");
}

int getip(char *ip,unsigned long *inet_ip) {
    uaddr *addr = (uaddr*)inet_ip;
    unsigned int i = -1, dots = 0, a, b, c, d;
    while(ip[++i]) {
        if(ip[i] < '0' || ip[i] > '9')
        if(ip[i] != '.') return 0;
        else ++dots;
    }
    if(dots != 3) return 0;
    sscanf(ip, "%i.%i.%i.%i", &a, &b, &c, &d);
    addr->oct.a=a;
    addr->oct.b = b;
    addr->oct.c=c;
    addr->oct.d = d;
    return 1;
}

int bit_to_netmask(char bitmask, unsigned long *netmask) {
    if(bitmask < 0 || bitmask > 32) return 0;
    int i;
    for(i = 0, *netmask = 0; i != 32; ++i, --bitmask) {
        *netmask = *netmask << 1;
        *netmask |= (bitmask > 0 ? 1 : 0);
    }
    return 1;
}

unsigned long inet_lton(unsigned long l_addr) {
    union ADDR {
        unsigned long naddr;
        struct OCTS {
            unsigned char d, c, b, a;
        }octs;
    }addr;
    addr.naddr = l_addr;
    unsigned char t;
    t = addr.octs.a;
    addr.octs.a = addr.octs.d;
    addr.octs.d = t;
    t = addr.octs.b;
    addr.octs.b = addr.octs.c;
    addr.octs.c = t;
    return addr.naddr;
}

int icmp_decode(unsigned char type, unsigned char code, char *buff) {
    switch(type) {
        case 0: lstrcpy(buff, "Echo Reply");
                break;
        case 3: lstrcpy(buff, "Address Unreachable: ");
            if(code == 0) lstrcat(buff, "Network Unreachable");
            else if(code == 1) lstrcat(buff, "Host Unreachable");
            else if(code == 2) lstrcat(buff, "Protocol Unreachable");
            else if(code == 3) lstrcat(buff, "Port Unreachable");
            else if(code == 4) lstrcat(buff, "Fragmentation Needing");
            else if(code == 5) lstrcat(buff, "Unknown Route From Source");
            else if(code == 6) lstrcat(buff, "Unknown Network");
            else if(code == 7) lstrcat(buff, "Unknown Host");
            else if(code == 8) lstrcat(buff, "Source Host Isolated");
            else if(code == 9) lstrcat(buff, "Network Administratively Denied");
            else if(code == 10) lstrcat(buff, "Host Administratively Denied");
            else if(code == 11) lstrcat(buff, "Network Unreachable For TOS");
            else if(code == 12) lstrcat(buff, "Host Unreachable For TOS");
            else if(code == 13) lstrcat(buff, "Comunications Administratively Denied");
            break;
        case 4: lstrcpy(buff, "Source Quench Message");
                break;
        case 5: lstrcpy(buff, "Redirecting: ");
            if(code == 0)lstrcat(buff, "Packets Redirecting To Network");
            else if(code == 1) lstrcat(buff, "Packets Redirecting To Host");
            else if(code == 2) lstrcat(buff, "Redirecting For TOS");
            else if(code == 3) lstrcat(buff, "Redirecting For TOS To Host");
            break;
        case 6: lstrcpy(buff, "Alternative host address");
            break;
        case 8: lstrcpy(buff, "Echo Request");
            break;
        case 9: lstrcpy(buff, "Router Discovery Message Reply");
            break;
        case 10: lstrcpy(buff, "Router Discovery Message Request");
            break;
        case 11: lstrcpy(buff, "TTL Is Left: ");
                 if(code == 0) lstrcat(buff, "TTL Is Left");
                 else if(code == 1) lstrcat(buff, "Fragmentation TTL Is Left ");
                 break;
        case 12: lstrcpy(buff, "Invalid Parameter: ");
                 if(code == 0) lstrcat(buff,"Pointer Error");
                 else if(code == 1) lstrcat(buff, "Needed Option Is Not Defined");
                 else if(code == 2) lstrcat(buff, "Incorrect length");
                 break;
        case 13: lstrcpy(buff, "Time Stamp Request");
            break;
        case 14: lstrcpy(buff, "Time Stamp Reply");
            break;
        case 15: lstrcpy(buff, "Information Request");
            break;
        case 16: lstrcpy(buff, "Information Reply");
            break;
        case 17: lstrcpy(buff, "Netmask Request");
            break;
        case 18: lstrcpy(buff, "Netmask Reply");
            break;
        case 30: lstrcpy(buff, "Trace Route");
            break;
        case 31: lstrcpy(buff, "Datagram Transformation Error");
            break;
        case 32: lstrcpy(buff, "Redirect For Mobile Host");
            break;
        case 33: lstrcpy(buff, "IPv6 Where-Are-You");
            break;
        case 34: lstrcpy(buff, "IPv6 I-Am-Here");
            break;
        case 35: lstrcpy(buff, "Redirect For Mobile Host Request");
            break;
        case 36: lstrcpy(buff, "Redirect For Mobile Host Reply");
            break;
        case 37: lstrcpy(buff, "Domain Name Request");
            break;
        case 38: lstrcpy(buff, "Domain Name Reply");
            break;
        case 39: lstrcpy(buff, "SKIP/Photuris: ");
                if(code == 0) lstrcat(buff, "Reserved");
                else if(code == 1) lstrcat(buff, "Unkown Security Parameters Index");
                else if(code == 2) lstrcat(buff, "Valid Security Parameters, but Authentication Failed");
                else if(code == 3) lstrcat(buff, "Valid Security Parameters, but Decryption Failed");
                break;
        default: wsprintf(buff, "Type - %i Code - %i", type, code);
    }
    return 0;
}

int printhex(char *buff, int size) {
    static char firsttime = 1, header[] = "Address  | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |      ASCII\n-----------------------------------------------------------------------------\n";
    static unsigned long addr = 0;
    if(!buff || !size) return 0;
    unsigned long readed, pos = 0;
    int hz, asd = 0, foo;
    if(firsttime && !(--firsttime)) printf(header);
    hz = size & 15;
    pos += size - hz;
    for(asd = 0; asd != size >> 4; ++asd) {
        printf("%.8X | ", addr);
        for(foo = 0; foo != 16; ++foo){
            printf("%.2X ",(unsigned char)buff[foo+(asd<<4)]);
        }
        putchar('|');
        putchar(' ');
        for(foo = 0; foo != 16; ++foo) {
            if(buff[foo + (asd << 4)] <= '\x1F') {
                putchar('.');
            }
            else {
                putchar(buff[foo + (asd << 4)]);
            }
        }
        putchar('\n');
        addr += 16;
    }
    if(hz) {
        printf("%.8X | ", addr);
        for(foo = 0; foo != hz; ++foo) {
            printf("%.2X ", (unsigned char)buff[foo + (asd << 4)]);
        }
        int i;
        for(i = 0; i != (16 - hz); ++i) {
            putchar(' ');
            putchar(' ');
            putchar(' ');
        }
        putchar('|');
        putchar(' ');
        for(foo = 0; foo != hz; ++foo) {
            if(buff[foo + (asd << 4)] <= '\x1F') {
                putchar('.');
            }
            else {
                putchar(buff[foo + (asd << 4)]);
            }
        }
        putchar('\n');
    }
    return 0;
}

int writehex(char *buff, int size) {
    static char firsttime = 1, header[] = "Address  | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |      ASCII\n-----------------------------------------------------------------------------\n";
    static unsigned long addr = 0;
    unsigned long bw;
    if(!buff || !size) {
        return 0;
    }
    unsigned long readed, pos = 0;
    int hz, asd = 0, foo;
    if(firsttime && !(--firsttime)) {
        WriteFile(hFile, header, 2, &bw, NULL);
    }
    hz = size & 15;
    pos += size - hz;
    for(asd = 0; asd != size >> 4; ++asd) {
        printf("%.8X | ", addr);
        for(foo = 0; foo != 16; ++foo) {
            printf("%.2X ", (unsigned char)buff[foo + (asd << 4)]);
        }
        putchar('|');
        putchar(' ');
        for(foo = 0; foo != 16; ++foo) {
            if(buff[foo + (asd << 4)] <='\x1F') {
                putchar('.');
            }
            else {
                putchar(buff[foo + (asd << 4)]);
            }
        }
        putchar('\n');
        addr += 16;
    }
    if(hz) {
        printf("%.8X | ", addr);
        for(foo = 0; foo != hz; ++foo) {
            printf("%.2X ", (unsigned char)buff[foo + (asd << 4)]);
        }
        int i;
        for(i = 0; i != (16 - hz); ++i) {
            putchar(' ');
            putchar(' ');
            putchar(' ');
        }
        putchar('|');
        putchar(' ');
        for(foo = 0; foo != hz; ++foo) {
            if(buff[foo + (asd << 4)] <= '\x1F') {
                putchar('.');
            }
            else {
                putchar(buff[foo + (asd << 4)]);
            }
        }
        putchar('\n');
    }
    return 0;
}

int params_parse(int argc, char **argv) {
    if(argc < 3) {
        usage();
        exit(0);
    }
    int param = 1;
    while(param <= argc - 1) {
        if(param <= argc - 1 && argv[param][0] == '-') {
            if(!lstrcmp(argv[param], "-i")) { //Interface
                if(!getip(argv[++param],&iface)) {
                    SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    printf("Invalid interface address %s\n", argv[param]);
                    SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
                    exit(-1);
                }
            }
            else if(!lstrcmp(argv[param], "-p")) { //Protocol
                ++param;
                while(param <= argc - 1 && argv[param][0] != '-') {
                    if(!lstrcmpi(argv[param], "icmp")) filter.protocol |= 1;
                    else if(!lstrcmpi(argv[param], "igmp")) filter.protocol |= 2;
                    else if(!lstrcmpi(argv[param], "ggp")) filter.protocol |= 4;
                    else if(!lstrcmpi(argv[param], "tcp")) filter.protocol |= 8;
                    else if(!lstrcmpi(argv[param], "pup")) filter.protocol |= 16;
                    else if(!lstrcmpi(argv[param], "udp")) filter.protocol |= 32;
                    else if(!lstrcmpi(argv[param], "idp")) filter.protocol |= 64;
                    else if(!lstrcmpi(argv[param], "nd")) filter.protocol |= 128;
                    else if(!lstrcmpi(argv[param], "raw")) filter.protocol |= 256;
                    else {
                        SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
                        printf("Invalid protocol name: %s\n", argv[param]);
                        SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
                        exit(-1);
                    }
                    ++param;
                }
                --param;
            }
            else if(!lstrcmp(argv[param], "-v")) filter.decode |= 1;
            else if(!lstrcmp(argv[param], "-f")) {
                ++param;
                if(param <= argc - 1) lstrcpy(filename, argv[param]), filter.decode |= 2;
                else {
                    SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    printf("File name is not specified\n");
                    SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
                    exit(-1);
                }
            }
            else if(!lstrcmp(argv[param++], "-x")) filter.decode |= 4;
            else if(!lstrcmp(argv[param], "-srcip")) {
                if(param <= argc - 1 && !getip(argv[++param], &filter.sip)) {
                    SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    printf("Invalid source IP address address\n", argv[param]);
                    SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
                    exit(-1);
                }
            }
            else if(!lstrcmp(argv[param], "-srcp")) {
                if(param <= argc - 1) filter.sport = atoi(argv[++param]);
                else {
                        SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
                        printf("Invalid source port\n");
                        SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
                        exit(-1);
                }
            }
            else if(!lstrcmp(argv[param], "-srcm")) {
                if(param <= argc - 1)filter.smask = atoi(argv[++param]);
                else {
                    SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    printf("Invalid source mask\n");
                    SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
                    exit(-1);
                }
            }
            else if(!lstrcmp(argv[param], "-dstip")) {
                if(param <= argc - 1 && !getip(argv[++param], &filter.dip)) {
                    SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    printf("Invalid destination IP address address\n", argv[param]);
                    SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
                    exit(-1);
                }
            }
            else if(!lstrcmp(argv[param], "-dstp")) {
                if(param<=argc-1) filter.dport = atoi(argv[++param]);
                else {
                    SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    printf("Invalid destination port\n");
                    SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
                    exit(-1);
                }
            }
            else if(!lstrcmp(argv[param], "-dstm")) {
                if(param <= argc - 1) filter.dmask = atoi(argv[++param]);
                else {
                    SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    printf("Invalid destination mask\n");
                    SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
                    exit(-1);
                }
            }
        }
        else {
            SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
            printf("Invalid argument \"%s\"\n", argv[param]);
            SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
            exit(-1);
        }
        ++param;
    }
}

BOOL HandlerRoutine(DWORD dwCtrlType) {
    if(dwCtrlType == CTRL_BREAK_EVENT) {
        breakflag = breakflag ? 0 : 1;
        return 1;
    }
    if(dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT) {
        SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
        ExitProcess(0);
    }
    return 0;
}

int main(int argc, char **argv) {
    breakflag = 0;
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(hStdout, &ConsoleScreenBufferInfo);
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)HandlerRoutine, 1);

    printf("Netdump for Windows\n(C) Aekzzz, 2009\n");
    memset((void*)&filter, 0, sizeof(FILTER));
    filter.decode = 0;
    params_parse(argc, argv);
    if(!filter.protocol) filter.protocol = 41;

    filter.snetwork = filter.sip & filter.smask;
    filter.sbcast = filter.sip | (~filter.smask);
    filter.dnetwork = filter.dip & filter.dmask;
    filter.dbcast = filter.dip | (~filter.dmask);

    if(filter.decode & 2 || filter.decode & 4) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        hFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile == INVALID_HANDLE_VALUE) {
            SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
            printf("Can\'t open file %s for dump\n", filename);
            SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
        }
        else {
            unsigned long bw, len = wsprintf(filename,"Dumping start at %.2i.%.2i.%.4i %.2i:%.2i:%.2i:%.4i\x0D\x0A\x0D\x0A", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            WriteFile(hFile, filename, len, &bw, NULL);
        }
    }

    printf("Initializing Windows Sockets 2.2...\t\t");
    if(WSAStartup(MAKEWORD(2, 2), &wsadata)) {
        SetConsoleTextAttribute(hStdout,FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("Error\n");
        SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
        return -1;
    }

    printf("Done\nCreating socket...\t\t\t\t");
    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if(s == INVALID_SOCKET) {
        SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("Error\n");
        SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
        return -1;
    }
    memset(&sa, 0, sizeof(SOCKADDR_IN));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = iface;
    printf("Done\nBinding interface %s with socket...\t", inet_ntoa(sa.sin_addr));
    if(bind(s, (SOCKADDR*)&sa, sizeof(SOCKADDR))) {
        SetConsoleTextAttribute(hStdout,FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("Error\n");
        SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
        return -1;
    }

    printf("Done\nEntering to promiscuous mode...\t\t\t");
    if(WSAIoctl(s, SIO_RCVALL, &optval, sizeof(optval), 0, 0, &bytesret, 0, 0) == SOCKET_ERROR) {
        SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("Error\n");
        SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
        return -1;
    }
    printf("Done\n\n");

    while(recv(s, Buffer, sizeof(Buffer), 0) >= sizeof(IPHeader)) {
        IPHeader* hdr = (IPHeader*)Buffer;
        char out[768];
        unsigned short dport, sport, size = (hdr->iph_length << 8) + (hdr->iph_length >> 8);
        if(breakflag) continue;
        if(hdr->iph_protocol == IPPROTO_ICMP && filter.protocol & 1) {
            SetConsoleTextAttribute(hStdout, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            ICMP *icmp = (ICMP*)(Buffer + ((hdr->iph_verlen & 15) << 2));
            if(hdr->iph_src<filter.snetwork || hdr->iph_src>filter.sbcast) continue;
            if(hdr->iph_dest<filter.dnetwork || hdr->iph_dest>filter.dbcast) continue;
            sa1.s_addr = hdr->iph_src;
            sa2.s_addr = hdr->iph_dest;
            char sas[20], tnd[64];
            lstrcpy(sas, inet_ntoa(sa1));
            icmp_decode(icmp->type, icmp->code, tnd);
            wsprintf(out, "%s -> %s Len:%i TTL:%i ICMP %s CRC:%X", sas, inet_ntoa(sa2), size, hdr->iph_ttl, tnd, icmp->CRC);
            puts(out);
        }
        if(hdr->iph_protocol == IPPROTO_IGMP && filter.protocol & 2) {
            SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
            if(hdr->iph_src < filter.snetwork || hdr->iph_src > filter.sbcast) continue;
            if(hdr->iph_dest < filter.dnetwork || hdr->iph_dest > filter.dbcast) continue;
            sa1.s_addr = hdr->iph_src;
            sa2.s_addr = hdr->iph_dest;
            char sas[20];
            lstrcpy(sas, inet_ntoa(sa1));
            wsprintf(out, "%s -> %s Len:%i TTL:%i IGMP", sas, inet_ntoa(sa2), size, hdr->iph_ttl);
            puts(out);
        }
        if(hdr->iph_protocol == IPPROTO_GGP && filter.protocol & 4) {
            SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
            if(hdr->iph_src < filter.snetwork || hdr->iph_src > filter.sbcast) continue;
            if(hdr->iph_dest < filter.dnetwork || hdr->iph_dest > filter.dbcast) continue;
            sa1.s_addr = hdr->iph_src;
            sa2.s_addr = hdr->iph_dest;
            char sas[20];
            lstrcpy(sas, inet_ntoa(sa1));
            wsprintf(out, "%s -> %s Len:%i TTL:%i GGP", sas, inet_ntoa(sa2), size, hdr->iph_ttl);
            puts(out);
        }
        if(hdr->iph_protocol == IPPROTO_TCP && filter.protocol & 8) {
            SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            TCP *tcp = (TCP*)(Buffer + ((hdr->iph_verlen & 15) << 2));
            dport = (tcp->dst_port << 8) + (tcp->dst_port >> 8);
            if(filter.dport && dport != filter.dport) continue;
            sport = (tcp->src_port << 8) + (tcp->src_port >> 8);
            if(filter.sport && sport != filter.sport) return 0;

            if(hdr->iph_src < filter.snetwork || hdr->iph_src > filter.sbcast) continue;
            if(hdr->iph_dest < filter.dnetwork || hdr->iph_dest > filter.dbcast) continue;

            sa1.s_addr = hdr->iph_src;
            sa2.s_addr = hdr->iph_dest;
            char flg[28] = "\x0";

            if(tcp->drf & 32768) lstrcat(flg, "CWR ");
            if(tcp->drf & 16384) lstrcat(flg, "ECE ");
            if(tcp->drf & 8192) lstrcat(flg, "URG ");
            if(tcp->drf & 4096) lstrcat(flg, "ACK ");
            if(tcp->drf & 2048) lstrcat(flg, "PSH ");
            if(tcp->drf & 1024) lstrcat(flg, "RST ");
            if(tcp->drf & 512) lstrcat(flg, "SYN ");
            if(tcp->drf & 256) lstrcat(flg, "FIN ");

            char sas[20];
            lstrcpy(sas, inet_ntoa(sa1));
            wsprintf(out, "%s:%i -> %s:%i Len:%i TTL:%i TCP Flags:%s SQ:%X", sas, sport, inet_ntoa(sa2), dport, size, hdr->iph_ttl, flg, tcp->sequence_number);
            puts(out);
        }
        if(hdr->iph_protocol == IPPROTO_PUP && filter.protocol & 16) {
            SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
            if(hdr->iph_src < filter.snetwork || hdr->iph_src > filter.sbcast) continue;
            if(hdr->iph_dest < filter.dnetwork || hdr->iph_dest > filter.dbcast) continue;
            sa1.s_addr = hdr->iph_src;
            sa2.s_addr = hdr->iph_dest;
            char sas[20];
            lstrcpy(sas, inet_ntoa(sa1));
            wsprintf(out, "%s -> %s Len:%i TTL:%i PUP", sas, inet_ntoa(sa2), size, hdr->iph_ttl);
            puts(out);
        }
        if(hdr->iph_protocol == IPPROTO_UDP && filter.protocol & 32) {
            SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            UDP *udp = (UDP*)(Buffer + ((hdr->iph_verlen & 15) << 2));
            dport = (udp->dst_port << 8) + (udp->dst_port >> 8);
            if(filter.dport && dport != filter.dport) continue;
            sport = (udp->src_port << 8) + (udp->src_port >> 8);
            if(filter.sport && sport != filter.sport) continue;

            if(hdr->iph_src < filter.snetwork || hdr->iph_src > filter.sbcast) continue;
            if(hdr->iph_dest < filter.dnetwork || hdr->iph_dest > filter.dbcast) continue;

            sa1.s_addr = hdr->iph_src;
            sa2.s_addr = hdr->iph_dest;

            char sas[20];
            lstrcpy(sas, inet_ntoa(sa1));
            wsprintf(out, "%s:%i -> %s:%i Len:%i TTL:%i UDP CRC:%X", sas, sport, inet_ntoa(sa2), dport, size, hdr->iph_ttl, udp->CRC);
            puts(out);
        }
        if(hdr->iph_protocol == IPPROTO_IDP && filter.protocol & 64) {
            SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
            if(hdr->iph_src < filter.snetwork || hdr->iph_src > filter.sbcast) continue;
            if(hdr->iph_dest < filter.dnetwork || hdr->iph_dest > filter.dbcast) continue;
            sa1.s_addr = hdr->iph_src;
            sa2.s_addr = hdr->iph_dest;
            char sas[20];
            lstrcpy(sas, inet_ntoa(sa1));
            wsprintf(out, "%s -> %s Len:%i TTL:%i IDP", sas,inet_ntoa(sa2), size, hdr->iph_ttl);
            puts(out);
        }
        if(hdr->iph_protocol == IPPROTO_ND && filter.protocol & 128) {
            SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
            if(hdr->iph_src < filter.snetwork || hdr->iph_src > filter.sbcast) continue;
            if(hdr->iph_dest < filter.dnetwork || hdr->iph_dest > filter.dbcast) continue;
            sa1.s_addr = hdr->iph_src;
            sa2.s_addr = hdr->iph_dest;
            char sas[20];
            lstrcpy(sas, inet_ntoa(sa1));
            wsprintf(out, "%s -> %s Len:%i TTL:%i ND", sas, inet_ntoa(sa2), size, hdr->iph_ttl);
            puts(out);
        }
        if(hdr->iph_protocol == IPPROTO_RAW && filter.protocol & 256) {
            SetConsoleTextAttribute(hStdout, ConsoleScreenBufferInfo.wAttributes);
            if(hdr->iph_src < filter.snetwork || hdr->iph_src > filter.sbcast) continue;
            if(hdr->iph_dest < filter.dnetwork || hdr->iph_dest > filter.dbcast) continue;
            sa1.s_addr = hdr->iph_src;
            sa2.s_addr = hdr->iph_dest;
            char sas[20];
            lstrcpy(sas, inet_ntoa(sa1));
            wsprintf(out, "%s -> %s Len:%i TTL:%i RAW", sas, inet_ntoa(sa2), size, hdr->iph_ttl);
            puts(out);
        }
        if(filter.decode & 1) {
            // SetConsoleTextAttribute(hStdout,FOREGROUND_GREEN|FOREGROUND_INTENSITY);
            printhex((char*)Buffer, size);
        }
        if(filter.decode & 2) {
            unsigned long bw;
            WriteFile(hFile, "\x0D\x0A", 2, &bw, NULL);
            WriteFile(hFile, out, lstrlen(out), &bw, NULL);

            // WriteFile(hFile, "\x0D\x0A",2, &bw, NULL);
            // WriteFile(hFile, Buffer + ((hdr->iph_verlen & 15) << 2), size, &bw, NULL);
        }
    }
    // SetConsoleScreenBufferInfo(hStdout,&ConsoleScreenBufferInfo);
    return 0;
}
