#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>

char errbuf[PCAP_ERRBUF_SIZE];

typedef struct{
        unsigned char des_mac[6];
        unsigned char src_mac[6];
        unsigned short type;
} Ethernet;

typedef struct{
        unsigned char ver_len;
        unsigned char tos;
        unsigned short total_len;
        unsigned short indent;
        unsigned short flags:3, offset:13;
        unsigned char tol;
        unsigned char protocol;
        unsigned short checksum;
        unsigned int src_ip;
        unsigned int des_ip;
} IP;

typedef struct{
        unsigned short d_port;
        unsigned short s_port;
        unsigned int seq_num;
        unsigned int ack_num;
        unsigned char offset;
        unsigned char flags;
        unsigned short window;
        unsigned short checksum;
        unsigned short urgent;
} TCP;

char* find_interface(){
        pcap_if_t *alldevs;
        pcap_if_t *s_devs;
        int i = 1;
        char choice;
        char* interface;

        pcap_findalldevs(&alldevs, errbuf);
        s_devs = alldevs;

        printf("\n\n====================|| Network Interface ||====================\n\n");
        while(1){
                if(alldevs->flags != PCAP_IF_LOOPBACK)
                {
                        printf("\t\t[%d] : %20s\n", i, alldevs->name);
                }
                if(alldevs->next == NULL){
                        break;
                }
                alldevs = alldevs->next;
                i++;
        }
        printf("\n================================================================\n>> ");
        scanf("%d", &choice);

        for(int j = 0; j < choice-1; j++)
        {
                if(s_devs->next == NULL){
                        printf("ERROR");
                        exit(-1);
                }
                s_devs = s_devs->next;
        }

        interface = s_devs->name;
        system("clear");
        return interface;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

        Ethernet* e_header;
        e_header = (Ethernet *)packet;
        unsigned char* m_dest = e_header->des_mac;
        unsigned char* m_src = e_header->src_mac;

        IP* ip_header;
        ip_header = (IP *)(packet + sizeof(Ethernet));
        unsigned int dest_ip = ip_header->des_ip;
        unsigned int src_ip = ip_header->src_ip;
        unsigned int ip_header_len = (ip_header->ver_len&0xf) * 4;
        unsigned int ip_total_len = ip_header->total_len;

        TCP* tcp_header;
        tcp_header = (TCP *)(packet + sizeof(IP));
        unsigned short d_port = tcp_header->d_port;
        unsigned short s_port = tcp_header->s_port;
        unsigned int tcp_header_len = (tcp_header->offset >> 4 ) * 4;

        char sMac[20];
        char dMac[20];
        char sIp[16];
        char dIp[16];

        sprintf(sMac, "%02x:%02x:%02x:%02x:%02x:%02x", m_src[0], m_src[1], m_src[2], m_src[3], m_src[4], m_src[5]);
        sprintf(dMac, "%02x:%02x:%02x:%02x:%02x:%02x",m_dest[0], m_dest[1], m_dest[2], m_dest[3], m_dest[4], m_dest[5]);
        sprintf(sIp, "%d.%d.%d.%d", src_ip&0xff, (src_ip >> 8)&0xff, (src_ip >> 16)&0xff, (src_ip >> 24)&0xff);
        sprintf(dIp, "%d.%d.%d.%d", dest_ip&0xff, (dest_ip >> 8)&0xff, (dest_ip >> 16)&0xff, (dest_ip >> 24)&0xff);

        unsigned char* message = (unsigned char*)(packet + sizeof(Ethernet) + ip_header_len + tcp_header_len);

        printf("|  MAC |\t%s\t|\t%s\t|", sMac, dMac);
        printf("\n-------------------------------------------------------------------------\n");
        printf("|  IP  |      \t%s\t      |      \t%s\t      |", sIp, dIp);
        printf("\n-------------------------------------------------------------------------\n");
        printf("| PORT |\t\t%d\t\t|\t\t%d\t\t|", s_port, d_port);
        printf("\n-------------------------------------------------------------------------\n");
        printf("\n-------------------------------------------------------------------------\n");
        printf("|\t\t\t\t  \033[31mMessage\033[0m  \t\t\t\t|");
        printf("\n-------------------------------------------------------------------------\n\t");

        for(int i = 0; i < (ip_total_len - ip_header_len - tcp_header_len); i++){
                printf("%02x ", message[i]);
                if(i % 16 == 0 && i != 0){
                        printf("\n\t  ");
                }
                if(i == 0x100) break;
        }
        printf("\n-------------------------------------------------------------------------\n");
}

void capture(char* inter){
        pcap_t* pcap_handle;
        int mode = 0;
        int count_mode = 0;
        int count = 0;

        printf("\n\n=============================|| Mode ||===========================\n\n");
        printf("\t\t\t[1] basic\n\t\t\t[2] promiscuous\n");
        printf("\n===================================================================\n[Mode]>> ");
        scanf("%d", &mode);
        system("clear");

        printf("\n\n=========================|| packet count ||=========================\n\n");
        printf("\t\t\t[1] decide for yourself.\n\t\t\t[2] all packet sniffing.\n");
        printf("\n===================================================================\n[count mode]>> ");
        scanf("%d", &count_mode);

        if(count_mode == 2){
                count = -1;
        }else{
                printf("\t  <<Please enter the number of times>>\n[self]>> ");
                scanf("%d", &count);
        }
        system("clear");
        printf("\n\n============================|| start sniff ||============================\n\n");
        printf("|      |\t    source        \t|\t    destination  \t|\n");
        printf("=========================================================================\n");

        pcap_handle = pcap_open_live(inter, BUFSIZ, mode-1, 1000, errbuf);
        pcap_loop(pcap_handle, count, got_packet, NULL);
}

int main(){
        char* inter;

        system("clear");
        inter = find_interface();
        capture(inter);

}
