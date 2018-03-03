#ifndef SIMPLE_SNIFFER_NETWORK_H
#define SIMPLE_SNIFFER_NETWORK_H

#define NETWORK_ETHER_ADDR_LEN 6
#define NETWORK_ETHER_TYPE_LEN 2
#define NETWORK_ETHER_HEADER_LEN (NETWORK_ETHER_ADDR_LEN * 2 + NETWORK_ETHER_TYPE_LEN)

/*
    0                   1                   2                   3                   4
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Destination MAC Address                                                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Source MAC Address                                                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Type                  |                      ...                                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct network_ether_header {
    // MAC Получателя.
    unsigned char ether_dest_address[NETWORK_ETHER_ADDR_LEN];

    // MAC Отправителя.
    unsigned char ether_src_address[NETWORK_ETHER_ADDR_LEN];

    // Тип пакета.
    unsigned short ether_type;
};

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct network_ip_header {
#if BYTE_ORDER == BIG_ENDIAN
    unsigned int version:4;
    unsigned int header_length:4;
#elif BYTE_ORDER == LITTLE_ENDIAN
    unsigned int header_length:4;
    unsigned int version:4;
#endif
    unsigned char tos;
    unsigned short length;
    unsigned short identification;
#if BYTE_ORDER == BIG_ENDIAN
    unsigned short flags:3;
    unsigned short fragment_offset:13;
#elif BYTE_ORDER == LITTLE_ENDIAN
    unsigned short fragment_offset:13;
    unsigned short flags:3;
#endif
    unsigned char time_to_live;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int ip_source_address;
    unsigned int ip_destination_address;
#if BYTE_ORDER == BIG_ENDIAN
    unsigned int options:24;
    unsigned int padding:8;
#elif BYTE_ORDER == LITTLE_ENDIAN
    unsigned int padding:8;
    unsigned int options:24;
#endif
};

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct network_tcp_header {
    unsigned short source_port;
    unsigned short destination_port;
    unsigned int sequence_number;
    unsigned int acknowledgment_number;
#define	NETWORK_TH_FIN	0x01
#define	NETWORK_TH_SYN	0x02
#define	NETWORK_TH_RST	0x04
#define	NETWORK_TH_PUSH	0x08
#define	NETWORK_TH_ACK	0x10
#define	NETWORK_TH_URG	0x20
#if BYTE_ORDER == BIG_ENDIAN
    unsigned short data_offset:4;
    unsigned short reserved:6;
    unsigned short flags:6;
#elif BYTE_ORDER == LITTLE_ENDIAN
    unsigned short flags:6;
    unsigned short reserved:6;
    unsigned short data_offset:4;
#endif
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
#if BYTE_ORDER == BIG_ENDIAN
    unsigned int options:24;
    unsigned int padding:8;
#elif BYTE_ORDER == LITTLE_ENDIAN
    unsigned int padding:8;
    unsigned int options:24;
#endif
    unsigned int data;
};

#endif //SIMPLE_SNIFFER_NETWORK_H
