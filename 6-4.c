// pacp.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cstdlib>
#include <time.h>

using namespace std;

#define BUFSIZE 10240
#define STRSIZE 1024 
typedef long bpf_int32;
typedef unsigned long bpf_u_int32;
typedef unsigned short  u_short;
typedef unsigned long u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;

//pcap 前24个字节 数据包包头
struct pcap_file_header
{
	bpf_u_int32 magic;       /* 0xa1b2c3d4  32位标识位*/
	u_short version_major;   /* magjor Version 2  主版本号*/
	u_short version_minor;   /* magjor Version 4 副版本号*/
	bpf_int32 thiszone;      /* gmt to local correction 区域时间*/
	bpf_u_int32 sigfigs;     /* accuracy of timestamps 精确时间戳*/
	bpf_u_int32 snaplen;     /* max length saved portion of each pkt 数据包最大长度*/
	bpf_u_int32 linktype;    /* data link type (LINKTYPE_*) 链路层类型*/
};
//时间戳
struct time_val
{
	long tv_sec;         /* seconds 含义同 time_t 对象的值 */
	long tv_usec;        /* and microseconds */
};
//pcap 数据包包头
struct pcap_pkthdr
{
	struct time_val ts;  /* time stamp  8B时间戳*/
	bpf_u_int32 caplen; /* length of portion present 4B数据包长度*/
	bpf_u_int32 len;    /* length this packet (off wire)  4B数据包实际长度*/
};
//数据帧头  
typedef struct FramHeader_t
{ //Pcap捕获的数据帧头 
	u_int8 DstMAC[6]; //目的MAC地址 
	u_int8 SrcMAC[6]; //源MAC地址 
	u_short FrameType;    //帧类型 
} FramHeader_t;
//IP数据报头  
typedef struct IPHeader_t
{ //IP数据报头  
	u_int8 Ver_HLen;       //版本+报头长度 
	u_int8 TOS;            //服务类型 
	u_int16 TotalLen;       //总长度 
	u_int16 ID; //标识  
	u_int16 Flag_Segment;   //标志+片偏移 
	u_int8 TTL;            //生存周期 
	u_int8 Protocol;       //协议类型 
	u_int16 Checksum;       //头部校验和 
	u_int32 SrcIP; //源IP地址 
	u_int32 DstIP; //目的IP地址 
} IPHeader_t;

//TCP数据报头 
typedef struct TCPHeader_t
{ //TCP数据报头  
	u_int16 SrcPort; //源端口 
	u_int16 DstPort; //目的端口 
	u_int32 SeqNO; //序号 
	u_int32 AckNO; //确认号  
	u_int8 HeaderLen; //数据报头的长度(4 bit) + 保留(4 bit) 
	u_int8 Flags; //标识TCP不同的控制消息 
	u_int16 Window; //窗口大小 
	u_int16 Checksum; //校验和 
	u_int16 UrgentPointer;  //紧急指针 
}TCPHeader_t;
typedef struct five
{
	u_int8 prototype;
	u_int32 ip_source;
	u_int32 ip_destine;
	u_int16 port1;  //Destine
	u_int16 port2; //Source
	u_int32 length;
	u_int32 seq;
	u_int32 ack;
	int pkt_offset;
	struct five *next;
}five;
typedef struct dir
{
	struct five * m_five;
	struct five *head;
	FILE *fp;
	int length;
	char name[50];
	struct dir *next;
}dir;
char * getfivename(struct  five * f){
	char * name = (char *)malloc(sizeof(char)* 27);
	char ips[9] = "";
	char ipd[9] = "";
	char ports[5] = "";
	char portd[5] = "";
	u_int8 prototype = f->prototype;
	u_int32 ip_source = f->ip_source;
	u_int32 ip_destine = f->ip_destine;
	u_int16 port1 = f->port1;
	u_int16 port2 = f->port2;
	_itoa(f->prototype, name, 16);
	_itoa(f->ip_source, ips, 16);
	_itoa(f->ip_destine, ipd, 16);
	_itoa(f->port1, ports, 16);
	_itoa(f->port2, portd, 16);
	strcat(name, ips);
	strcat(name, ipd);
	strcat(name, ports);
	strcat(name, portd);
	return name;
}
void writeinto(struct dir *node,struct five *m_five,FILE *fp)
{
	char *data;
	char longname[80]="E:/pcap/";
	FILE *Tmpfp;
	__int64 number = 0;
	short _data = 0;
	struct five *p;
	data = (char *)calloc(m_five->length + 20, sizeof(char));
	p = node->head;
	while (p->next)
	{
		p = p->next;
	}
	p->next = m_five;
	p->next->next = NULL;

	strcat(longname, node->name);
	strcat(longname, ".pcap");

	if ((Tmpfp = fopen(longname, "ab")) == NULL)
	{
		printf("\ncreate file error");
		getchar();
		exit(0);
	}
	
	for (int i = 0; i < m_five->length + 16; i++)
	{
		fseek(fp, m_five->pkt_offset + i, SEEK_SET);
		fread(&_data, 1, 1, fp);
		fprintf(Tmpfp, "%0*x ",2, _data);
	}
	
	/*fseek(fp, m_five->pkt_offset, SEEK_SET);
	fread(data, m_five->length + 16, 1, fp);
	fputs(data, node->fp);*/
	fclose(node->fp);
}
void makenew(char *name, struct dir *node, struct five *m_five,FILE *fp)
{
	char dirname[50]="E:/pcap/";
	struct dir *new_node = (struct dir *)malloc(sizeof(struct dir));
	short data_ = 0;
	//char * data;
	//data = (char *)calloc(m_five->length+20, sizeof(char));

	new_node->head = m_five;
	new_node->head->next = NULL;

	new_node->length = 0;
	strcpy(new_node->name, name);
	strcat(dirname, new_node->name);
	strcat(dirname, ".pcap");
	new_node->m_five = m_five;
	if ((new_node->fp = fopen(dirname, "ab")) == NULL)
	{
		printf("\ncreate file error");
		getchar();
		exit(0);
	}
	if ((fp = fopen("E:/lofter2.pcap", "r")) == NULL)
	{
		cout << "can not find file!";
		exit(0);
	}
	for (int i = 0; i < m_five->length + 16; i++)
	{
		fseek(fp, m_five->pkt_offset+ i, SEEK_SET);
		fread(&data_, 1, 1, fp);
		fprintf(new_node->fp, "%0*x ",2,data_);
	}
	fclose(new_node->fp);
	/*fseek(fp, m_five->pkt_offset, SEEK_SET);
	fread(data, m_five->length + 16, 1, fp);
	fputs(data, new_node->fp);*/
	node->next = new_node;
	new_node->next = NULL;
}

void confirm(char *name, struct dir *list, struct five *m_five,FILE *fp){
	struct dir *p;
	int key=0;//1代表五元组已经存在,0代表五元组不存在需要重新开辟
	p = list;//dir 头
	while (p->next != NULL)
	{
		if (strcmp(name, p->name) == 0)
		{
			key = 1;
			break;
		}
		p = p->next;
		key = 0;
	}
	if (key == 1)
	{
		writeinto(p,m_five,fp);
	}
	else if (key == 0)
	{
		makenew(name, p, m_five,fp);
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	struct pcap_pkthdr *ptk_header;
	struct dir *dir_head;
	struct dir *m, *n;
	struct five *head = NULL;
	struct five *p, *q;
	FILE *fp, *output;
	int pkt_offset, i = 0, k = 0;
	u_int32 a[6];

	char  * name = NULL;

	int fplength;

	q = p = head;

	p = (struct five *)malloc(sizeof(struct five));
	dir_head = (struct dir *)malloc(sizeof(struct dir));
	dir_head->next = NULL;
	if ((fp = fopen("E:/lofter2.pcap", "r")) == NULL)
	{
		cout << "can not find file!";
		exit(0);
	}
	fseek(fp, 0, SEEK_END);
	fplength = ftell(fp);
	printf("%d\n", fplength);
	pkt_offset = 24;
	while (1)
	{
		if (fseek(fp, pkt_offset, SEEK_SET) != 0)
		{
			break;
		}
		p->seq = 0;
		fseek(fp, pkt_offset + 8, SEEK_SET);
		fread(&p->length, 4, 1, fp);
		fseek(fp, pkt_offset + 39, SEEK_SET);
		fread(&p->prototype, 1, 1, fp);
		fseek(fp, pkt_offset + 42, SEEK_SET);
		fread(&p->ip_source, 1, 4, fp);
		fseek(fp, pkt_offset + 46, SEEK_SET);
		fread(&p->ip_destine, 1, 4, fp);
		fseek(fp, pkt_offset + 50, SEEK_SET);
		fread(&p->port1, 1, 2, fp);
		fseek(fp, pkt_offset + 52, SEEK_SET);
		fread(&p->port2, 1, 2, fp);

		fseek(fp, pkt_offset + 54, SEEK_SET);
		fread(&p->seq, 1, 4, fp);
		p->seq = _byteswap_ulong(p->seq);

		fseek(fp, pkt_offset + 58, SEEK_SET);
		fread(&p->ack, 1, 4, fp);
		p->ack = _byteswap_ulong(p->ack);

		p->ip_source = _byteswap_ulong(p->ip_source);
		p->ip_destine = _byteswap_ulong(p->ip_destine);
		p->port1 = _byteswap_ushort(p->port1);
		p->port2 = _byteswap_ushort(p->port2);
		p->pkt_offset = pkt_offset;
		pkt_offset = p->length + 16 + pkt_offset;
		q = (struct five *)malloc(sizeof(struct five));
		p->next = q;
		name = getfivename(p);
		printf("%d %d——%x——%lx——%lx——%x——%x\n", k++,
			p->length, p->prototype, p->ip_destine, p->ip_source, p->port1, p->port2);
		if (p->length < 0)
		{
			break;
		}
		confirm(name, dir_head, p, fp);
		p = q;
	}
	getchar();
	return 0;

}