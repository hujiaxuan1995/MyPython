// pacp.cpp : �������̨Ӧ�ó������ڵ㡣
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

//pcap ǰ24���ֽ� ���ݰ���ͷ
struct pcap_file_header
{
	bpf_u_int32 magic;       /* 0xa1b2c3d4  32λ��ʶλ*/
	u_short version_major;   /* magjor Version 2  ���汾��*/
	u_short version_minor;   /* magjor Version 4 ���汾��*/
	bpf_int32 thiszone;      /* gmt to local correction ����ʱ��*/
	bpf_u_int32 sigfigs;     /* accuracy of timestamps ��ȷʱ���*/
	bpf_u_int32 snaplen;     /* max length saved portion of each pkt ���ݰ���󳤶�*/
	bpf_u_int32 linktype;    /* data link type (LINKTYPE_*) ��·������*/
};
//ʱ���
struct time_val
{
	long tv_sec;         /* seconds ����ͬ time_t �����ֵ */
	long tv_usec;        /* and microseconds */
};
//pcap ���ݰ���ͷ
struct pcap_pkthdr
{
	struct time_val ts;  /* time stamp  8Bʱ���*/
	bpf_u_int32 caplen; /* length of portion present 4B���ݰ�����*/
	bpf_u_int32 len;    /* length this packet (off wire)  4B���ݰ�ʵ�ʳ���*/
};
//����֡ͷ  
typedef struct FramHeader_t
{ //Pcap���������֡ͷ 
	u_int8 DstMAC[6]; //Ŀ��MAC��ַ 
	u_int8 SrcMAC[6]; //ԴMAC��ַ 
	u_short FrameType;    //֡���� 
} FramHeader_t;
//IP���ݱ�ͷ  
typedef struct IPHeader_t
{ //IP���ݱ�ͷ  
	u_int8 Ver_HLen;       //�汾+��ͷ���� 
	u_int8 TOS;            //�������� 
	u_int16 TotalLen;       //�ܳ��� 
	u_int16 ID; //��ʶ  
	u_int16 Flag_Segment;   //��־+Ƭƫ�� 
	u_int8 TTL;            //�������� 
	u_int8 Protocol;       //Э������ 
	u_int16 Checksum;       //ͷ��У��� 
	u_int32 SrcIP; //ԴIP��ַ 
	u_int32 DstIP; //Ŀ��IP��ַ 
} IPHeader_t;

//TCP���ݱ�ͷ 
typedef struct TCPHeader_t
{ //TCP���ݱ�ͷ  
	u_int16 SrcPort; //Դ�˿� 
	u_int16 DstPort; //Ŀ�Ķ˿� 
	u_int32 SeqNO; //��� 
	u_int32 AckNO; //ȷ�Ϻ�  
	u_int8 HeaderLen; //���ݱ�ͷ�ĳ���(4 bit) + ����(4 bit) 
	u_int8 Flags; //��ʶTCP��ͬ�Ŀ�����Ϣ 
	u_int16 Window; //���ڴ�С 
	u_int16 Checksum; //У��� 
	u_int16 UrgentPointer;  //����ָ�� 
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
	struct five * m_five;//ͷ�ڵ�
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
void write(struct dir *head_dir,FILE *fp)
{
	char longname[80] = "";
	int i = 0;
	FILE *Tmpfp;
	short _data = 0;
	struct dir *p;
	struct five *q;
	p = head_dir->next;
	while (p != NULL)
	{
		strcat(longname, "E:/pcap/");
		strcat(longname, p->name);
		strcat(longname, ".pcap");
		q = p->head;
		if ((Tmpfp = fopen(longname, "ab")) == NULL)
		{
			printf("\ncreate file error");
			getchar();
			exit(0);
		}
		while (q != NULL)
		{
			for (int i = 0; i < q->length + 16; i++)
			{
				fseek(fp, q->pkt_offset + i, SEEK_SET);
				fread(&_data, 1, 1, fp);
				fprintf(Tmpfp, "%0*x", 2, _data);
			}
			q = q->next;
			printf("loading....................%d\n", i++);
		}
		p = p->next;
		fclose(Tmpfp);
		memset(longname, 0, sizeof(char)* 80);
	}
	printf("Proceedure loading complished");
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
	//׷�ӵ�ĩβ
	p = node->head;
	while (p != NULL)
	{
		p = p->next;
	}
	p = m_five;
	p->next = NULL;
}

void makenew(char *name, struct dir *node, struct five *m_five,FILE *fp)
{
	//char dirname[50]="E:/pcap/";
	struct dir *new_node = (struct dir *)malloc(sizeof(struct dir));
	//short data_ = 0;

	new_node->head = m_five;
	new_node->head->next = NULL;
	new_node->length = 0;
	strcpy(new_node->name, name);
	//strcat(dirname, new_node->name);
	//strcat(dirname, ".pcap");
	//new_node->m_five = m_five;
	//fclose(new_node->fp);
	node = new_node;
	node->next = NULL;
}

void confirm(char *name, struct dir *dir_head, struct five *m_five,FILE *fp){
	struct dir *p;
	int key=0;//1������Ԫ���Ѿ�����,0������Ԫ�鲻������Ҫ���¿���
	p = dir_head->next;//dir ͷ
	while (p != NULL)
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
		printf("%d %d����%x����%lx����%lx����%x����%x\n", k++,
			p->length, p->prototype, p->ip_destine, p->ip_source, p->port1, p->port2);
		if (p->length < 0)
		{
			break;
		}
		confirm(name, dir_head, p, fp);
		p = q;
	}
	write(dir_head, fp);
	getchar();
	return 0;
}