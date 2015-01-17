#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include"my402list.h"

#define SNAP_LEN 1518


#define SIZE_ETHERNET 14

My402List *list, *list1, *list2;

	
typedef u_int tcp_seq;
struct sniff_ip 
{
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct sniff_tcp 
{
	u_short th_sport; /* source port */
	u_short th_dport; /* destination port */
	tcp_seq th_seq; /* sequence number */
	tcp_seq th_ack; /* acknowledgement number */
	u_char th_offx2; /* data offset, rsvd */
	#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};


#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct sniff_udp 
{
	u_short udp_sport; /* source port */
	u_short udp_dport; /* destination port */
	u_short udp_hlen; /* Udp header length*/
	u_short udp_chksum; /* Udp Checksum */
};

typedef struct infz2
{
	char sip[16];
	char dip[16];
	u_short sport;
	u_short dport;
	u_char prot;
}Z2;

typedef struct ds_ip
{
	char d_ip[16];
	My402List *l1;
	int s_count;
}DS;
	


int t=1,vmode,count=0,f=0,tcount= 0, ucount=0, icount=0, ocount=0, flow=0, z, fg,ffflag,pcflag, tflows=0, uflows=0, pthresh=65536, bthresh=2147483647, fthresh=65536, sthresh=65536, sf=0,pflag=0,fg1,bf=0,bf1,cflag,fflag=0;

int sflag=0;
int fi,fr,j;
long pac_len=0;
char wfile[50];
long sec, usec,c,p_tim,r_tim,cons,ftim;
FILE *fp1,*fp2;
int p=0,cnt=0;
pthread_t print;
pthread_mutex_t lock;

void * print_func()
{
	while(1){
	
	c=r_tim/1000000;
	pthread_mutex_lock(&lock);
	if(vmode==0)
		{
			if(f==1)
			{
				
				fp1=fopen(wfile,"a+");
				
				fprintf(fp1,"%ld.%ld\t %d\t %ld\t %d\n",c,cons,count,pac_len,list->num_members);
				fclose(fp1);
				My402ListUnlinkAll(list);
					
			}
			else
			{
				printf("%ld.%ld\t %d\t %ld\t %d\n",c,cons,count,pac_len,list->num_members);
				 My402ListUnlinkAll(list);
			}

		}	
		else
		{
			if(f==1)
			{
				
				fp1=fopen(wfile,"a+");
				fprintf(fp1,"%ld.%ld\t %d\t %ld\t %d\t	%d\t %d\t %d\t %d\t %d\t %d\t \n ",c,cons,count,pac_len,list->num_members,tcount,ucount,icount,ocount,tflows,uflows);	
				fclose(fp1);
				My402ListUnlinkAll(list);
					
			
			}

			else
			{
				printf("%ld.%ld\t %d\t %ld\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t \n ",c,cons,count,pac_len,list->num_members,tcount,ucount,icount,ocount,tflows,uflows);
				My402ListUnlinkAll(list);
			}
		}		
		r_tim+=t*1000000;
		tcount=0,ocount=0,icount=0,ucount=0,pac_len=0,count=0,tflows=0,uflows=0,pflag=0,sf=0,pcflag=0,ffflag=0;
	
	pthread_mutex_unlock(&lock);
	usleep(t*1000000); 
	}


}


void packets(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{


	const struct sniff_ip *ip; 
	const struct sniff_tcp *tcp;
	const struct sniff_udp *udp;            
	int sp;
	Z2 *infZ2;
	My402ListElem *elem, *elem1, *elem2;
	DS *ds;
	int spt,dpt;
	char dname[100];
	int i;	
	My402List *temp;
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	sp = IP_HL(ip)*4;
	gethostname(dname,sizeof dname);
	strcat(dname,".attackinfo");
	if (sp < 20) {
		printf("   * Invalid IP header length: %u bytes\n", sp);
		return;
	}
	if(ip->ip_p == IPPROTO_TCP)
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + sp);
	if(ip->ip_p == IPPROTO_UDP)
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + sp);	
	pthread_mutex_lock(&lock);
	if(z==2||z== 5)
	{
		infZ2= (Z2 *) malloc (sizeof(Z2));
		memset(infZ2,0,sizeof(infZ2));
		strcpy(infZ2->sip,inet_ntoa(ip->ip_src));
		strcpy(infZ2->dip,inet_ntoa(ip->ip_dst));
		infZ2->prot=ip->ip_p;
		if(ip->ip_p == IPPROTO_TCP)
		{
			infZ2->sport=tcp->th_sport;
			infZ2->dport=tcp->th_dport;	
		}
		if(ip->ip_p == IPPROTO_UDP)
		{
			infZ2->sport=udp->udp_sport;
			infZ2->dport=udp->udp_dport;
		}	
		
	}
	sec= header->ts.tv_sec;
	usec= header->ts.tv_usec;
	p_tim= sec*1000000+usec;
	
	
	if (cnt==0)
	{
		cons=usec;
		r_tim=p_tim;
		ftim= header->ts.tv_sec;

	}
	
	cnt++;
	while(p_tim>=1000000*t+r_tim)
	{
		c=r_tim/1000000;
		if(vmode==0)
		{
			if(f==1)
			{
				
				fp1=fopen(wfile,"a+");
				
				fprintf(fp1,"%ld.%ld\t %d\t %ld\t %d\n",c,cons,count,pac_len,list->num_members);
				fclose(fp1);
				My402ListUnlinkAll(list);
				My402ListUnlinkAll(list1);
				My402ListUnlinkAll(list2);
					
			}
			else
			{
				printf("%ld.%ld\t %d\t %ld\t %d\n",c,cons,count,pac_len,list->num_members);
				My402ListUnlinkAll(list);
				My402ListUnlinkAll(list1);
				My402ListUnlinkAll(list2);
					
			}

		}	
		else
		{
			if(f==1)
			{
				
				fp1=fopen(wfile,"a+");
				fprintf(fp1,"%ld.%ld\t %d\t %ld\t %d\t	%d\t %d\t %d\t %d\t %d\t %d\t \n ",c,cons,count,pac_len,list->num_members,tcount,ucount,icount,ocount,tflows,uflows);	
				fclose(fp1);
				My402ListUnlinkAll(list);
				My402ListUnlinkAll(list1);
				My402ListUnlinkAll(list2);
					
			
			}

			else
			{
				printf("%ld.%ld\t %d\t %ld\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t \n ",c,cons,count,pac_len,list->num_members,tcount,ucount,icount,ocount,tflows,uflows);
				My402ListUnlinkAll(list);
				My402ListUnlinkAll(list1);
				My402ListUnlinkAll(list2);
					
			}
		}		
		r_tim+=t*1000000;
		tcount=0,ocount=0,icount=0,ucount=0,pac_len=0,count=0,tflows=0,uflows=0,pflag=0,sf=0,pcflag=0,ffflag=0;
		ftim+=t;

	}
	count++;
	pac_len+=header->len;

																																																																																																																																																																																																																																																																																																																			

	if(My402ListEmpty(list)==1)
	{
		if(ip->ip_p == IPPROTO_TCP)
			tflows++;
		if(ip->ip_p == IPPROTO_UDP)
			uflows++;
		My402ListAppend(list,infZ2);
		My402ListAppend(list1,infZ2);

		
	}
	if(z==2)
	{
		for(elem=My402ListFirst(list);elem!=NULL;elem=My402ListNext(list,elem))
		{
			if((strcmp(infZ2->sip, (((Z2 *)(elem->obj))->sip))==0) && (strcmp(infZ2->dip, (((Z2 *)(elem->obj))->dip))==0))
			
			fg=1;
					
					
		}
		if(fg==0)
		{
			if(ip->ip_p == IPPROTO_TCP)
				tflows++;
			if(ip->ip_p == IPPROTO_UDP)
				uflows++;
			My402ListAppend(list,infZ2);
				
		}
		fg=0;

	}
	
	
	if(z==5)
	{
		for(elem=My402ListFirst(list);elem!=NULL;elem=My402ListNext(list,elem))
		{
			
		
			spt=(((Z2 *)(elem->obj))->sport);
			dpt=(((Z2 *)(elem->obj))->dport);
			if((infZ2->prot== IPPROTO_TCP) || (infZ2->prot ==IPPROTO_UDP))
			{
				if((strncmp((((Z2 *)(elem->obj))->sip),
					      infZ2->sip,
					      sizeof(((Z2 *)(elem->obj))->sip))==0) && 
				   (strncmp((((Z2 *)(elem->obj))->dip),
					      infZ2->dip,
					      sizeof(((Z2 *)(elem->obj))->dip))==0)  && (spt==infZ2->sport) && (dpt==infZ2->dport) && (infZ2->prot==(((Z2 *)(elem->obj))->prot)))
					fg=1;
			}
			else
			{
				if((strncmp((((Z2 *)(elem->obj))->sip),
					      infZ2->sip,
					      sizeof(((Z2 *)(elem->obj))->sip))==0) && 
				   (strncmp((((Z2 *)(elem->obj))->dip),
					      infZ2->dip,
					      sizeof(((Z2 *)(elem->obj))->dip))==0) && 
				   (infZ2->prot == (((Z2 *)(elem->obj))->prot)))		
					fg=1;
			}	
				
		}
		if(fg==0)
		{
			if(ip->ip_p == IPPROTO_TCP)
				tflows++;
			if(ip->ip_p == IPPROTO_UDP)
				uflows++;
			My402ListAppend(list,infZ2);
				
						
		}
		fg=0;
	
	}

	if(fflag==1||cflag==1)
	{
		for(elem=My402ListFirst(list1);elem!=NULL;elem=My402ListNext(list1,elem))
		{
			
		
			spt=(((Z2 *)(elem->obj))->sport);
			dpt=(((Z2 *)(elem->obj))->dport);
			if((infZ2->prot== IPPROTO_TCP) || (infZ2->prot ==IPPROTO_UDP))
			{
				if((strcmp((((Z2 *)(elem->obj))->sip),infZ2->sip)==0) && (strcmp((((Z2 *)(elem->obj))->dip),infZ2->dip)==0)  && (spt==infZ2->sport) && (dpt==infZ2->dport) && (infZ2->prot==(((Z2 *)(elem->obj))->prot)))
					fg1=1;
			}
			else
			{
				if((strcmp((((Z2 *)(elem->obj))->sip),infZ2->sip)==0) && (strcmp((((Z2 *)(elem->obj))->dip),infZ2->dip)==0) && (infZ2->prot == (((Z2 *)(elem->obj))->prot)))		
						fg1=1;
			}	
				
		}
		if(fg1==0)
		{
			if(ip->ip_p == IPPROTO_TCP)
				tflows++;
			if(ip->ip_p == IPPROTO_UDP)
				uflows++;
			My402ListAppend(list1,infZ2);
				
					
		}
		fg1=0;
	
	}
	if(sflag==1)
		{
			ds=(DS*)malloc(sizeof(DS));
			memset(ds,0,sizeof(ds));
			if(My402ListEmpty(list2)==1)
			{
				ds->s_count++;
				strncpy(ds->d_ip,infZ2->dip,sizeof(ds->d_ip));
				ds->l1=(My402List*)malloc(sizeof(My402List));
				My402ListInit(ds->l1);
				My402ListAppend(ds->l1,infZ2->sip);
				My402ListAppend(list2,ds);
			}
			else
			{
				for(elem1=My402ListFirst(list2);elem1!=NULL;elem1=My402ListNext(list2,elem1))
				{
					if( strncmp(((DS*)(elem1->obj))->d_ip,infZ2->dip,sizeof(infZ2->dip))==0)
					{
						bf=1;
						temp=((DS*)(elem1->obj))->l1;
						for(elem2=My402ListFirst(temp);elem2!=NULL;elem2=My402ListNext(temp,elem2))
						{
							if(strncmp(((char*)(elem2->obj)),infZ2->sip,sizeof(infZ2->sip))==0)
								bf1=1;
						}
						if(bf1==0)
						{
							My402ListAppend(temp,infZ2->sip);
							i=((DS*)(elem1->obj))->s_count++;
							if(i>=sthresh && sf==0)
							{
								sf=1;
								fp2=fopen(dname,"a+");
								fprintf(fp2,"%ld.%ld\t %ld.%ld\t %d\t %ld\t %d\n",sec,usec,ftim,cons,count,pac_len,list1->num_members);
								fclose(fp2);

							}

						}
						bf1=0;

					}
				}
				if(bf==0)
				{
					ds->s_count++;
					strncpy(ds->d_ip,infZ2->dip,sizeof(ds->d_ip));
					ds->l1=(My402List*)malloc(sizeof(My402List));
					My402ListInit(ds->l1);
					My402ListAppend(ds->l1,infZ2->sip);
					My402ListAppend(list2,ds);
				}
				bf=0;

			}
		}

	
	

	if(p==0 && fi==0)
	{
		pthread_create(&print,NULL,print_func,NULL);
		p++;
	}
	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			tcount++;
			break;
		case IPPROTO_UDP:
			ucount++;
			break;
		case IPPROTO_ICMP:
			icount++;
			break;
		default:
			ocount++;
			break;
	}

	if((count>pthresh) && (pflag==0))
	{
		
		pflag=1;
		fp2=fopen(dname,"a+");
		fprintf(fp2,"%ld.%ld\t %ld.%ld\t %d\t %ld\t %d\n",sec,usec,ftim,cons,count,pac_len,list1->num_members);
		fclose(fp2);
		
	}
	if((pac_len>bthresh) && (pcflag==0))
	{
		pcflag=1;
		fp2=fopen(dname,"a+");
		fprintf(fp2,"%ld.%ld\t %ld.%ld\t %d\t %ld\t %d\n",sec,usec,ftim,cons,count,pac_len,list->num_members);
		fclose(fp2);

	}
	if((list1->num_members>fthresh) && (ffflag==0))
	{
		ffflag=1;
		fp2=fopen(dname,"a+");
		fprintf(fp2,"%ld.%ld\t %ld.%ld\t %d\t %ld\t %d\n",sec,usec,ftim,cons,count,pac_len,list1->num_members);
		fclose(fp2);

	}
	
	pthread_mutex_unlock(&lock);
	return;
}


int main(int argc, char **argv)
{

	char *dev = NULL;			
	char errbuf[PCAP_ERRBUF_SIZE];		
	pcap_t *handle;				
	char filter_exp[] = "ip";		
	struct bpf_program fp;			
	
	bpf_u_int32 net;			
	int i,rflag=0,iflag=0;
	char filename[50];

	if(argc<2)
	{
		printf("Usage Instruction:\n-r,--read 	Read the specified pcap file.\n-i, --int Listen on the specified interface.\n-T, --time Print out packet and byte counts for the specified time epoch. If epoch is not specified, assume an epoch duration of one second.\n-v, --verbose Also print out packet and byte counts based on the procotol specified in the IP header. The tool currently supports tcp, udp and icmp.\n -w, --write 	Write the packet counts to a specified filename. If filename is not specified, write to stdout");
		exit(0);
	}


	if(argc>1)
	{
		for(i=1;i<argc;i++)
		{
			if((strncmp(argv[i],"-r",2)==0)||(strncmp(argv[i],"--read",6)==0))
			{
				if(i+1>=argc)
				{
					printf("Enter the file to be written to\n");
					exit(0);
				}
				
				if(argv[i+1][0]=='-')
				{
					printf("Enter the file to written to\n");
					exit(0);
				}
				strncpy(filename,argv[i+1],sizeof(filename));
				fi=1;
				rflag=1;
			}

			else if(strncmp(argv[i],"-i",2)==0||(strncmp(argv[i],"--int",5)==0))
			{
				dev= argv[i+1];
				iflag=1;
			}
			else if(strncmp(argv[i],"-T",2)==0||(strncmp(argv[i],"--time",6)==0))
			{
				if(i+1>=argc)
				{
					printf("Enter a valid time\n");
					exit(0);
				}
				
				if(argv[i+1][0]=='-')
				{
					printf("Enter a valid time\n");
					exit(0);
				}
				t=atoi(argv[i+1]);
				if(t<=0)
				{
					printf("Enter a valid Time\n");
					exit(0);
				}
			}
			else if(strncmp(argv[i],"-w",2)==0||(strncmp(argv[i],"--write",7)==0))
			{
				if(i+1>=argc)
				{
					printf("Enter the file to be written to\n");
					exit(0);
				}
				
				if(argv[i+1][0]=='-')
				{
					printf("Enter the file to written to\n");
					exit(0);
				}
				strncpy(wfile,argv[i+1],sizeof(wfile));
				
				f=1;
			}
			
			else if(strncmp(argv[i],"-v",2)==0||(strncmp(argv[i],"--verbose",9)==0))
				vmode=1;
			
			else if(strncmp(argv[i],"-z",2)==0|| (strncmp(argv[i],"--track",7)==0))
			{
				if(i+1>=argc)
				{
					printf("Enter a value for z\n");
					exit(0);
				}
				
				if(argv[i+1][0]=='-')
				{
					printf("Enter a value for z\n");
					exit(0);
				}
				z=atoi(argv[i+1]);
				
				if(z!=2 && z!=5)
				{
					printf("Enter a valid value for z\n");
					exit(0);
				}
				fr=1;
			
			}
			else if(strncmp(argv[i],"-p",2)==0)
			{
				if(i+1>=argc)
				{
					printf("Enter a value for p\n");
					exit(0);
				}
				if(argv[i+1][0]=='-')
				{
					printf("Enter a value for p\n");
					exit(0);
				}
				pthresh=atoi(argv[i+1]);
				cflag=1;
			}
			else if(strncmp(argv[i],"-f",2)==0)
			{
				if(i+1>=argc)
				{
					printf("Enter a value for f\n");
					exit(0);
				}
				if(argv[i+1][0]=='-')
				{
					printf("Enter a value for f\n");
					exit(0);
				}
				fthresh=atoi(argv[i+1]);
				fflag=1;
				cflag=1;
				
			}
			else if(strncmp(argv[i],"-s",2)==0)
			{
				if(i+1>=argc)
				{
					printf("Enter a value for s\n");
					exit(0);
				}
				if(argv[i+1][0]=='-')
				{
					printf("Enter a value for s\n");
					exit(0);
				}
				sthresh=atoi(argv[i+1]);
				sflag=1;
				cflag=1;
			}
			else if(strncmp(argv[i],"-b",2)==0)
			{
				if(i+1>=argc)
				{
					printf("Enter a value for b\n");
					exit(0);
				}
				if(argv[i+1][0]=='-')
				{
					printf("Enter a value for b\n");
					exit(0);
				}
				bthresh=atoi(argv[i+1]);
				cflag=1;
				
			}
				

		}
	}
	
	if(iflag==0 && rflag==0)
	{
		printf("Enter the interface or the tracefile\n");
		exit(0);
	}
	if(iflag==1 && rflag==1)
	{
		printf("Enter either the interface or the tracefile\n");
		exit(0);
	}
	list=(My402List *) malloc(sizeof(My402List));
	My402ListInit(list);
	list1=(My402List *) malloc(sizeof(My402List));
	My402ListInit(list1);
	
	list2= (My402List *) malloc(sizeof(My402List));
	My402ListInit(list2);


	if(iflag==1)
	{
		FILE *f_inf;
		char fnp[15];
		strcpy(fnp,"inf_name");
		f_inf=fopen(fnp,"w+");
		fprintf(f_inf, "%s",dev);
		fflush(f_inf);
		fclose(f_inf);

	}


	if (fi==0 && rflag==0)
	{
		if(dev==NULL)

			if ((dev=pcap_lookupdev(errbuf)) == NULL) 
			{
				fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
				net=0;
			}
				
		
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	}
	else
		handle=pcap_open_offline(filename,errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}
	

	
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	

	pcap_loop(handle,-1, packets, NULL);
	c=r_tim/1000000;
	if(vmode==0)
	{
		if(f==1)
		{
				
			fp1=fopen(wfile,"a+");				
			fprintf(fp1,"%ld.%ld\t %d\t %ld\t %d\n",c,cons,count,pac_len,list->num_members);
			fclose(fp1);
			My402ListUnlinkAll(list);
			if(cflag==1)
				My402ListUnlinkAll(list1);
			if(sflag==1)
				My402ListUnlinkAll(list2);
					
		}
		else
		{
			printf("%ld.%ld\t %d\t %ld\t %d\n",c,cons,count,pac_len,list->num_members);
			My402ListUnlinkAll(list);
                        if(cflag==1)
				My402ListUnlinkAll(list1);
			if(sflag==1)
				My402ListUnlinkAll(list2);
		}

	}	
	else
	{
		if(f==1)
		{
				
			fp1=fopen(wfile,"a+");
			fprintf(fp1,"%ld.%ld\t %d\t %ld\t %d\t	%d\t %d\t %d\t %d\t %d\t %d\t \n ",c,cons,count,pac_len,list->num_members,tcount,ucount,icount,ocount,tflows,uflows);	
			fclose(fp1);
			My402ListUnlinkAll(list);
			if(cflag==1)
				My402ListUnlinkAll(list1);
			if(sflag==1)
				My402ListUnlinkAll(list2);		
			
		}

		else
		{
			printf("%ld.%ld\t %d\t %ld\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t \n ",c,cons,count,pac_len,list->num_members,tcount,ucount,icount,ocount,tflows,uflows);
			My402ListUnlinkAll(list);
			if(cflag==1)
				My402ListUnlinkAll(list1);
			if(sflag==1)
				My402ListUnlinkAll(list2);
		}
	}		
	r_tim+=t*1000000;
	tcount=0,ocount=0,icount=0,ucount=0,pac_len=0,count=0,fg=0,tflows=0,uflows=0;
	
	pthread_join(print,NULL);
	free(list1);
	free(list);
	free(list2);
	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}
 
