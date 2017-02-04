/* Program to generate XML information for all packets
 * For GET/POST packets URL is hashed and for other packets entire payload is hashed
 * Modified from libtrace complete.c : Complete libtrace skeleton program
 *
 * This libtrace skeleton includes everything you need for a useful libtrace
 * program, including command line parsing, dealing with bpf filters etc.
 *
 */

#include "libtrace.h"
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "time.h"
#include <dirent.h>/*for scandir*/
#include <sys/stat.h>/*for strcut stat */
#include <errno.h> /*for strerror*/
#include <pthread.h>
#include "math.h"
#include "../includes/md5.h"

#define bucket_depth 1000000
#define OutfilePath "results"

#define checkResults(string, val) {            			 \
	if (val) {                                    		 \
		printf("Failed with %d at %s", val, string); \
		exit(1);                                     \
	}                                              \
}

char bucket[bucket_depth][1500];

int packet_count = 0;
int total_packets_in_trace = 0;
int ipv4=0;
int tcp_sizegtzero_packet_count = 0;
int tcp_packet_count = 0;
int empty = 0;
	
//Added on August-6-2013 for kaustubh's lander4 changes
void empty_bucket_stdout() {

	int i;
	for (i = 0; i < tcp_packet_count; i++) {	
		printf("%s", bucket[i]);
	}
	tcp_packet_count = 0;
	empty = 1;
}

void empty_bucket(FILE * fp_write) {

	int i;
	for (i = 0; i < tcp_packet_count; i++) {
		fprintf(fp_write, "%s", bucket[i]);	
	}
	tcp_packet_count = 0;
	empty = 1;
}

int issubstring(char *inputstring1, char *inputstring2){
	if(inputstring1==NULL) return 0;
	char *ptr=NULL; 
	ptr = strstr(inputstring1,inputstring2);
	if(ptr!=NULL && inputstring2[0]==*ptr) {return 1;}
	return 0;
}

char all_extentions[45][100]={"?","&",";",".css",".aspx",".js",".php",".do",".gif",".jpg","jpeg",".ico",".png",".htm",".html",".xml",".pdf",".swf",".txt",".asc",".mp3",".tpt",".tgz",".rss",".rdf",".gz",".tar",".ipa",".ini",".flv",".cms",".zip",".mp4",".ppt",".dll",".deb",".rpm",".bz2",".gpg",".cab",".psf",".tex",".conf",".crl",".cer"};

typedef struct {
	char name[50];
	int is_dynamic;
	int is_present;
}extention;

extention extention_array[45];

void initialize_extention_array(){
	int ex;
	for(ex=0;ex<45;ex++){
		extention_array[ex].is_dynamic=2;
		strcpy(extention_array[ex].name,all_extentions[ex]);
		if(strcmp(extention_array[ex].name,"?")==0||strcmp(extention_array[ex].name,";")==0||strcmp(extention_array[ex].name,"&")==0||strcmp(extention_array[ex].name,".css")==0||strcmp(extention_array[ex].name,".aspx")==0||strcmp(extention_array[ex].name,".js")==0||strcmp(extention_array[ex].name,".php")==0||strcmp(extention_array[ex].name,".do")==0){

			extention_array[ex].is_dynamic=1;

		}else {
			extention_array[ex].is_dynamic=0;
		}
		//Intialize everything to not present
		extention_array[ex].is_present=0;
	}
}

void set_extention(char* input_ext){
	int ex;
	for(ex=0;ex<45;ex++){
		if(strcmp(extention_array[ex].name,input_ext)==0){
			extention_array[ex].is_present=1;
			break; //loop no further, job done
		}
	}		
}

char URL[1500];

void mark_exts (char* payload_string){
	int i,tmplen=0,tmplen2=0,isdynamic=2;
	char *tokenarray[5],url[1500],cmd[255];	
	bzero(url,1500);
	tokenarray[0]=strtok(payload_string," ");
	tokenarray[1]=strtok(NULL," ");
	tokenarray[2]=strtok(NULL," ");



	if(tokenarray[1]!=NULL) {
		tmplen=strlen(tokenarray[1]);
	}
	else {
		strcpy(URL,"NULL");
		return;
	}
	for(i=0;i<tmplen;i++){
		url[i]=tolower(tokenarray[1][i]);
	}

	strcat(url,"\0");
	strcpy(URL,url);

	//Initialize extention parameters for this GET packet
	initialize_extention_array();

	//Loop to search for all extensions
	int lp;
	for(lp=0;lp<45;lp++){
		//Special case for htm to avoid double count of htm and html
		if(strcmp(all_extentions[lp],".htm")==0){
			if(issubstring(url,".html")==0){
				if(issubstring(url,".htm")){
					set_extention(".htm");
				}	
			}
		}
		else if (issubstring(url,all_extentions[lp])){
			set_extention(all_extentions[lp]);
		}
	}
}

int isget(char *payload, int len, int offset)
{


	int i,isget=0;

	const u_char *ch;

	char payload_string[10240],payload_first_ten[10];

	//bzero(url,2048);
	//bzero(cmd,255);
	bzero(payload_string,10240);
	bzero(payload_first_ten,10);


	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			payload_string[i]=*ch;
		ch++;
	}


	for(i=0;i<10;i++){
		payload_first_ten[i]=payload_string[i];
	}

	if(issubstring(payload_first_ten,"GET ")||issubstring(payload_first_ten,"POST "))	
	{	
		//Since payload is already read, parse to keep static and dynamic URL information
		bzero(URL,1500);	
		mark_exts(payload_string);
		isget=1;
	}

	return isget;
}


char* timestamp() {
	time_t ltime; /* calendar time */
	ltime = time(NULL); /* get current cal time */
	return (asctime(localtime(&ltime)));
}
char* to_date(char* epoch) {
	struct tm tm;
	char buf[255];
	memset(&tm, 0, sizeof(struct tm));
	strptime(epoch, "%s", &tm);
	strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y\n", &tm);
	return buf;
}

void per_packet(libtrace_packet_t * packet, FILE * fp_write) {

	struct sockaddr_storage src_addr;
	struct sockaddr_storage dest_addr;
	struct sockaddr *src_addr_ptr;
	struct sockaddr *dest_addr_ptr;
	// Packet data 
	uint32_t remaining;
	// L3 data
	void *l3;
	uint16_t ethertype;
	// Transport data 
	void *transport;
	uint8_t proto;
	// Payload data
	void *payload;

	struct timeval ts;

	l3 = trace_get_layer3(packet, &ethertype, &remaining);

	if (!l3) {
		// Probable ARP or something 
		return;
	}

	// Get the TCP header from the IPv4 packet
	switch (ethertype) {
	  case 0x0800:
		  transport = trace_get_payload_from_ip((libtrace_ip_t*) l3, &proto,
												&remaining);
		  if (!transport) {
			  return;
		  }
		  ipv4++;
		  break;
	  default:
		  return;
	}

	// Process only tcp payload
	if (proto == 6) {	
		payload = trace_get_payload_from_tcp((libtrace_tcp_t*) transport,
											 &remaining);
	} else {
		return;
	}

	// Packet size gt 0
	int pkt_size = trace_get_capture_length(packet);
	char psize[255];
	bzero(psize,255);

	if (!(pkt_size > 0)) {
		return;
	}
	//Check if payload length is greater than 0
	int pay_length= remaining;	
	if (pay_length == 0) {	
		return;
	}


	src_addr_ptr = trace_get_source_address(packet,
											(struct sockaddr *) &src_addr);
	dest_addr_ptr = trace_get_destination_address(packet,
												  (struct sockaddr *) &dest_addr);
	if ((NULL == src_addr_ptr) || (NULL == dest_addr_ptr)) {
		return;
	}


	//Time
	ts = trace_get_timeval(packet);
	char timestamp[255],time_human[255]="";
	sprintf(timestamp, "%u", ts.tv_sec);
	strcat(time_human,to_date(timestamp));
	//Src IP
	char source_ip[255];
	char src_ip[255];
	if (src_addr_ptr->sa_family == AF_INET) {
		struct sockaddr_in *src_v4 = (struct sockaddr_in *) src_addr_ptr;
		inet_ntop(AF_INET, &(src_v4->sin_addr), source_ip, 255);
	}
	sprintf(src_ip,"%s\n",source_ip);
	//Src Port
	char src_port[255];
	int src_pt = trace_get_source_port(packet);	
	sprintf(src_port, "%d\n",src_pt);
	//Dest IP
	char dest_ip[255];
	char dst_ip[255];
	if (dest_addr_ptr->sa_family == AF_INET) {
		struct sockaddr_in *dest_v4 = (struct sockaddr_in *) dest_addr_ptr;
		inet_ntop(AF_INET, &(dest_v4->sin_addr), dest_ip, 255);
	}	
	sprintf(dst_ip,"%s\n",dest_ip);	
	//Dest Port
	char dst_port[255];
	int dst_pt = trace_get_destination_port(packet);	
	sprintf(dst_port, "%d\n",dst_pt);
	//Direction
	char direction[255];
	bzero(direction,255);
	if (match_ip(dest_ip)) {
		strcpy(direction,"incoming");
	}
	else if (match_ip(source_ip)){
		strcpy(direction,"outgoing");
	}

	//Flow ID
	char flow_id[1500];
	bzero(flow_id,1500);

	//Read the Payload

	char* hash = malloc(255); //Will hold hash of payload or hash of url. This will get destroyed when return occurs
	char read_payload[1500]; //Will hold the payload
	bzero(read_payload,1500);
	memcpy(read_payload,payload,pay_length);

	// Packet info 

	//Mark bucket is not empty
	empty = 0;

	//Check if packet is GET/POST packet or CONTENT packet
	//Only if destination port is 80 check for GET
	int isget_packet=0;
	if(dst_pt == 80){	
		isget_packet = isget(read_payload,pay_length,0); 
	}else {
		return;
	}	
	if(!isget_packet){
		return;
	}

	char packet_type[255];
	bzero(packet_type,255);

	//Process GET packets

	//URL was set when this was decided to be GET/POST packet
	if(strcmp(URL,"NULL")==0){
		//Ignore this packet if URL is NULL
		return;
	}
	strcpy(packet_type,"GET ");
	strcat(packet_type,direction);	
	//Flow ID
	//sprintf(flow_id,"<flow_id>%s-%d-%s-%d-%d</flow_id>",source_ip,src_pt,dest_ip,dst_pt,proto);
	char dstplusurl[1600];
	bzero(dstplusurl,1600);
	strcat(dstplusurl,dest_ip);
	strcat(dstplusurl,URL);
	sprintf(hash,"%s\n",MDString(dstplusurl,OutfilePath,strlen(dstplusurl)));

	//Done processing this packet, now writing results
	tcp_sizegtzero_packet_count++;
	sprintf(bucket[tcp_packet_count],"%s\n",packet_type);
	strncat(bucket[tcp_packet_count], time_human,strlen(time_human));
	//strncat(bucket[tcp_packet_count], direction,strlen(direction));
	//strncat(bucket[tcp_packet_count], src_ip, strlen(src_ip));
	//strncat(bucket[tcp_packet_count], src_port, strlen(src_port));	
	strcat(bucket[tcp_packet_count],"dest: ");
	strncat(bucket[tcp_packet_count], dst_ip, strlen(dst_ip));
	//strncat(bucket[tcp_packet_count], dst_port, strlen(dst_port));	
	//strncat(bucket[tcp_packet_count], flow_id,strlen(flow_id));

	int lp,first_ex=1,set=0,at_least_one_extension=0;
	char static_extension[3]="0";

	for(lp=0;lp<45;lp++){		
		if(extention_array[lp].is_present==1){	
			at_least_one_extension=1;
			strncat(bucket[tcp_packet_count],extention_array[lp].name, strlen(extention_array[lp].name));	
			strcat(bucket[tcp_packet_count],"\n");
			if(extention_array[lp].is_dynamic==0 && !set){
				set=1;
				strcpy(static_extension,"1");
			}
		}
	}
	if(!at_least_one_extension){
		strcat(bucket[tcp_packet_count],"NoClassURL");
	}


	if(strcmp(static_extension,"1")==0){

		strcat(bucket[tcp_packet_count], "hash: ");
		strncat(bucket[tcp_packet_count], hash, strlen(hash));	
	}

	//char urllen[1500];
	//sprintf(urllen,"<url_len>%d</url_len>",strlen(URL));
	//strncat(bucket[tcp_packet_count],urllen, strlen(urllen));

	strcat(bucket[tcp_packet_count],"GET PACKET END\n");

	free(hash);

	tcp_packet_count++;

	if (tcp_packet_count == (bucket_depth)) {
		//empty_bucket(fp_write);
		empty_bucket_stdout();
	}



}
int file_exists(const char * filename)
{
	FILE * file;
	if (file = fopen(filename, "r"))
	{
		fclose(file);
		return 1;
	}
	return 0;
}
int main(int argc, char *argv[]) {

	//To calculate execution time
	clock_t start;
	clock_t end;
	double function_time;

	time(&start);

	char* start_timestamp;
	start_timestamp = timestamp();

	//Create Trie of CSU prefixes
	create_trie();

	libtrace_filter_t *filter = NULL;
	FILE * fp_write = NULL;
	FILE * fp_stats = NULL;
	int snaplen = -1;
	int promisc = -1;

	char inputfile[1024];
	char outputfile[1024];
	char outputstats[1024];

	strcpy(inputfile, argv[1]);

	int i = 0;
	for (i = 0; i < bucket_depth; i++) {
		bzero(bucket[i], sizeof(bucket[i]));
	}

	libtrace_t *trace;
	libtrace_packet_t *packet;

	char temp[1024];
	char outputfile_temp[32];

	bzero(temp, sizeof(temp));
	bzero(outputfile_temp, sizeof(outputfile_temp));
	bzero(outputfile, sizeof(outputfile));
	bzero(outputstats, sizeof(outputstats));


	strcpy(temp, inputfile);
	char * p = NULL;
	p = strtok(temp, "/");
	if (p) {
		while (1) {
			p = strtok(NULL, "/");
			if (p) {
				bzero(outputfile_temp, sizeof(outputfile_temp));
				strcpy(outputfile_temp, outputfile);
				bzero(outputfile, sizeof(outputfile));
				strcpy(outputfile, p);

			} else {
				break;
			}
		}
	} else {
		strcpy(outputfile, p);
	}

	bzero(temp, sizeof(temp));
	strcpy(temp, outputfile);
	bzero(outputfile, sizeof(outputfile));
	sprintf(outputfile, "%s/%s-output.results", OutfilePath, temp);
	sprintf(outputstats, "%s/%s-output.info", OutfilePath, temp);

	/*
	if ((fp_write = fopen(outputfile, "w+")) == NULL) //open the file to read
	{
		fprintf(stderr, "Open File %s Failed\n", outputfile);
		exit(1);
	}
	*/
	if ((fp_stats = fopen(outputstats, "w+")) == NULL) //open the file to read
	{
		fprintf(stderr, "Open File %s Failed\n", outputstats);
		exit(1);
	}


	fprintf(fp_stats, "This file was picked up for processing at: %s\n",
			start_timestamp);

	trace = trace_create(inputfile);
	if (trace_is_err(trace)) {
		trace_perror(trace, "Opening trace file");
		return 1;
	}
	if (trace_start(trace)) {
		trace_perror(trace, "Starting trace");
		trace_destroy(trace);
		return 1;
	}


	packet = trace_create_packet();
	//Loop to process all packets
	while (trace_read_packet(trace, packet) > 0) {
		total_packets_in_trace++;
		per_packet(packet, fp_write);

	}
	trace_destroy_packet(packet);
	trace_destroy(trace);


	//Leftovers in bucket
	if (!empty) {
		//empty_bucket(fp_write);	
		empty_bucket_stdout();
	}

	fprintf(fp_stats, "Total number of packets in trace: %d\n",
			total_packets_in_trace);

	fprintf(fp_stats, "Total number of packets processed (IPv4,TCP,Payload>0): %d\n",
			tcp_sizegtzero_packet_count);

	trace = trace_create(inputfile);
	if (trace_is_err(trace)) {	
		fprintf(fp_stats, "\nCould not finish processing at: %s\n",timestamp());
	}else{
		fprintf(fp_stats, "\nThis file was finished processing at: %s\n",timestamp());
	}
	trace_destroy(trace);


	time(&end);
	double cost = difftime(end, start);
	fprintf(fp_stats, "Processing time: %f seconds\n", cost);

	//fclose(fp_write);
	fclose(fp_stats);

	return 0;
}
