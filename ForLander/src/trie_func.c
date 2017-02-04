#include"../includes/patricia.h"
#include"../includes/list.h"

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

// Create trie 
patricia_tree_t *prefixes;
// Node list.
list_node_t *head; 

// Destroy tries.
void destroy_tries()
{
    Destroy_Patricia(prefixes, NULL);
}

// Write the cachable fib to output file.
void write_cachable_fib(patricia_node_t * n)
{
    // Write nodes prefix, interface to file.
    if (n) {
	printf("%s/%d\n", prefix_toa(n->prefix),n->prefix->bitlen);
    }
    
}


int create_trie()
{
	/*
    // Check if we have the right number of arguments.
    if (argc != 2) {
	fprintf(stderr, "usage: %s prefix_file output_file\n", argv[0]);
	return 1;
    }
	*/
    // Create trie for FIB.
    prefixes = New_Patricia(32);
    if (!prefixes) {
	fprintf(stderr, "Could not create patricia tree\n");
	return 1;
    }



    // Create node list.
    head = new_node();

    // File pointers for input
    //FILE *infile;
    //if ((infile = fopen(filename, "r")) == NULL) {
	//perror("fopen");
	//destroy_tries();
	//return 1;
    //}

	char infile[6][50];
	int i;
	for(i=0;i<6;i++){
		bzero(infile[i],50);
	}
	strcpy(infile[0],"129.82.0.0/16");
	strcpy(infile[1],"129.19.0.0/19");
	strcpy(infile[2],"198.59.46.0/24");
	strcpy(infile[3],"198.59.47.0/24");
	strcpy(infile[4],"198.59.48.0/24");
	strcpy(infile[5],"198.59.49.0/24");

    
    // Populate trie from prefix file.
    // Prefix file has format: prefix,interface
    // Also populate node list
    char line[100];
    char *prefix; 

    patricia_node_t *node;
    list_node_t *new_list_node;	
	for(i=0;i<6;i++){
	prefix = infile[i];
	//printf("Adding %s\n",prefix);
	node = make_and_lookup(prefixes, prefix);
	new_list_node = insert(head, node);
    }

    // Close infile.
    //fclose(infile);

	//char dstip[100]="129.82.23.34";
	//int ret=match_ip(dstip);

    return 0;
}

int match_ip(char *dstip){

	//Test for IP
    patricia_node_t *ip_node;

	ip_node=try_search_best(prefixes,dstip);

    // Write output file
    //write_cachable_fib(ip_node);
   if(ip_node!=NULL){ 
	return 1;
   }
   else{
   	return 0;
   }


}
