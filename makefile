all:
	gcc -g -w src/packet_processor.c src/trie_func.c src/patricia.c src/list.c -ltrace -o bin/packet_processor 
debug:
	gcc -g -Wall src/packet_processor.c src/trie_func.c src/patricia.c src/list.c -ltrace -o bin/packet_processor 
clean:
	rm bin/packet_processor
