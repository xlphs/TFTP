#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

#define DATA_SIZE   	 512
#define MAX_FILENAME	 255
#define INITIAL_BLOCK 0
#define MAX_TIMEOUTS	 5
#define TIMEOUT_SECS	3

/* Opcodes */
#define RRQ    1
#define WRQ    2
#define DATA   3
#define ACK	   4
#define ERROR  5

static const char *TFTP_error_messages[] = {
	"Undefined error",                 // Error code 0
	"File not found",                  // 1
	"Access violation",                // 2
	"Disk full or allocation error",   // 3
	"Illegal TFTP operation",          // 4
	"Unknown transfer ID",             // 5
	"File already exists",             // 6
	"No such user"                     // 7
};
extern int errno;
typedef struct {
	unsigned short int opcode;
	char filename[MAX_FILENAME];
	char zero_0;
	char mode[MAX_FILENAME];
	char zero_1;
} TFTP_Request;
typedef struct {
	unsigned short int opcode;
	unsigned short int block;
	char data[DATA_SIZE];
} TFTP_Data;
typedef struct {
	unsigned short int opcode;
	unsigned short int block;
} TFTP_Ack;

/* Global vars */
static int is_debugging = 0, timeout;
jmp_buf timeoutbuf, endbuf;

int get_port(char* s) {
	 int retval = 0;
	 char *a = s;
	 while (*a != '\0') {
		  if (*a >= '0' && *a <= '9') {
				retval = retval * 10 + (*a - '0');
		  } else {
				return -1;
		  }
		  a++;
	 }
	 return retval;
}

/* Returns 0 for sucess, otherwise -1. */
int make_socket(struct sockaddr_in *s, char *host, int port) {
	s->sin_family = AF_INET;
	if (host != NULL) {
		struct hostent *he = gethostbyname(host);
		if (he == NULL) {
			perror("gethostbyname");
			return -1;
		}
		s->sin_addr = *((struct in_addr *)he->h_addr);
	} else {
		s->sin_addr.s_addr = htonl(INADDR_ANY);
	}
	s->sin_port = htons(port);
	memset(&(s->sin_zero), 0, 8);
	return 0;
}

/* Returns 0 a file that exists, other -1. */
int file_exists(char *filename) {
	struct stat filebuf;
	if ( stat(filename, &filebuf) == 0 ) {
		return 0;
	} else {
		return -1;
	}
}

/* Fill in the struct using data from buffer */
void packet_to_request(TFTP_Request *r, char *buf) {
	char filename[MAX_FILENAME];
	char mode[MAX_FILENAME];
	short signed int code;
	code = *(short signed int*)buf;
	buf += sizeof(r->opcode);
	strcpy(filename, buf);
	buf += strlen(filename) + 1;
	strcpy(mode, buf);
	r->opcode = ntohs(code);
	strcpy(r->filename, filename);
	r->zero_0 = '\0';
	strcpy(r->mode, mode);
	r->zero_1 = '\0';
}

/* Fill the given buffer using data from the given request */
void request_to_packet(TFTP_Request *r, char *buf) {
	char *pos = buf;
	*(short signed int*)pos = htons(r->opcode);
	pos += sizeof(r->opcode);
	strcpy(pos, r->filename);
	pos += strlen(r->filename) + 1;
	*pos = r->zero_0;
	strcpy(pos, r->mode);
	pos += strlen(r->mode) + 1;
	*pos = r->zero_1;
}

/* Computes length of request */
int request_length(TFTP_Request *r) {
	int len = sizeof(r->opcode) + sizeof(r->zero_0) + sizeof(r->zero_1);
	len += strlen(r->filename) + 1;
	len += strlen(r->mode) + 1;
	return len;
}

/* Returns 0 if request has the given mode, otherwise 0 */
int request_is_mode(TFTP_Request *r, char *mode) {
	if (strcmp(r->mode, mode) == 0) return 0;
	return -1;
}

void request_init(TFTP_Request *r, unsigned short int opcode, char *filename, char *mode) {
	memset(r, 0, sizeof(TFTP_Request));
	r->opcode = opcode;
	strcpy(r->filename, filename);
	r->zero_0 = '\0';
	strcpy(r->mode, "octet");
	r->zero_1 = '\0';
}

void timer(int sig) {
	switch(sig) {
		case SIGALRM: {
			timeout++;
			if (timeout >= MAX_TIMEOUTS) {
				if (is_debugging) printf("Retransmission timed out.\n");
				timeout = 0;
				alarm(0);
				longjmp(endbuf, sig);
			}
			if (is_debugging) printf("Retransmitting.\n");
			longjmp(timeoutbuf, sig);
		} break;
		case SIGINT: {
			if (is_debugging) printf("Transfer interrupted.\n");
			timeout = 0;
			alarm(0);
			longjmp(endbuf, sig);
		} break;
		default: break;
	}
}

void send_data(int sockfd, struct sockaddr *to_addr, socklen_t addr_len, char *filename) {
	int filesize, n, pos = 0, nextAck = -1;
	signed short int block = 0; 
	int fd = open(filename, O_RDONLY, 0006);
	
	if (fd == -1) {
		perror("open");
		exit(1);
	}
	filesize = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	
	/* Allocate memory for DATA, ACK structs */
	TFTP_Data *dataPacket;
	TFTP_Ack *ack;
	dataPacket = (TFTP_Data *)malloc(sizeof(TFTP_Data));
	ack = (TFTP_Ack *)malloc(sizeof(TFTP_Ack));
	memset(dataPacket, 0, sizeof(TFTP_Ack));
	memset(ack, 0, sizeof(TFTP_Ack));
	
	/* Read from file and send data to server */
	while (pos < filesize) {
		char dataBuf[DATA_SIZE] = {0};
		n = read(fd, &dataBuf, DATA_SIZE);
		if (n == -1) {
			perror("read");
			exit(1);
		}
		pos += n;
		
		block++;
		dataPacket->opcode = htons(DATA);
		dataPacket->block = htons(block);
		if (is_debugging) printf("Block #%d, %d bytes\n", block, n);
		memset(dataPacket->data, 0, DATA_SIZE);
		memcpy(dataPacket->data, dataBuf, n);
		
		sigsetjmp(timeoutbuf, 1); // jump for retransmission
		if (is_debugging) printf("Sending DATA for block #%d\n", block);
		n = sendto(sockfd, dataPacket, 4 + n, 0, to_addr, addr_len);
		if (n < 0) {
			if (is_debugging) printf("Error sending DATA block #%d\n", block);
			break;
		}
		
		if (sigsetjmp(endbuf, 1) != 0) {
			// setup jump for retransmission timeout and interrupt
			break;
		}
		signal(SIGINT, timer);
		signal(SIGALRM, timer);
		
		while (nextAck < 0) {
			/* Receive ACK for the sent DATA */
			if (is_debugging) printf("Waiting for ACK...\n");
			alarm(TIMEOUT_SECS); // start new timer
			n = recvfrom(sockfd, ack, sizeof(TFTP_Ack), 0, to_addr, &addr_len);
			timeout = 0;
			alarm(0);
			if (n < 0) {
				if (is_debugging) printf("Error receiving ACK for block #%d\n", block);
				break;
			}
			
			if (ntohs(ack->opcode) == ERROR) {
				if (is_debugging) printf("Received ERROR: %s\n", TFTP_error_messages[ntohs(ack->block)]);
			}
			else if (ntohs(ack->opcode) == ACK) {
				/* Check block */
				if (ntohs(ack->block) == block) {
					nextAck = 1;
					if (pos == filesize) {
						if (is_debugging) printf("Received ACK for final block #%d\n", block);
						break;
					} else {
						if (is_debugging) printf("Received ACK for block #%d\n", block);
						continue;
					}
				} else if (ntohs(ack->block) < block) {
					nextAck = -1;
				}
			}
		}
		
		nextAck = -1;
	}
	
	free(dataPacket);
	free(ack);
	close(fd);
}

void recv_data(int sockfd, char *filename) {
	struct sockaddr client_addr;
	int n;
	socklen_t clilen;
	short signed int block = 0, nextBlock = 1;

	/* Allocate memory for DATA, ACK and FILE structs */
	TFTP_Data *dataPacket = malloc(sizeof(TFTP_Data));
	TFTP_Ack *ack = malloc(sizeof(TFTP_Ack));
	memset(dataPacket, 0, sizeof(TFTP_Data));
	memset(ack, 0, sizeof(TFTP_Ack));
	FILE * file = fopen(filename, "ab");
	
	while (1) {
		clilen = sizeof(struct sockaddr);
		int length;
		
		if (sigsetjmp(endbuf, 1) != 0) {
			// setup jump for retransmission timeout and interrupt
			break;
		}
		signal(SIGINT, timer);
		signal(SIGALRM, timer);
		
		/* Receive the DATA */
		if (is_debugging) printf("Waiting for DATA...\n");
		alarm(TIMEOUT_SECS); // start new timer
		n = recvfrom(sockfd, dataPacket, sizeof(TFTP_Data), 0, (struct sockaddr *)&client_addr, &clilen);
		timeout = 0;
		alarm(0); // void timer
		if (n < 0) break;
		
		/* Received a duplicate DATA block */
		if (ntohs(dataPacket->block) < nextBlock) {
			if (is_debugging) printf("Received duplicate DATA for block #%d\n", ntohs(dataPacket->block));
		}
		else {
			length = strlen(dataPacket->data);
			if (length == 0) break;
			
			/* Fill the data buffer */
			char dataBuf[DATA_SIZE+1];
			strcpy(dataBuf, dataPacket->data);
			if (length > DATA_SIZE) {
				dataBuf[DATA_SIZE] = '\0';
				length = strlen(dataBuf);
			}
			if (is_debugging) printf("Received DATA for block #%d of size %d\n", ntohs(dataPacket->block), length);

			/* Write data to the file and check if disk is full */
			fwrite(dataBuf, sizeof(char), length, file);
			if (errno == ENOSPC) {
				if (is_debugging) printf("Sending error: %s\n", TFTP_error_messages[3]);
				ack->opcode = htons(ERROR);
				ack->block = htons(3);
				n = sendto(sockfd, ack, sizeof(TFTP_Ack), 0, &client_addr, clilen);
				break;
			}

			/* Fill ACK if correct block received */
			block = nextBlock;
			nextBlock++;
			ack->opcode = htons(ACK);
			ack->block = htons(block);
		}
		
		sigsetjmp(timeoutbuf, 1); // jump for retransmission
		if (is_debugging) printf("Sending ACK for block #%d\n", block);
		n = sendto(sockfd, ack, sizeof(TFTP_Ack), 0, &client_addr, clilen);
		if (n < 0) {
			printf("Error sending ACK.\n");
			break;
		}
		
		/* last block of DATA */
		if (length < DATA_SIZE) break;
	}

	free(dataPacket);
	free(ack);
	fclose(file);
}

void send_error(int sockfd, struct sockaddr *to_addr, socklen_t addrlen, TFTP_Ack *ack, char *msg) {
	int len = sizeof(TFTP_Ack)+strlen(msg)+1;
	char *buf = (char *)malloc(len);
	char *pbuf = buf;
	memset(buf, 0, len);
	*(short signed int*)pbuf = htons(ack->opcode);
	pbuf += sizeof(ack->opcode);
	*(short signed int*)pbuf = htons(ack->block);
	pbuf += sizeof(ack->block);
	strcpy(pbuf, msg);
	sendto(sockfd, buf, len, 0, to_addr, addrlen);
	free(buf);
}

int server_process(int oldsockfd, struct sockaddr *client_addr, TFTP_Request *request) {
	int pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}
	if (pid == 0) {
		close(oldsockfd);
		
		int sockfd = 0;
		if ((sockfd=socket(AF_INET,SOCK_DGRAM,0)) == -1) {
			perror("socket");
			exit(1);
		}
		struct sockaddr_in serv_addr;
		make_socket(&serv_addr, NULL, 0);
		if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr)) == -1) {
			perror("bind");
			exit(0);
		}
		unsigned int addr_len = sizeof(struct sockaddr);
		if (getsockname(sockfd, (struct sockaddr *)&serv_addr, &addr_len) == -1) {
			perror("getsockname");
			exit(1);
		}
		if (is_debugging) printf("Child process listening on port %i\n", ntohs(serv_addr.sin_port));
		
		/* Allocate memory for ACK struct */
		TFTP_Ack *ack = (TFTP_Ack *)malloc(sizeof(TFTP_Ack));
		memset(ack, 0, sizeof(TFTP_Ack));
		
		/* Octet mode only */
		if (request_is_mode(request, "octet") != 0) {
			ack->opcode = htons(ERROR);
			ack->block = htons(0);
			send_error(sockfd, client_addr, addr_len, ack, "mode not supported");
			free(ack);
			close(sockfd);
			free(request);
			exit(1);
		}
		
		if (request->opcode == WRQ) {
			/* file should not exist locally */
			if ( file_exists(request->filename) == 0 ) {
				exit(1);
			}
			
			/* Fill ACK struct and compute packet length */
			ack->opcode = htons(ACK);
			ack->block = htons(INITIAL_BLOCK);
			/* Send ACK and start receiving DATA */
			sendto(sockfd, ack, sizeof(TFTP_Ack), 0, client_addr, addr_len);
			recv_data(sockfd, request->filename);
		}
		else if (request->opcode == RRQ) {
			/* file must exist locally */
			if ( file_exists(request->filename) == -1 ) {
				exit(1);
			}
			/* Send data */
			send_data(sockfd, client_addr, addr_len, request->filename);
		}
		else {
			if (is_debugging) printf("Received request with unknown opcode: %i\n", request->opcode);
		}
		
		free(ack);
		close(sockfd);
		free(request);
		exit(0);
	}
	return pid;
}

void chld_trap(int s) {
	int pid = wait(NULL);
	if (pid < 0) {
		return; // wait went wrong, fly away
	} 
}

void run_server(int port) {
	/* install signal handlers */
	signal(SIGCHLD, chld_trap);
	
	int sockfd;
	struct sockaddr_in my_addr;
	struct sockaddr_in client_addr;
	unsigned int addr_len, numbytes;
	char *buf;
	
	/* Try to bind socket to the port */
	if ((sockfd=socket(AF_INET,SOCK_DGRAM,0)) == -1) {
		perror("socket");
		exit(1);
	}
	make_socket(&my_addr, NULL, port);
	if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
		exit(1);
	}
	
	/* Listen for incoming requests until program is teminated */
	if (is_debugging) printf("Listening on port %i\n", ntohs(my_addr.sin_port));
	while (1) {
		buf = (char *)malloc( sizeof(TFTP_Request) );
		memset(buf, 0, sizeof(TFTP_Request));
		addr_len = sizeof(struct sockaddr);
		
		numbytes = recvfrom(sockfd, buf, sizeof(TFTP_Request), 0, (struct sockaddr *)&client_addr, &addr_len);
		if (numbytes < 0) {
			free(buf);
			continue;
		}
		
		if (is_debugging) {
			printf("Got packet from %s:%d, %i bytes.\n",
						inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), numbytes
			);
		}
		
		TFTP_Request *request = (TFTP_Request *)malloc( sizeof(TFTP_Request) );
		packet_to_request(request, buf);
		free(buf);
		
		server_process(sockfd, (struct sockaddr *)&client_addr, request);
		free(request);
	}
	
	close(sockfd);
}

void send_request_read(char *host, int port, char *filename) {
	int n, len;
	int mysockfd;
	struct sockaddr_in serv_addr;
	struct sockaddr_in my_addr;
	unsigned int addr_len;
	
	/* Prepare the sockets */
	make_socket(&serv_addr, host, port);
	if ((mysockfd=socket(AF_INET,SOCK_DGRAM,0)) == -1) {
		perror("socket");
		exit(1);
	}
	make_socket(&my_addr, NULL, 0);
	if (bind(mysockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
		exit(1);
	}
	addr_len = sizeof(struct sockaddr);
	
	/* Allocate the Ack struct */
	TFTP_Ack *ack =  (TFTP_Ack *)malloc(sizeof(TFTP_Ack));
	memset(ack, 0, sizeof(TFTP_Ack));
	
	/* Create the request */
	TFTP_Request *request = (TFTP_Request *)malloc(sizeof(TFTP_Request));
	request_init(request, RRQ, filename, "octet");
	len = request_length(request);
	char *req_buffer = (char*)malloc(len);
	memset(req_buffer, 0, len);
	request_to_packet(request, req_buffer);
	
	/* Send the request */
	sigsetjmp(timeoutbuf, 1);
	if (is_debugging) printf("Sending read request to server, %i bytes.\n", len);
	n = sendto(mysockfd, req_buffer, len, 0, (struct sockaddr *)&serv_addr, addr_len);
	if (n < 0) {
		if (is_debugging) printf("Error sending read request!\n");
		free(ack);
		free(request);
		free(req_buffer);
		close(mysockfd);
		exit(1);
	}
	
	/* Just receive data */
	recv_data(mysockfd, filename);
	
	free(ack);
	free(request);
	free(req_buffer);
	close(mysockfd);
}

void send_request_write(char *host, int port, char *filename) {
	int mysockfd, n, len;
	struct sockaddr_in serv_addr, my_addr;
	unsigned int addr_len;
	
	/* Prepare the sockets */
	make_socket(&serv_addr, host, port);
	if ((mysockfd=socket(AF_INET,SOCK_DGRAM,0)) == -1) {
		perror("socket");
		exit(1);
	}
	make_socket(&my_addr, NULL, 0);
	if (bind(mysockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
		exit(1);
	}
	addr_len = sizeof(struct sockaddr);
	
	/* Allocate the Ack struct */
	TFTP_Ack *ack =  (TFTP_Ack *)malloc(sizeof(TFTP_Ack));
	memset(ack, 0, sizeof(TFTP_Ack));
	
	/* Create the request */
	TFTP_Request *request = (TFTP_Request *)malloc(sizeof(TFTP_Request));
	request_init(request, WRQ, filename, "octet");
	len = request_length(request);
	char *req_buffer = (char*)malloc(len);
	memset(req_buffer, 0, len);
	request_to_packet(request, req_buffer);
	
	/* Send the request */
	sigsetjmp(timeoutbuf, 1); // jump for retransmission
	if (is_debugging) printf("Sending write request to server, %i bytes.\n", len);
	n = sendto(mysockfd, req_buffer, len, 0, (struct sockaddr *)&serv_addr, addr_len);
	if (n < 0) {
		if (is_debugging) printf("Error sending write request!\n");
		exit(1);
	}
	
	if (sigsetjmp(endbuf, 1) != 0) {
		// jump for retransmission failure or interrupt
		free(ack);
		free(request);
		free(req_buffer);
		close(mysockfd);
		exit(1);
	}
	
	/* Wait for the Ack */
	if (getsockname(mysockfd, (struct sockaddr *)&my_addr, &addr_len) == -1) {
		if (is_debugging) perror("getsockname");
		exit(1);
	}
	if (is_debugging) printf("Waiting for ACK on port %d...\n", ntohs( my_addr.sin_port ));
	signal(SIGINT, timer);
	signal(SIGALRM, timer);
	alarm(TIMEOUT_SECS);
	n = recvfrom(mysockfd, ack, sizeof(TFTP_Ack), 0, (struct sockaddr *)&serv_addr, &addr_len);
	alarm(0);
	timeout = 0;
	if (n < 0) {
		if (is_debugging) printf("Error receiving ACK from server!\n");
		exit(1);
	}
	
	/* Check the Opcode */
	if (ntohs(ack->opcode) == ERROR) {
		if (is_debugging) printf("Received ERROR: %s\n", TFTP_error_messages[ntohs(ack->block)]);
	}
	else if ( ntohs(ack->opcode) == ACK && ntohs(ack->block) == INITIAL_BLOCK ) {
		if (is_debugging) printf("Received ACK for block #%d\n", ntohs(ack->block));
		send_data(mysockfd, (struct sockaddr *)&serv_addr, addr_len, filename);
	} else {
		if (is_debugging) printf("Received packet other than expected ACK\n");
	}
	
	free(ack);
	free(request);
	free(req_buffer);
	close(mysockfd);
}

void run_client(char *host, int port, char mode, char *filename) {
	void (* sender)(char *, int , char *) = NULL;
	int exist = (mode == 'r') ? 0 : -1;
	if (file_exists(filename) == exist) {
		/* Nothing to do here */
		exit(1);
	}
	sender = (mode == 'r') ? &send_request_read : &send_request_write;
	if (sender != NULL) sender(host, port, filename);
}

/*
 * Server: mytftp -l [-p port] [-v]
 * Client: mytftp [-p port] [-v] [-r|w file] host
 */
int main(int argc, char** argv) {
	int server = 0;
	int port = 3335;
	char mode = 0;
	char *filename = NULL;
	char *host = NULL;
	
	/* Parse the arguments */
	while (--argc > 0) {
		char *str = *++argv;
		if (*str != '-') {
			host = (char *)malloc( sizeof(char)*(strlen(str)+1) );
			strcpy(host, str);
			continue;
		}
		str++;
		if (*str == 'l') {
			server = 1;
		}
		else if (*str == 'p') {
			if (--argc > 0) {
				port = get_port(*++argv);
				if (port < 0) {
					printf("Invalid port number: %s\n", *argv);
					exit(0);
				}
			}
		}
		else if (*str == 'v') {
			is_debugging = 1;
			printf("Verbose mode on.\n");
		}
		else if (*str == 'r' || *str == 'w') {
			mode = *str;
			--argc;
			filename = (char *)malloc( sizeof(char)*(strlen(*++argv)+1) );
			strcpy(filename, *argv);
		}
	}
	
	if (server == 1) {
		run_server(port);
	} else {
		if (host != NULL && mode > 0 && filename != NULL) {
			run_client(host, port, mode, filename);
			free(host);
			free(filename);
		} else {
			printf("Usage:\nServer: mytftp -l [-p port] [-v]\nClient: mytftp [-p port] [-v] [-r|w file] host\n");
		}
	}

	return 0;
}
