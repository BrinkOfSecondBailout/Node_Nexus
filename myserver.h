/* myserver.h */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>



#pragma GCC diagnostic ignored "-Wstringop-truncation"
#pragma GCC diagnostic ignored "-Wunused-result"
#pragma GCC diagnostic ignored "-Wunused-variable"

#pragma GCC diagnostic push

#define MAX_CONNECTIONS 50

#define METHOD_LENGTH 8
#define URL_LENGTH 128
#define LOCAL_HOST "127.0.0.1"



struct http_request {
	char method[METHOD_LENGTH];
	char url[URL_LENGTH];
};

typedef struct http_request http_req;

struct sFile {
	char file_name[64];
	int fd;
	off_t size;
};

typedef struct sFile File;

// void sigint_handler(int);
// int server_init(const char *, int);
// int cli_accept(int);
// int http_headers(int, int);
// int http_response(int, const char *, const char*);
// File *read_file(const char *);
// http_req *http_parse(char *);
// char *read_cli_header(int);
// char *get_mime_type(const char*);
// void sanitize_input(char *, size_t, const char *);
// int send_file(int, const char *, File *);
// void url_decode(char *, const char *, size_t);
void clean_up(int, ...);
// char *read_client_body(int, const char *);
// int cli_connection(int);
int start_server(int, char **);

