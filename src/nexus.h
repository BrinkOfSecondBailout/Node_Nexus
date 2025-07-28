/* nexus.h */
#ifndef NEXUS_H
#define NEXUS_H

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/sem.h>
#include <sys/mman.h>
#include <poll.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "database.h"

#define PORT				"8000"
#define HOST				"127.0.0.1"
#define MAX_FILE_UPLOAD			1048576 //1MB
#define MAX_USERNAME_LEN		32

#define WRITE_GLOBAL_BUF(x)		written = snprintf(global_buf + used, remaining, x); \
					if (written < 0 || (size_t)written >= remaining) goto buffer_full; \
					used += written; \
					remaining -= written; 




typedef unsigned int int32;
typedef unsigned short int int16;
typedef unsigned char int8;

typedef struct s_command_handler Command_Handler;
// typedef struct s_client Client;

typedef int32 (*Callback)(Client *, char *, char *);

/* struct s_client {
	int s;
	char ip[16];
	int16 port;
	size_t logged_in;
	char username[MAX_USERNAME_LEN];
};*/

struct s_command_handler {
	char *cmd_name;
	Callback callback_function;
};
int32 help_handle(Client *, char *, char *);
int32 register_handle(Client *, char *, char *);
int32 login_handle(Client *, char *, char *);
int32 users_handle(Client *, char *, char *);
int32 logout_handle(Client *, char *, char *);
int32 tree_handle(Client *, char *, char *);
int32 newdir_handle(Client *, char *, char *);
int32 back_handle(Client *, char *, char *);
int32 root_handle(Client *, char *, char *);
int32 curr_handle(Client *, char *, char *);
int32 jump_handle(Client *, char *, char *);
int32 addfile_handle(Client *, char *, char *);
int32 open_handle(Client *, char *, char *);
int32 save_handle(Client *, char *, char *);
int32 kill_handle(Client *, char *, char *);
int32 classify_handle(Client *, char *, char *);
int32 nuke_handle(Client *, char *, char *);
int32 boot_all_handle(Client *, char *, char *);
int32 exit_handle(Client *, char *, char *);

#endif
