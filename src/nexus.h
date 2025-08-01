/* nexus.h */
#ifndef NEXUS_H
#define NEXUS_H

#include "nexus.h"
#include "database.h"
#include "myserver.h"
#include "base64.h"
#include "classifier.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/sem.h>
#include <sys/mman.h>
#include <poll.h>

#pragma GCC diagnostic ignored "-Wstringop-truncation"
#pragma GCC diagnostic push

#define PORT				"8000"
#define HOST				"127.0.0.1"
#define MAX_FILE_UPLOAD			1048576 //1MB

#define WRITE_GLOBAL_BUF(x)		written = snprintf(global_buf + used, remaining, x); \
					if (written < 0 || (size_t)written >= remaining) goto buffer_full; \
					used += written; \
					remaining -= written; 



typedef unsigned int int32;
typedef unsigned short int int16;
typedef unsigned char int8;

typedef struct s_command_handler Command_Handler;

typedef int32 (*Callback)(Client *, char *, char *);

struct s_command_handler {
	char *cmd_name;
	Callback callback_function;
};

int32 help_handle(Client *, char *, char *);
int32 register_handle(Client *, char *, char *);
int32 login_handle(Client *, char *, char *);
int32 change_pw_handle(Client *, char *, char *);
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
int32 destroy_handle(Client *, char *, char *);
int32 classify_handle(Client *, char *, char *);
int32 banish_handle(Client *, char *, char *);
int32 nuke_handle(Client *, char *, char *);
int32 boot_handle(Client *, char *, char *);
int32 boot_all_handle(Client *, char *, char *);
int32 exit_handle(Client *, char *, char *);

#endif
