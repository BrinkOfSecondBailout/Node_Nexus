/* cli.h */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/sem.h>

#define MAX_CONNECTION			50
#define PORT				"8000"
#define HOST				"127.0.0.1"
#define MAX_FILE_UPLOAD			1048576 //1MB
typedef unsigned int int32;
typedef unsigned short int int16;
typedef unsigned char int8;

typedef struct s_command_handler Command_Handler;
typedef struct s_client Client;

typedef int32 (*Callback)(Client *, char *, char *);

struct s_client {
	int s;
	char ip[16];
	int16 port;
};

struct s_command_handler {
	char *cmd_name;
	Callback callback_function;
};
// int32 temp_handle(Client *, char *, char *);
int32 help_handle(Client *, char *, char *);
int32 tree_handle(Client *, char *, char *);
int32 newdir_handle(Client *, char *, char *);
int32 back_handle(Client *, char *, char *);
int32 root_handle(Client *, char *, char *);
int32 curr_handle(Client *, char *, char *);
int32 jump_handle(Client *, char *, char *);
int32 addfile_handle(Client *, char *, char *);
int32 open_handle(Client *, char *, char *);
int32 save_handle(Client *, char *, char *);
int32 exit_handle(Client *, char *, char *);
