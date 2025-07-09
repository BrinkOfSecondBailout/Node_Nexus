/* cli.c */
#include "database.h"
#include "cli.h"
#include "myserver.h"

static Node *root = NULL;
static Node *curr_node = NULL;
static char global_buf[1024];
static volatile int keep_running = 1;
static volatile int keep_running_child = 1;
int active_connections = 0;

Command_Handler c_handlers[] = {
	{ (char *)"hello", hello_handle },
	{ (char *)"help", help_handle },
	{ (char *)"tree", tree_handle },
	{ (char *)"newdir", newdir_handle },
	{ (char *)"back", back_handle },
	{ (char *)"root", root_handle },
	{ (char *)"curr", curr_handle },
	{ (char *)"exit", exit_handle }	
};

int32 hello_handle(Client *cli, char *folder, char *args) {
	dprintf(cli->s, "hello back!\n\n");
	return 0;
}

int32 help_handle(Client *cli, char *folder, char *args) {
	zero(global_buf, sizeof(global_buf));
	char *instructions = "-- 'help' - list all available command apis\n"
	"-- 'tree' - show all current folders and files\n"
	"-- 'newdir <name>' - add new directory in current folder\n"
	"-- 'back' - jump back one directory\n"
	"-- 'root' - jump back to root directory\n"
	"-- 'curr' - list current directory\n"
	"-- 'exit' - exit program\n";

	strncpy(global_buf, instructions, sizeof(global_buf));
	dprintf(cli->s, "%s\n", global_buf);
	return 0;
}

int32 tree_handle(Client *cli, char *folder, char *args) {
	print_tree(cli->s, root);
	return 0;
}

int32 newdir_handle(Client *cli, char *folder, char *args) {
	if ((strlen(folder) < 1)) {
		dprintf(cli->s, "Please enter a name for new directory\n");
		return 1;
	}
	Node *temp = create_new_node(curr_node, folder);
	if (temp) {
		dprintf(cli->s, "Successfully created new directory '%s' in current folder '%s'\n", folder, curr_node->path);
		curr_node = temp;
	} else {
		dprintf(cli->s, "Unsuccessful at creating new directory '%s' in current folder '%s'.. Please try again..\n", folder, curr_node->path);
	}
	return 0;
}

int32 back_handle(Client *cli, char *folder, char *args) {
	if (curr_node == root) {
		dprintf(cli->s, "Already at root node '/'\n");
	} else {
		curr_node = curr_node->parent;
		dprintf(cli->s, "Back to %s\n", curr_node->path);
	}
	return 0;
}

int32 root_handle(Client *cli, char *folder, char *args) {
	curr_node = root;
	dprintf(cli->s, "Back to root directory '/'\n");
	return 0;
}

int32 curr_handle(Client *cli, char *folder, char *args) {
	dprintf(cli->s, "%s\n", curr_node->path);
	return 0;
}

int32 exit_handle(Client *cli, char *folder, char *args) {
	keep_running_child = 0;
	return 0;	
}


Callback get_command(int8 *cmd_name) {
	int16 n, arrlen;
	if (sizeof(c_handlers) < 16)
		return 0;
	arrlen = sizeof(c_handlers) / 16;
	for (n = 0; n < arrlen; n++) {
		if (!strcmp((char *)cmd_name, (char *)c_handlers[n].cmd_name)) {
			return c_handlers[n].callback_function;
		}
	}

	return NULL;
}

void child_loop(Client *cli) {
	char buf[256] = {0};
	char cmd[256] = {0}, folder[256] = {0}, args[256] = {0};
	while (keep_running_child) {
		ssize_t n = read(cli->s, buf, 255);
		if (n <= 0) {
			dprintf(cli->s, "400 Read error: %s\n", n < 0 ? strerror(errno) : "connection closed");
			return;
		}
		buf[n] = '\0';

		// Parse command
		char *p = strtok(buf, " \n\r");
		if (!p) {
			dprintf(cli->s, "400 Empty command\n");
			continue;
		}
		strncpy(cmd, p, sizeof(cmd) - 1);

		// Parse folder
		p = strtok(NULL, " \n\r");
		if (p) {
			strncpy(folder, p, sizeof(folder) - 1);
			
			// Parse args
			p = strtok(NULL, "\n\r");
			if (p) {
				strncpy(args, p, sizeof(args) - 1);
			}
		}

		// dprintf(cli->s, "\ncmd: %s\nfolder: %s\nargs: %s\n", cmd, folder, args);
		
		Callback cb = get_command(cmd);
		if (!cb) {
			dprintf(cli->s, "400 Command not found: %s\n", cmd);
			continue;
		}
		cb(cli, folder, args);
	}
}

Client *build_client_struct() {
	Client *client = (Client *)malloc(sizeof(Client));
	if (!client) {
		fprintf(stderr, "build_client_struct() malloc failure\n");
		return NULL;
	}
	return client;
}

int cli_accept_cli(Client *client, int serv_fd) {
	if (!keep_running) return 1;
	char *cli_ip;
	int16 cli_port;

	if (active_connections >= MAX_CONNECTIONS) {
                fprintf(stderr, "Too many connections\n");
                keep_running = 0;
		return 1;
        }

        int cli_fd;
        struct sockaddr_in cli_addr;

        memset(&cli_addr, 0, sizeof(cli_addr));
        socklen_t addrlen = sizeof(cli_addr);

        cli_fd = accept(serv_fd, (struct sockaddr *)&cli_addr, &addrlen);
        if (cli_fd < 0) {
                fprintf(stderr, "cli_accept() failure\n");
                keep_running = 0;
		return 1;
        }
        active_connections++;
	
	cli_port = (int16)htons((int)cli_addr.sin_port);
	cli_ip = inet_ntoa(cli_addr.sin_addr);
	printf("Connection from %s:%d\n", cli_ip, cli_port);

	client->s = cli_fd;
	client->port = cli_port;
	strncpy(client->ip, cli_ip, 15);
	
        return cli_fd;
}

int start_cli_app(int serv_fd) {
	int cli_fd;
	Client *client = build_client_struct();
	while (keep_running) {
		if (!keep_running) break;
		cli_fd = cli_accept_cli(client, serv_fd);
		if (!cli_fd) {
			if (!keep_running) break;
			fprintf(stderr, "start_cli_app() failure\n");
			continue;
		}
		printf("Incoming connection (%d/%d)\n", active_connections, MAX_CONNECTIONS);

		if (!fork()) {
			close(serv_fd);
			dprintf(client->s, "100 - Connected to server\nType 'help' for all available commands\n");
			child_loop(client);
			
			// close(cli_fd);
			// free(client);
			exit(0);
		}
		free(client);
		close(cli_fd);
	}
	return 0;
}

int init_root() {
	root = create_root_node();
	if (!root) {
		fprintf(stderr, "create_root_node() failure\n");
		return 1;
	}
	curr_node = root;
	return 0;
}

int main(int argc, char *argv[]) {
	if (init_root())
		return 1;

	char *str_port;
	int port;
	int serv_fd;
	if (argc < 2) {
		str_port = PORT;
	} else {
		str_port = argv[1];
	}
	port = (int)atoi(str_port);
	serv_fd = start_server(HOST, port);
	start_cli_app(serv_fd);	
	close_server(serv_fd);
	return 0;
}
