/* cli.c */
#include "database.h"
#include "cli.h"
#include "myserver.h"
#include "base64.h"

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
	{ (char *)"jump", jump_handle },
	{ (char *)"addfile", addfile_handle},
	{ (char *)"open", open_handle},
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
	"-- 'jump <dir_name>' - find and navigate to directory by name\n"
	"-- 'addfile <dir> <filename> -<filetype(s)(i)(b)(f)> <filevalue>' - \nadd a new file to a directory, use 'curr' for current directory\nfor type, use flag -s for string, -i for integer, -b for binary, -f for file\nfollowed by the file value *maximum 64KB* (or if -f, file path)\n" 
	"-- 'open <file_name>' - find and open file by name\n"
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
		dprintf(cli->s, "Added new directory '%s' in current folder '%s'\n", folder, curr_node->path);
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

int32 jump_handle(Client *cli, char *folder, char *args) {
	if ((strlen(folder) < 1)) {
		dprintf(cli->s, "Missing folder name\n");
		return 1;	
	}
	Node *node = find_node_linear(root, folder);
	if (!node) {
		dprintf(cli->s, "No folder by that name exists\n");
		return 1;
	}
	curr_node = node;
	dprintf(cli->s, "Found and currently in folder '%s'\n", curr_node->path);
	return 0;
}


int32 addfile_handle(Client *cli, char *folder, char *args) {
	if ((strlen(folder) == 0)) {
		dprintf(cli->s, "Missing folder name, use 'curr' for current directory\n");
		return 1;
	}
	if ((strlen(args) < 3)) {
		dprintf(cli->s, "Missing arguments, please include filename, type flag, and file value\n");
		return 1;
	}
	Node *node;
	if (!strcmp(folder, "curr")) {
		node = curr_node;
	} else {
		node = find_node_linear(root, folder);
		if (!node) dprintf(cli->s, "Invalid folder name\n");
	}
	char name[256] = {0}, flag[8] = {0};
	char *value = (char *)malloc(MAX_FILE_UPLOAD);
	Leaf *leaf;

	char *p = strtok(args, " ");
	strncpy(name, p, sizeof(name) - 1);

	p = strtok(NULL, " ");
	strncpy(flag, p, sizeof(flag) - 1);
	p = strtok(NULL, " ");
	strncpy(value, p, MAX_FILE_UPLOAD - 1);
	if (!strcmp(flag, "-s")) {
		leaf = create_new_leaf_string(node, name, value, sizeof(value));		
	} else if (!strcmp(flag, "-i")) {
		leaf = create_new_leaf_int(node, name, (int32_t)atoi(value));
	} else if (!strcmp(flag, "-b")) {
		size_t decoded_len;
		unsigned char *decoded = base64_decode(value, strlen(value), &decoded_len);
		if (!decoded) {
			dprintf(cli->s, "Base64 decoding failed\n");
			return 1;
		}
		leaf = create_new_leaf_binary(node, name, decoded, decoded_len);
		free(decoded);
	} else if (!strcmp(flag, "-f")) {
		FILE *f = fopen(value, "rb");
		if (!f) {
			dprintf(cli->s, "Cannot open file from designated path %s\n", value);
			return 1;
		}
		fseek(f, 0, SEEK_END);
		size_t size = ftell(f);
		fseek(f, 0, SEEK_SET);
		char *data = malloc(size);
		fread(data, 1, size, f);
		fclose(f);
		
		leaf = create_new_leaf_binary(node, name, data, size);
		free(data);
	} else {
		dprintf(cli->s, "Invalid flag, please use -s , -i , -b for string/integer/binary\n");
		return 1;
	}
	if (!leaf) {
		dprintf(cli->s, "Unable to add file %s.. please try again..\n", name);
		return 1;
	}
	dprintf(cli->s, "Successfully created new file '%s' in folder '%s'\n", name, node->path);
	free(value);
	return 0;	
}

int32 open_handle(Client *cli, char *folder, char *args) {
	Leaf *leaf;
	if ((strlen(folder) < 1)) {
		dprintf(cli->s, "Please provide a file name to open\n");
		return 1;
	}
	leaf = find_leaf_by_hash(folder);
	if (!leaf) {
		dprintf(cli->s, "Unable to find file by name '%s'\n", folder);
		return 1;
	}
	dprintf(cli->s, "\nSuccessfully found file '%s'\n", folder);
	print_leaf(cli->s, leaf);	
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

void zero_multiple(void *buf,...) {
	va_list args;
	va_start(args, buf);
	void *ptr;
	while ((ptr = va_arg(args, void *)) != NULL) {
		zero(ptr, sizeof(*ptr));
	}
	va_end(args);
}

void child_loop(Client *cli) {
	char buf[256] = {0};
	char cmd[256] = {0}, folder[256] = {0}, args[256] = {0};
	while (keep_running_child) {
		zero_multiple(buf, cmd, folder, args, NULL);
		ssize_t n = read(cli->s, buf, 255);
		if (n <= 0) {
			dprintf(cli->s, "400 Read error: %s\n", n < 0 ? strerror(errno) : "connection closed");
			break;
		}
		buf[n] = '\0';
		if (strcmp(buf, "quit\n") == 0) break;

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
		
		Callback cb = get_command((int8 *)cmd);
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
