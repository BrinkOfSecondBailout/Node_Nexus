/* cli.c */
#include "database.h"
#include "cli.h"

static Node *root = NULL;
static Node *curr_node = NULL;

Command_Handler c_handlers[] = {
	{ (char *)"hello", hello_handle },
	{ (char *)"help", help_handle },
	{ (char *)"tree", tree_handle },
	{ (char *)"newdir", newdir_handle },
	
};

int32 hello_handle(Client *cli, char *folder, char *args) {
	dprintf(cli->s, "hello back!\n");
	return 0;
}

int32 help_handle(Client *cli, char *folder, char *args) {
	dprintf(cli->s, "-- 'help' - list all available command apis\n");
	dprintf(cli->s, "-- 'tree' - show all current folders and files\n");
	dprintf(cli->s, "-- 'newdir <name>' - add new directory in current folder\n");
	return 0;
}

int32 tree_handle(Client *cli, char *folder, char *args) {
	print_tree(cli->s, root);
	return 0;
}

int32 newdir_handle(Client *cli, char *folder, char *args) {
	Node *temp = create_new_node(curr_node, folder);
	if (temp) {
		dprintf(cli->s, "Successfully created new directory %s in current folder %s\n", folder, curr_node->path);
		curr_node = temp;
	} else {
		dprintf(cli->s, "Unsuccessful at creating new directory %s in current folder %s.. Please try again..\n", folder, curr_node->path);
	}
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

int init_server(int16 port) {
	struct sockaddr_in serv_addr;
	int serv;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = inet_addr(HOST);
	serv = socket(AF_INET, SOCK_STREAM, 0);
	if (serv < 0) {
		fprintf(stderr, "init_server socket() failure: %s\n", strerror(errno));
		return 0;
	}
	errno = 0;
	if ((bind(serv, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0) {
		fprintf(stderr, "init_server bind() failure: %s\n", strerror(errno));
		return 0;
	}
	errno = 0;
	if ((listen(serv, 20)) < 0) {
		fprintf(stderr, "init_server listen() failure: %s\n", strerror(errno));
		return 0;
	}
	printf("Server listening on %s: %d\n", HOST, port);
	return serv;
}

void child_loop(Client *cli) {
	char buf[256] = {0};
	char cmd[256] = {0}, folder[256] = {0}, args[256] = {0};
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
		return;
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
		return;
	}
	cb(cli, folder, args);

}

void main_loop(int serv) {
	struct sockaddr_in addr;
	int cli;
	int32 len;
	char *cli_ip;
	int16 cli_port;
	Client *client;
	pid_t pid;

	cli = accept(serv, (struct sockaddr *)&addr, (unsigned int*)&len);
	if (cli < 0) {
		fprintf(stderr, "accept() failure: %s\n", strerror(errno));
		return;
	}
	cli_port = (int16)htons((int)addr.sin_port);
	cli_ip = inet_ntoa(addr.sin_addr);
	printf("Connection from %s:%d\n", cli_ip, cli_port);
	client = (Client *)malloc(sizeof(struct s_client));
	if (!client) {
		fprintf(stderr, "malloc() client struct failure\n");
		return;
	}
	client->s = cli;
	client->port = cli_port;
	strncpy(client->ip, cli_ip, 15);
	pid = fork();

	if (pid) {
		free(client);
		return;
	} else {
		dprintf(cli, "100 - Connected to server\n");
		dprintf(cli, "Type 'help' to see all available commands\n");
		bool c_continuation = true;
		while (c_continuation) {
			child_loop(client);
		}
		close(cli);
		free(client);
	}
}

int init_cli(int argc, char *argv[]) {
	char *str_port;
	int16 port;
	int16 size;
	char *p;
	int serv;
	if (argc < 2) {
		str_port = PORT;
	} else {
		str_port = argv[1];
	}
	port = (int16)atoi(str_port);
	serv = init_server(port);
	bool s_continuation = true;
	while (s_continuation)
		main_loop(serv);
	printf("Shutting down server...\n");
	close(serv);
	return 0;
}

int main(int argc, char *argv[]) {
	root = create_root_node();
	if (!root) {
		fprintf(stderr, "create_root_node() failure\n");
		return 1;
	}
	curr_node = root;
	return init_cli(argc, argv);	
}
