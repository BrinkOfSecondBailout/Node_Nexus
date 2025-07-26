/* nexus.c */
#include "database.h"
#include "nexus.h"
#include "myserver.h"
#include "base64.h"
#include "classifier.h"

Node *curr_node = NULL;
static char global_buf[2048];
volatile int keep_running_child = 1;
int active_connections = 0;
ClientList *client_list = NULL;

Command_Handler c_handlers[] = {
	{ (char *)"help", help_handle },
	{ (char *)"register", register_handle },
	{ (char *)"login", login_handle },
	{ (char *)"users", users_handle},
	{ (char *)"logout", logout_handle },
	{ (char *)"tree", tree_handle },
	{ (char *)"newdir", newdir_handle },
	{ (char *)"back", back_handle },
	{ (char *)"root", root_handle },
	{ (char *)"curr", curr_handle },
	{ (char *)"jump", jump_handle },
	{ (char *)"addfile", addfile_handle},
	{ (char *)"open", open_handle},
	{ (char *)"save", save_handle},
	{ (char *)"kill", kill_handle},
	{ (char *)"classify", classify_handle},
	{ (char *)"nuke", nuke_handle},
	{ (char *)"exit", exit_handle }	
};

int32 help_handle(Client *cli, char *unused1, char *unused2) {
	zero(global_buf, sizeof(global_buf));
	size_t used = 0;
	size_t remaining = sizeof(global_buf);
	int written;
	WRITE_GLOBAL_BUF("=== Node Nexus Command Help ===\n\n");
        WRITE_GLOBAL_BUF("General Commands:\n"
                       "-----------------\n"
		       "help                			List all available commands\n"
                       "register <user> <pass>  		Create a new account\n"
                       "  	#Example: register alice password123\n"
                       "login <user> <pass>    			Log in to an account\n"
                       "  	#Example: login alice password123\n"
                       "logout              			Log out of current account\n"
                       "tree                			Display all directories and files\n"
                       "newdir <name>       			Create a new directory\n"
                       "  	#Example: newdir my_folder\n"
                       "back                			Move to parent directory\n"
                       "root                			Move to root directory\n"
                       "curr                			Show current directory\n"
                       "jump <dir_name>     			Navigate to a directory by name\n"
                       "  	#Example: jump my_folder\n"
                       "addfile <dir> <file> <type> <value> 	Add a file to a directory\n"
                       "  	<dir>: 'curr' or directory name\n"
                       "  	<type>: -s (string), -i (int), -b (binary), -f (file path)\n"
                       "  	<value>: File content (max 1MB) or file path for -f\n"
                       "  	#Example: addfile curr diary.txt -s\n"
		       "		  *Enter string when prompted: *\n"
		       "		  I am feeling great today! Carpe diem!\n"
                       "  		  addfile logs friday -i 13\n"
                       "  		  addfile img titan -f ~/downloads/eren.png\n"
                       "open <name>    				Open a folder or file by name\n"
                       "  	#Example: open test.txt\n"
                       "save <file_name>    			Download a binary file\n"
                       "  	#Example: save data.bin\n"
                       "kill -<flag> <name> 			Delete a file or directory\n"
                       "  	<flag>: -d (directory), -f (file)\n"
                       "  	#Example: kill -f test.txt\n"
                       "  		  kill -d images\n"
                       "exit                			Exit the program\n\n");
	WRITE_GLOBAL_BUF("Admin Commands (Admin Only):\n"
                       "----------------------------\n"
                       "users             			List all registered users\n"
		       "classify <filename>			Use AI to gauge sentiment of a text file (beta mode)\n"
		       "	#Example: classify diary.txt\n"
                       "nuke                			Delete all files and directories\n\n");
    	// Send to client
    	int result = dprintf(cli->s, "%s", global_buf);
    	if (result < 0) {
        	fprintf(stderr, "help_handle: dprintf failed: %s\n", strerror(errno));
        	return 1;
   	}
    	return 0;

	buffer_full:
		fprintf(stderr, "help_handle: Buffer overflow prevented\n");
		strncpy(global_buf, "Error: Help text too long\n", sizeof(global_buf));
		global_buf[sizeof(global_buf) - 1] = '\0';
		dprintf(cli->s, "%s\n", global_buf);
		return 1;
}

int32 register_handle(Client *cli, char *username, char *args) {
	if (cli->logged_in) {
		dprintf(cli->s, "Error: Already logged in as %s\n", cli->username);
		return 1;
	}
	if (strlen(username) < 1 || strlen(username) >= MAX_USERNAME_LEN) {
		dprintf(cli->s, "Invalid username, must be 1-%d characters\n", MAX_USERNAME_LEN - 1);
		return 1;	
	}
	if (strlen(args) < 1) {
		dprintf(cli->s, "Missing password\n");
		return 1;
	}
	User *user = create_new_user(username, args);
	if (!user) {
		dprintf(cli->s, "Registration failed: Username may already exist or server error\n");
		return 1;
	}
	cli->logged_in = 1;
	user->logged_in = 1;
	strncpy(cli->username, username, MAX_USERNAME_LEN - 1);
	dprintf(cli->s, "Successfully registered and logged in as user '%s'\n", username);
	return 0;
}

int32 login_handle(Client *cli, char *username, char *args) {
	if (cli->logged_in) {
		dprintf(cli->s, "Error: Already logged in as %s\n", cli->username);
		return 1;
	}
	if (strlen(username) < 1 || strlen(username) >= MAX_USERNAME_LEN) {
		dprintf(cli->s, "Invalid username, must be 1-%d characters\n", MAX_USERNAME_LEN - 1);
		return 1;
	}
	if (strlen(args) < 1) {
		dprintf(cli->s, "Missing password\n");
		return 1;
	}
	int n = verify_user(username, args);
	
	if (n == 0) {
		cli->logged_in = 1;
		mark_user_logged_in(username);
		strncpy(cli->username, username, MAX_USERNAME_LEN - 1);
		dprintf(cli->s, "Successfully logged in as '%s'\n", username);
		return 0;
	} else if (n == 1) {
		dprintf(cli->s, "Login failed: Username '%s' not found\n", username);
		return 1;
	} else if (n == 2) {
		dprintf(cli->s, "Login failed: Incorrect password\n");
		return 1;
	} else if (n == 3) {
		dprintf(cli->s, "Login failed: User '%s' already logged in elsewhere\n", username);
		return 1;
	}
	return 1;
}

int32 users_handle(Client *cli, char *unused1, char *unused2) {
	if (strcmp(cli->username, ADMIN_USERNAME) != 0) {
		dprintf(cli->s, "Not logged in as admin, authorization failed\n");
		return 1;
	}
	if (mem_control->user_count == 0) {
		strncpy(global_buf, "No registered users currently..\n", sizeof(global_buf));
		global_buf[sizeof(global_buf) - 1] = '\0';
	} else {
		zero(global_buf, sizeof(global_buf));
		size_t remaining = sizeof(global_buf);
		size_t used = 0;
		int written;

		for (size_t i = 0; i < mem_control->user_count; i++) {
			User *user = mem_control->users[i];
			if (!user) continue;
			size_t remaining = sizeof(global_buf) - used;
			int written = snprintf(global_buf + used, remaining, "%s: %s\n", user->username, user->logged_in ? "-online" : "offline");
			if (written < 0 || (size_t)written >= remaining) {
				fprintf(stderr, "players_handle: Buffer overflow prevented\n");
				break;
			}
			used += written;
		}
	}
	dprintf(cli->s, "%s\n", global_buf);
	return 0;
}

int32 logout_handle(Client *cli, char *username, char *args) {
	if (cli->logged_in == 1) {
		if (!mark_user_logged_out((const char *)cli->username)) {
			cli->username[0] = '\0';
			cli->logged_in = 0;
			dprintf(cli->s, "Successfully logged out\n");
			return 0;
		} else {
			dprintf(cli->s, "Server error, please try again later\n");
			return 1;
		}
	} else {
		dprintf(cli->s, "Error: Current client isn't logged in\n");
		return 1;
	}
}

int32 tree_handle(Client *cli, char *folder, char *args) {
	print_tree(cli->s, root);
	return 0;
}

int32 newdir_handle(Client *cli, char *folder, char *args) {
	if (!cli->logged_in) {
		dprintf(cli->s, "Please register or log in first to modify database\n");
		return 1;
	}
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
	Node *node = find_node_by_hash(folder);
	if (!node) {
		dprintf(cli->s, "No folder by that name exists\n");
		return 1;
	}
	curr_node = node;
	dprintf(cli->s, "Found and currently in folder '%s'\n", node->path);
	return 0;
}


int32 addfile_handle(Client *cli, char *folder, char *args) {
	if (!cli->logged_in) {
		dprintf(cli->s, "Please register or log in first to modify database\n");
		return 1;
	}
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
		node = find_node_by_hash(folder);
		if (!node) {
			dprintf(cli->s, "Invalid folder name\n");
			return 1;
		}
	}
	char name[256] = {0}, flag[8] = {0};
	Leaf *leaf;
	char *p = strtok(args, " ");
	strncpy(name, p, sizeof(name) - 1);

	p = strtok(NULL, " ");
	strncpy(flag, p, sizeof(flag) - 1);
	
	if (!strcmp(flag, "-s")) {
		pthread_mutex_lock(&mem_control->mutex);
		zero(global_buf, sizeof(global_buf));
		dprintf(cli->s, "Enter string:\n");
		ssize_t n = read(cli->s, global_buf, sizeof(global_buf) - 1);
		if (n <= 0) {
			dprintf(cli->s, "Error reading response: %s\n", n < 0 ? strerror(errno) : "connection closed");
			pthread_mutex_unlock(&mem_control->mutex);
			return 1;
		}
		size_t size = sizeof(global_buf);
		leaf = create_new_leaf_string(node, name, global_buf, size);
	} else {
		pthread_mutex_lock(&mem_control->mutex);
		char *value = (char *)malloc(MAX_FILE_UPLOAD);
		p = strtok(NULL, " ");
		strncpy(value, p, MAX_FILE_UPLOAD - 1);
		if (!strcmp(flag, "-i")) {
			leaf = create_new_leaf_int(node, name, (int32_t)atoi(value));
		} else if (!strcmp(flag, "-b")) {
			size_t decoded_len;
			unsigned char *decoded = base64_decode(value, strlen(value), &decoded_len);
			if (!decoded) {
				dprintf(cli->s, "Base64 decoding failed\n");
				pthread_mutex_unlock(&mem_control->mutex);
				free(value);
				return 1;
			}
			leaf = create_new_leaf_binary(node, name, decoded, decoded_len);
			free(decoded);
		} else if (!strcmp(flag, "-f")) {
			FILE *f = fopen(value, "rb");
			if (!f) {
				dprintf(cli->s, "Cannot open file from designated path %s\n", value);
				pthread_mutex_unlock(&mem_control->mutex);
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
			pthread_mutex_unlock(&mem_control->mutex);
			free(value);
			return 1;
		}
		free(value);
	}
	if (!leaf) {
		dprintf(cli->s, "Unable to add file %s.. make sure new file name is unique.. please try again..\n", name);
		pthread_mutex_unlock(&mem_control->mutex);
		return 1;
	}

	dprintf(cli->s, "Successfully created new file '%s' in folder '%s'\n", name, node->path);
	pthread_mutex_unlock(&mem_control->mutex);
	return 0;	
}

int32 open_handle(Client *cli, char *key, char *args) {
	Leaf *leaf;
	Node *node;
	if (strlen(key) < 1 || strlen(key) >= MAX_KEY_LEN || strstr(key, "/") || strstr(key, "..")) {
		dprintf(cli->s, "Invalid name, must be non-empty < %d chars, no '/' or '..'\n", MAX_KEY_LEN);
		return 1;
	}
	node = find_node_by_hash(key);
	if (node) {
		print_node(cli->s, node);
		return 0;
	}

	leaf = find_leaf_by_hash(key);
	if (!leaf) {
		dprintf(cli->s, "Unable to find folder or file by name '%s'\n", key);
		return 1;
	}
	print_leaf(cli->s, leaf);
	return 0;
}

int32 save_handle(Client *cli, char *key, char *args) {
	Leaf *leaf;
	if (strlen(key) < 1 || strlen(key) >= MAX_KEY_LEN || strstr(key, "/") || strstr(key, "..")) {
		dprintf(cli->s, "Invalid file name, must be non-empty < %d chars, no '/' or '..'\n", MAX_KEY_LEN);
		return 1;
	}
	leaf = find_leaf_by_hash(key);
	if (!leaf || leaf->type != VALUE_BINARY) {
		dprintf(cli->s, "File '%s' not found or not binary\n", key);
		return 1;
	}
	
	size_t encoded_len;
	char *encoded;
	if (leaf->value.binary.compressed) {
		uLongf uncompressed_size = MAX_FILE_UPLOAD;
		unsigned char *uncompressed_data = malloc(uncompressed_size);
		if (!uncompressed_data) {
			dprintf(cli->s, "Memory allocation failed for decompression\n");
			return 1;
		}
		if (uncompress(uncompressed_data, &uncompressed_size, leaf->value.binary.data, leaf->value.binary.size) != Z_OK) {
			dprintf(cli->s, "Decompression failed\n");
			free(uncompressed_data);
			return 1;
		}
		encoded = base64_encode(uncompressed_data, uncompressed_size, &encoded_len);
		free(uncompressed_data);

	} else {
		encoded = base64_encode(leaf->value.binary.data, leaf->value.binary.size, &encoded_len);
	}
	if (!encoded) {
		dprintf(cli->s, "Base64 encoding failed\n");
		return 1;
	}
	if (dprintf(cli->s, "%s\n", encoded) < 0) {
		fprintf(stderr, "save_handle() dprintf failure: %s\n", strerror(errno));
	}
	free(encoded);
	return 0;
}

int32 kill_handle(Client *cli, char *flag, char *name) {
	if (!cli->logged_in) {
		dprintf(cli->s, "Please register or log in first to modify database\n");
		return 1;
	}
	if (strcmp(flag, "-d") && strcmp(flag, "-f")) {
		dprintf(cli->s, "Invalid flag, use -d for directory or -f for file\n");
		return 1;
	}
	if (strlen(name) < 1) {
		dprintf(cli->s, "Invalid name argument, enter directory or file name\n");
		return 1;
	}
	if (!strcmp(flag, "-d")) {
		Node *node = find_node_by_hash(name);
		if (!node) {
			dprintf(cli->s, "Invalid directory, '%s' not found\n", name);
			return 1;
		}
		if (node == root) {
			dprintf(cli->s, "Cannot delete root directory\n");
			return 1;
		}
		char buffer[256] = {0};
		dprintf(cli->s, "This will delete '%s' folder and all its contents, proceed?\n~ Y/N ~\n", name);
		ssize_t n = read(cli->s, buffer, sizeof(buffer) - 1);
		if (n <= 0) {
			dprintf(cli->s, "Error reading response: %s\n", n < 0 ? strerror(errno) : "connection closed");
			return 1;
		}
		buffer[n] = '\0';
		char *newline = strchr(buffer, '\n');
		if (newline) *newline = '\0';
		if (!strcmp(buffer, "Y") || !strcmp(buffer, "y") || !strcmp(buffer, "Yes") || !strcmp(buffer, "yes")) {
			if (delete_node(node)) {
				dprintf(cli->s, "Unable to delete directory '%s'\n", name);
				return 1;
			}
			curr_node = root;
			dprintf(cli->s, "Directory '%s' deleted\n", name);
			return 0;
		} else if (!strcmp(buffer, "N") || !strcmp(buffer, "n") || !strcmp(buffer, "No") || !strcmp(buffer, "no")) {
			dprintf(cli->s, "Understood.. directory '%s' left untouched\n", name);
			return 0;
		} else {
			dprintf(cli->s, "Invalid response, directory '%s' left untouched\n", name);
			return 1;
		}
		

	} else if (!strcmp(flag, "-f")) {
		if (delete_leaf(name)) {
			dprintf(cli->s, "Unable to delete file '%s'\n", name);
			return 1;
		}
		dprintf(cli->s, "File '%s' deleted..\n", name);
		return 0;
	}
	return 1;
}

int32 classify_handle(Client *cli, char *file_name, char *unused) {
	pthread_mutex_lock(&mem_control->mutex);
	Leaf *leaf = find_leaf_by_hash(file_name);
	if (!leaf || leaf->type != VALUE_STRING) {
		fprintf(stderr, "Invalid or not a string file\n");
		pthread_mutex_unlock(&mem_control->mutex);
		return 1;
	}
	SentimentLabel label = classify_text(leaf->value.string);
	pthread_mutex_unlock(&mem_control->mutex);
	
	zero(global_buf, sizeof(global_buf));
	snprintf(global_buf, sizeof(global_buf), "Sentiment: %s\n", label == POSITIVE ? "POSITIVE" : "NEGATIVE");
	dprintf(cli->s, "%s\n", global_buf);
	
	return 0;	
}

int32 nuke_handle(Client *cli, char *folder, char *args) {
	if (!cli->logged_in) {
		dprintf(cli->s, "Please register or log in first to modify database\n");
		return 1;
	}
	if (strcmp(cli->username, ADMIN_USERNAME) != 0) {
		dprintf(cli->s, "Not logged in as admin, authorization failed\n");
		return 1;
	}
	char buffer[256] = {0};
	dprintf(cli->s, "This will delete all files and folders, proceed?\n~ Y/N ~\n");
	ssize_t n = read(cli->s, buffer, sizeof(buffer) - 1);
	if (n <= 0) {
		dprintf(cli->s, "Error reading response: %s\n", n < 0 ? strerror(errno) : "connection closed");
		return 1;
	}
	buffer[n] = '\0';
	char *newline = strchr(buffer, '\n');
	if (newline) *newline = '\0';
	if (!strcmp(buffer, "Y") || !strcmp(buffer, "y") || !strcmp(buffer, "Yes") || !strcmp(buffer, "yes")) {
		reset_database();
		
		root = create_root_node();
		if (!root) {
			fprintf(stderr, "create_root_node() failure\n");
			munmap(mem_control, sizeof(SharedMemControl));
			mem_control = NULL;
			return 1;
		}
		curr_node = root;
		
		dprintf(cli->s, "All files and folders successfully nuked\n");
		return 0;
	} else if (!strcmp(buffer, "N") || !strcmp(buffer, "n") || !strcmp(buffer, "No") || !strcmp(buffer, "no")) {
		dprintf(cli->s, "Understood.. crisis averted\n");
		return 0;
	} else {
		dprintf(cli->s, "Invalid response, nuke command canceled\n");
		return 1;
	}
		

	return 0;
}

int32 exit_handle(Client *cli, char *folder, char *args) {
	dprintf(cli->s, "Bye now!\n");
	keep_running_child = 0;
	cli->logged_in = 0;
	return 0;	
}

void log_all_users_out() {
	for (size_t i = 0; i < client_list->count; i++) {
		logout_handle(client_list->list[i], "", "");		
	}
	return;
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
//	fprintf(stderr, "child_loop: Client %d, root=%p\n", getpid(), (void*)root);
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
	logout_handle(cli, "", "");
}

Client *build_client_struct() {
	Client *client = (Client *)malloc(sizeof(Client));
	if (!client) {
		fprintf(stderr, "build_client_struct() malloc failure\n");
		return NULL;
	}
	client->logged_in = 0;
	client->username[0] = '\0';
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
	
	client_list->list[client_list->count++] = client;

        return cli_fd;
}

int start_cli_app(int serv_fd) {
	int cli_fd;
	Client *client;
	client_list = (ClientList*)malloc(sizeof(ClientList));
	if (!client_list) {
		fprintf(stderr, "Error Clients malloc()\n");
		return 1;
	}
	client_list->count = 0;
	while (keep_running) {
		client = build_client_struct();
		if (!client) continue;
		cli_fd = cli_accept_cli(client, serv_fd);
		if (!cli_fd) {
			free(client);
			fprintf(stderr, "start_cli_app() failure\n");
			continue;
		}
		printf("Incoming connection (%d/%d)\n", active_connections, MAX_CONNECTIONS);

		if (!fork()) {
			close(serv_fd);
			struct pollfd pfd = { .fd = client->s, .events = POLLIN };
			int ret = poll(&pfd, 1, 0);
			if (ret <= 0 || !(pfd.revents & POLLIN)) {
				dprintf(client->s, "Connected to server\nType 'help' for all available commands\n");
			}
			child_loop(client);
			exit(0);
		}
		free(client);
		close(cli_fd);
	}
	log_all_users_out();
	return 0;
}

int init_mem_control() {
	mem_control = mmap(NULL, sizeof(SharedMemControl), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (mem_control == MAP_FAILED) {
		fprintf(stderr, "mmap failed for mem_control: %s\n", strerror(errno));
		return 1;
	}	
	mem_control->shared_mem_pool = NULL;
	mem_control->shared_mem_size = 0;
	mem_control->shared_mem_used = 0;
	mem_control->user_count = 0;
	zero((void *)mem_control->users, sizeof(mem_control->users));
	mem_control->dirty = 0;

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	if (pthread_mutex_init(&mem_control->mutex, &attr) != 0) {
		fprintf(stderr, "Mutex initialization failed: %s\n", strerror(errno));
		munmap(mem_control, sizeof(SharedMemControl));
		return 1;
	}
	pthread_mutexattr_destroy(&attr);
	node_hash_table_init();
	leaf_hash_table_init();
	return 0;
}
int init_root() {
	reset_database();
	root = create_root_node();
	if (!root) {
		fprintf(stderr, "create_root_node() failure\n");
		munmap(mem_control, sizeof(SharedMemControl));
		mem_control = NULL;
		return 1;
	}
	create_admin_user();
	// curr_node = root;
	// fprintf(stderr, "init_root: Root node created at %p, mem_control at %p\n", (void*)root, (void*)mem_control);
	mem_control->dirty = 0;
	return 0;
}
int main(int argc, char *argv[]) {
	if (init_mem_control()) return 1;
	if (init_saved_database()) {
		fprintf(stderr, "Initializing new database\n");
		if (init_root()) return 1;
	}
	curr_node = root;
	atexit(base64_cleanup);
	atexit(cleanup_database);
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
