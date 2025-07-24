/* database.c */

#include "database.h"
#include "base64.h"

Node *root = NULL;
SharedMemControl *mem_control = NULL;

void *alloc_shared(size_t size) {
	if (!mem_control->shared_mem_pool) {
		mem_control->shared_mem_size = SHARED_MEM_INITIAL_SIZE;
		mem_control->shared_mem_pool = mmap(NULL, mem_control->shared_mem_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (mem_control->shared_mem_pool == MAP_FAILED) {
			fprintf(stderr, "mmap failed: %s\n", strerror(errno));
			return NULL;
		}
		mem_control->shared_mem_used = 0;
	}
	if (mem_control->shared_mem_used + size > mem_control->shared_mem_size) {
		fprintf(stderr, "Shared memory pool exhausted\n");
		return NULL;
	}
	void *ptr = (char *)mem_control->shared_mem_pool + mem_control->shared_mem_used;
	mem_control->shared_mem_used += size;
//	fprintf(stderr, "PID: %d: Mempool size: %ld\n", getpid(), mem_control->shared_mem_used);
	return ptr;
}

void zero(void *buf, size_t size) {
	memset(buf, 0, size);
}

void node_hash_table_init() {
	zero((void*)mem_control->node_hash_table, (size_t)sizeof(mem_control->node_hash_table));
	mem_control->node_count = 0;
}

void leaf_hash_table_init() {
	zero((void *)mem_control->leaf_hash_table, (size_t)sizeof(mem_control->leaf_hash_table));
	mem_control->leaf_count = 0;
}

char *indent(int8 n) {
	static char buf[512];
	if (n < 1 || n >= 128) {
		buf[0] = '\0';
		return buf;
	}
	int i;
	for (i = 0; i < n; i++) {
		memcpy(buf + i * 4, i == 0 ? "|---" : "----", 4);
	}
	buf[n * 4] = '\0';
	return buf;
}

int write_str(int fd, const char *str) {
	size_t len = strlen(str);
	if (len == 0) return 0;
	if (write(fd, str, len) == -1) {
		fprintf(stderr, "write_str() failure\n");
		return -1;
	}
	return 0;
}
static void print_original_node(Node *n, int8 indentation, int fd) {
	char buf[512];
	if (!n) return;
	snprintf(buf, sizeof(buf), "%s%s\n", indent(indentation), n->path);
	if (write_str(fd, buf) < 0) {
		fprintf(stderr, "print_original_node() failure\n");	
	}
	return;
}

static Leaf *find_first_leaf(Node *parent) {
	Leaf *l;
	CHECK_NULL(parent, "find_first_leaf() failure, invalid parent node");
	if (!parent->leaf)
		return NULL;
	l = parent->leaf;

	if (!l) {
		fprintf(stderr, "find_first_leaf() failure, invalid leaf found\n");
		return NULL;
	}
	return l;
}

static Leaf *find_last_leaf_linear(Node *parent) {
	Leaf *l;
	CHECK_NULL(parent, "find_last_leaf() failure, invalid parent node");
	
	if (!parent->leaf)
		return NULL;
	for (l = parent->leaf; l->sibling; l = l->sibling);
	if (!l) {
		fprintf(stderr, "find_last_leaf() failure, invalid leaf found\n");
		return NULL;
	}
	return l;
}

Leaf *find_leaf_by_hash(char *key) {
	printf("Searching for leaf: %s\n", key);
	uint32_t index = HASH_KEY(key, LEAF_HASH_TABLE_SIZE);
	LeafHashEntry *entry = mem_control->leaf_hash_table[index];
	printf("Entry %p\n", entry);
	while (entry) {
		if (!strcmp(entry->key, key)) {
			return entry->leaf;
		}
		entry = entry->next;
	}
	return NULL;
}

Leaf *find_leaf_linear(Node *root, char *key) {
	Node *n;
	Leaf *l;
	for (n = root; n; n = n->child) {
		l = find_first_leaf(n);
		while (l) {
			if (!strcmp(l->key, key)) {
				return l;
			}
			l = l->sibling;
		}
		while (n->sibling) {
			n = n->sibling;
			l = find_first_leaf(n);
			while (l) {
				if (!strcmp(l->key, key)) {
					return l;
				}
				l = l->sibling;
			}
		}
	}
	return NULL;
}

Node *find_node_and_siblings(Node *node, char *path) {
	while (node) {
		if (strstr(node->path, path)) {
			return node;
		}
		node = node->sibling;
	}
	return NULL;
}

Node *find_node_by_hash(char *key) {
	uint32_t index = HASH_KEY(key, NODE_HASH_TABLE_SIZE);
	NodeHashEntry *entry = mem_control->node_hash_table[index];
	while (entry) {
		printf("Searching for node: %s\n", key);
		if (!strcmp(entry->key, key)) {
			return entry->node;
		}
		entry = entry->next;
	}
	return NULL;
}

Node *find_node_linear(Node *root, char *path) {
	Node *node, *temp;
	for (node = root; node; node = node->child) {
		if (strstr(node->path, path)) {
			return node;
		}
		temp = find_node_and_siblings(node, path);
		if (temp) return temp;
	}
	return NULL;
}

static Node *find_first_child_node(Node *parent) {
	Node *n;
	CHECK_NULL(parent, "find_first_child_node() failure, invalid parent node");
	n = parent->child;
	CHECK_NULL(parent, "find_first_child_node() failure, no node found");
	return n;
}

static Node *find_last_child_node_linear(Node *parent) {
	Node *n;
	CHECK_NULL(parent, "find_last_child_node() failure, invalid parent node");
	n = parent->child;
	if (!n) {
		return NULL;	
	}
	while (n->sibling) {
		n = n->sibling;
	}
	if (!n) {
		return NULL;
	}
	return n;
}

static int is_node_in_stack(Node *node, Node **stack, int stack_count) {
	int i;
	for (i = 0; i < stack_count && i < 256; i++) {

		if (stack[i] == node) {
			return 1;
		}
	}
	return 0;
}


static void print_leaves_of_node(Node *n, int8 indentation, int fd) {
	char buf[512];
	Leaf *l, *first;
	if (!n) return;
	if (n->leaf) {
		first = find_first_leaf(n);
		for (l = first; l; l = l->sibling) {
			switch (l->type) {
				case VALUE_STRING:
					snprintf(buf, sizeof(buf), "%s%s/..%s -> '%s'\n",
						indent(indentation), (!strcmp(n->path, "/")) ? "" : n->path, l->key, l->value.string);
					break;
				case VALUE_INT:
					snprintf(buf, sizeof(buf), "%s%s/..%s -> %d\n",
						indent(indentation), (!strcmp(n->path, "/")) ? "" : n->path, l->key, l->value.integer);
					break;
				case VALUE_DOUBLE:
					snprintf(buf, sizeof(buf), "%s%s/..%s -> %.2f\n",
						indent(indentation), (!strcmp(n->path, "/")) ? "" : n->path, l->key, l->value.floating);
					break;
				case VALUE_BINARY:
					snprintf(buf, sizeof(buf), "%s%s/..%s -> [binary data, size = %ld]\n",
						indent(indentation), (!strcmp(n->path, "/")) ? "" : n->path, l->key, l->value.binary.size);
					break;
			}
			if (write_str(fd, buf) < 0) {
				fprintf(stderr, "print_leaves_of_node() failure\n");
			}
		}
	}
}

static void print_node_and_leaves(Node *n, int8 indentation, int fd) {
	if (!n) return;

	print_original_node(n, indentation, fd);
	
	print_leaves_of_node(n, indentation, fd);

}

void print_tree(int fd, Node *root) {
	if (!root) {
		fprintf(stderr, "print_tree() failure, invalid root\n");
		return;
	}
	Node *stack[256];
	Node *used_stack[256];
	int used_stack_count = 0;

	int stack_top = -1;
	int8 indentations[256];
	
	stack[++stack_top] = root;

	used_stack[used_stack_count++] = root;

	indentations[stack_top] = 0;

	while (stack_top >= 0) {
		Node *n = stack[stack_top];
		int8 indentation = indentations[stack_top--];
		print_node_and_leaves(n, indentation, fd);

		Node *sibling = n->sibling;
		while (sibling) {
			if (!is_node_in_stack(sibling, used_stack, used_stack_count)) {
				stack[++stack_top] = sibling;
				used_stack[used_stack_count++] = sibling;
				indentations[stack_top] = indentation;
			}
			sibling = sibling->sibling;
		}

		if (n->child) {
			if (!is_node_in_stack(n->child, used_stack, used_stack_count)) {
				stack[++stack_top] = n->child;
				used_stack[used_stack_count++] = n->child;
			}
			indentations[stack_top] = indentation + 1;
		}
	}
	write_str(fd, "\n");
	
}

static void add_node_to_table(Node *node) {
	uint32_t index = HASH_KEY(node->key, NODE_HASH_TABLE_SIZE);
	NodeHashEntry *entry = alloc_shared(sizeof(NodeHashEntry));
	if (!entry) {
		fprintf(stderr, "add_node_to_table() malloc failure\n");
		return;
	}
	zero((void*)entry, (size_t)sizeof(NodeHashEntry));
	strncpy(entry->key, node->key, MAX_KEY_LEN);
	entry->node = node;
	entry->next = mem_control->node_hash_table[index];
	mem_control->node_hash_table[index] = entry;
	mem_control->node_count++;
	// printf("New node: %s\n", node->key);
	// printf("Node count: %ld\n", mem_control->node_count);
	return;
}

Node *create_root_node() {
	Node *root = alloc_shared(sizeof(Node));
	CHECK_NULL(root, "Failed to allocate root");
	zero((void *)root, sizeof(Node));
	root->parent = NULL;
	root->sibling = NULL;
	root->child = NULL;
	root->leaf = NULL;
	strncpy(root->key, "root", MAX_KEY_LEN - 1);
	strncpy(root->path, "/", MAX_PATH_LEN - 1);
	root->path[MAX_PATH_LEN - 1] = '\0';
	add_node_to_table(root);
	return root;
}

Node *create_new_node(Node *parent, char *name) {
	pthread_mutex_lock(&mem_control->mutex);
	Node *new, *last;
	size_t size;
	CHECK_NULL(parent, "create_new_node() failure, invalid parent node");
	size = sizeof(Node);
	new = alloc_shared(size);
	CHECK_NULL(new, "create_new_node() malloc failure");
	zero((void *)new, size);
	char temp_path[MAX_PATH_LEN];
	size_t parent_len = strlen(parent->path);
	size_t new_len = strlen(name);	
	if (parent_len + new_len + 2 >= MAX_PATH_LEN) {
		fprintf(stderr, "Path too long in new node\n");
		pthread_mutex_unlock(&mem_control->mutex);
		return NULL;
	}

	last = find_last_child_node(parent);
	if (!last) {
		parent->child = new;
	} else {
		last->sibling = new;
	}

	new->parent = parent;
	new->sibling = NULL;
	new->child = NULL;
	new->leaf = NULL;
	
	CONCAT_PATH(temp_path, parent->path, name, MAX_PATH_LEN); 
	strncpy(new->key, name, MAX_KEY_LEN - 1);
	strncpy(new->path, temp_path, MAX_PATH_LEN - 1);
	printf("New node path: %s\n", new->path);	
	add_node_to_table(new);
	pthread_mutex_unlock(&mem_control->mutex);
	return new;
}

static void add_leaf_to_table(Leaf *leaf) {	
	uint32_t index = HASH_KEY(leaf->key, LEAF_HASH_TABLE_SIZE);
	LeafHashEntry *entry = alloc_shared(sizeof(LeafHashEntry));
	if (!entry) {
		fprintf(stderr, "add_leaf_to_table() malloc failure\n");
		return;
	}
	zero((void *)entry, (size_t)sizeof(LeafHashEntry));
	strncpy(entry->key, leaf->key, MAX_KEY_LEN);
	entry->leaf = leaf;
	entry->next = mem_control->leaf_hash_table[index];
	mem_control->leaf_hash_table[index] = entry;
	mem_control->leaf_count++;
	printf("Leaf count: %ld\n", mem_control->leaf_count);
	return;
}

static Leaf *create_new_leaf_prototype(Node *parent, char *key) {
	Leaf *check, *last, *new;
	size_t size;
	CHECK_NULL(parent, "create_new_leaf() failure, invalid parent node");
	
	check = find_leaf_by_hash(key);
	if (check) {
		fprintf(stderr, "Name already exits\n");
		return NULL;
	}

	last = find_last_leaf(parent);
	size = sizeof(Leaf);
	new = alloc_shared(size);
	CHECK_NULL(new, "create_leaf_prototype() malloc failure\n");

	zero((void *)new, size);
	if (last) {
		last->sibling = new;
	} else {
		parent->leaf = new;
	}
	new->parent = parent;
	new->sibling = NULL;
	strncpy(new->key, key, MAX_KEY_LEN - 1);
	return new;
}


Leaf *create_new_leaf_string(Node *parent, char *key, char *value, size_t count) {
	Leaf *new;
	new = create_new_leaf_prototype(parent, key);	
	if (!new) {
		return NULL;
	}

	new->type = VALUE_STRING;
	new->value.string = alloc_shared(count);
	CHECK_NULL(new->value.string, "create_new_leaf() malloc failed\n");
	strncpy(new->value.string, value, count);
	
	add_leaf_to_table(new);
	return new;
}

Leaf *create_new_leaf_int(Node *parent, char *key, int32_t value) {
	Leaf *new;
	new = create_new_leaf_prototype(parent, key);
	if (!new) {
		return NULL;
	}
	
	new->type = VALUE_INT;
	new->value.integer = value;
	add_leaf_to_table(new);
	return new;
}

Leaf *create_new_leaf_double(Node *parent, char *key, double value) {
	Leaf *new;
	new = create_new_leaf_prototype(parent, key);
	if (!new) {
		return NULL;
	}

	new->type = VALUE_DOUBLE;
	new->value.floating = value;
	add_leaf_to_table(new);
	return new;
}

Leaf *create_new_leaf_binary(Node *parent, char *key, void *data, size_t size) {
	Leaf *new;
	new = create_new_leaf_prototype(parent, key);
	if (!new) {
		return NULL;
	}
	new->type = VALUE_BINARY;
	uLongf compressed_size = compressBound(size);
	void *compressed_data = alloc_shared(compressed_size);
	CHECK_NULL(compressed_data, "create_leaf_binary() alloc_shared failure\n");
	if (compress(compressed_data, &compressed_size, data, size) != Z_OK) {
		fprintf(stderr, "create_leaf_binary() compression failed\n");
		return NULL;
	}
	fprintf(stderr, "create_leaf_binary: key=%s, original size=%zu bytes, compressed size=%zu bytes\n", key, size, compressed_size);

	new->value.binary.data = compressed_data;
	new->value.binary.size = compressed_size;
	new->value.binary.compressed = 1;
	add_leaf_to_table(new);
	return new;
}

User *create_new_user(const char *username, const char *password) {
	pthread_mutex_lock(&mem_control->mutex);
	if (strlen(username) >= MAX_USERNAME_LEN || strlen(username) < 1) {
		fprintf(stderr, "create_new_user: Invalid username length\n");
		pthread_mutex_unlock(&mem_control->mutex);
		return NULL;
	}
	if (mem_control->user_count >= MAX_USERS) {
		fprintf(stderr, "create_new_user: User limit reached\n");
		pthread_mutex_unlock(&mem_control->mutex);
		return NULL;
	}
	for (size_t i = 0; i < mem_control->user_count; i++) {
		if (strcmp(mem_control->users[i]->username, username) == 0) {
			fprintf(stderr, "create_new_user: Username already exists\n");
			pthread_mutex_unlock(&mem_control->mutex);
			return NULL;
		}
	}

	User *user = alloc_shared(sizeof(User));
	if (!user) {
		fprintf(stderr, "create_new_user: Malloc failed\n");
		pthread_mutex_unlock(&mem_control->mutex);
		return NULL;
	}
	zero(user, sizeof(User));
	strncpy(user->username, username, MAX_USERNAME_LEN - 1);
	SHA256((const unsigned char *)password, strlen(password), user->password_hash);
	mem_control->users[mem_control->user_count++] = user;
	fprintf(stderr, "create_new_user: Created User %s\n", username);
	pthread_mutex_unlock(&mem_control->mutex);
	return user;
}

User *find_user(const char *username) {
	for (size_t i = 0; i < mem_control->user_count; i++) {
		if (strcmp(mem_control->users[i]->username, username) == 0) {
			return mem_control->users[i];
		}
	}
	fprintf(stderr, "User not found\n");
	return NULL;
}

int mark_user_logged_in(const char *username) {
	User *user = find_user(username);
	if (!user) {
		fprintf(stderr, "Invalid user\n");
		return 1;
	}
	user->logged_in = 1;
	return 0;
}

int mark_user_logged_out(const char *username) {
	User *user = find_user(username);
	if (!user) {
		fprintf(stderr, "Invalid user\n");
		return 1;
	}
	user->logged_in = 0;
	return 0;
}

int verify_user(const char *username, const char *password) {
	User *user = find_user(username);
	if (!user) {
		fprintf(stderr, "verify_user: User %s not found\n", username);
		return 1;
	}
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((const unsigned char *)password, strlen(password), hash);
	if (memcmp(hash, user->password_hash, SHA256_DIGEST_LENGTH) == 0) {
		if (user->logged_in) {
			fprintf(stderr, "User %s already logged in\n", username);
			return 3;
		}
		fprintf(stderr, "User %s found and verified\n", username);
		return 0;
	}
	fprintf(stderr, "Verify_user: Password mismatch\n");
	return 2;
}



void print_node(Node *n) {
	if (!n) {
		printf("Invalid directory\n");
	} else {
		printf("**FOLDER**\n");
		printf("Folder path: %s\n", n->path);
		if (n->child)
			printf("Folder has files inside\n");
		else
			printf("Folder is empty\n");
		printf("\n");
	}
	return;
}

void print_leaf(int cli_fd, Leaf *l) {
	char header[512];
	char body[MAX_BASE64_LEN];
	if (!l) {
		dprintf(cli_fd, "Invalid file\n");
		fprintf(stderr, "Invalid file\n");
		return;
	}
	snprintf(header, sizeof(header), "**FILE**\n%s\n%s\n", l->parent->path, l->key);
	switch(l->type) {
		case VALUE_STRING:
			snprintf(body, sizeof(body), "'%s'\n", l->value.string);
			break;
		case VALUE_INT:
			snprintf(body, sizeof(body), "%d\n", l->value.integer);
			break;
		case VALUE_DOUBLE:
			snprintf(body, sizeof(body), "%.2f\n", l->value.floating);
			break;
		case VALUE_BINARY:
			if (l->value.binary.compressed) {
				// Decompress for display
				uLongf uncompressed_size = MAX_BASE64_LEN * 3 / 4;
				unsigned char *uncompressed_data = malloc(uncompressed_size);
				if (!uncompressed_data) {
					snprintf(body, sizeof(body), "Memory allocation failed for decompression\n");
				} else if (uncompress(uncompressed_data, &uncompressed_size, l->value.binary.data, l->value.binary.size) != Z_OK) {
					snprintf(body, sizeof(body), "Decompression failed\n");
					free(uncompressed_data);	
				} else {
					size_t encoded_len;
					char *encoded = base64_encode(uncompressed_data, uncompressed_size, &encoded_len);
					if (!encoded) {
						snprintf(body, sizeof(body), "Base64 encoding failed\n");
					} else {
						snprintf(body, sizeof(body), "[binary data, size=%ld, base64=%s]\n", uncompressed_size, encoded);
						free(encoded);
					}
					free(uncompressed_data);
				}
			} else {	
				if (l->value.binary.size > (sizeof(body) - 1) / 4 * 3) {
					snprintf(body, sizeof(body), "Binary data too large to display (%ld bytes)\n", l->value.binary.size);
				} else {
					size_t encoded_len;
					char *encoded = base64_encode(l->value.binary.data, l->value.binary.size, &encoded_len);
					if (!encoded) {
						snprintf(body, sizeof(body), "Base64 encoding failed\n");
					} else {
						snprintf(body, sizeof(body), "[binary data, size=%ld, base64=%s]\n", l->value.binary.size, encoded);
						free(encoded);
					}
				}
			}

			break;
		default:
			snprintf(body, sizeof(body), "Unknown file type\n");
			break;
	}
	if (dprintf(cli_fd, "%s%s", header, body) < 0) {
		fprintf(stderr, "print_leaf() dprintf failure: %s\n", strerror(errno));	
	};
	return;
}

int delete_node(Node *node) {
	pthread_mutex_lock(&mem_control->mutex);
	Node *parent, *first;
	Node *prev = NULL;
       	parent = node->parent;
	first = find_first_child_node(parent);
	while (first) {
		if (first == node) {
			if (first->sibling) {
				if (prev) {
					prev->sibling = first->sibling;
				} else {
					parent->child = first->sibling;
				}
			} else {
				if (prev) {
					prev->sibling = NULL;
				} else {
					parent->child = NULL;
				}
			}
			free_node(first);
			pthread_mutex_unlock(&mem_control->mutex);
			return 0;
		}
		prev = first;
		first = first->sibling;
	}
	fprintf(stderr, "delete_node() failure, unable to unlink node\n");	
	pthread_mutex_unlock(&mem_control->mutex);
	return 1;
}

int delete_leaf(char *name) {
	pthread_mutex_lock(&mem_control->mutex);
	Leaf *leaf, *first;
	Leaf *prev = NULL;
	Node *parent;
	leaf = find_leaf_by_hash(name);
	if (!leaf) {
		fprintf(stderr, "delete_leaf() failure, no such file\n");
		pthread_mutex_unlock(&mem_control->mutex);
		return 1;
	}
	parent = leaf->parent;
	first = find_first_leaf(parent);
	while (first) {
		if (first == leaf) {
			if (first->sibling) {
				if (prev) {
					prev->sibling = first->sibling;
				} else {
					parent->leaf = first->sibling;
				}
			} else {
				if (prev) {
					prev->sibling = NULL;
				} else {
					parent->leaf = NULL;
				}
			}
			free_leaf(first);
			pthread_mutex_unlock(&mem_control->mutex);
			return 0;
		} else {
			prev = first;
			first = first->sibling;
		}
	}
	fprintf(stderr, "delete_leaf() failure, unable to unlink leaf\n");	
	pthread_mutex_unlock(&mem_control->mutex);
	return 1;
}

void reset_database() {
	pthread_mutex_lock(&mem_control->mutex);
	if (root) {
		free_node(root);
		root = NULL;
	}
	node_hash_table_init();
	leaf_hash_table_init();
	mem_control->shared_mem_used = 0;
	pthread_mutex_unlock(&mem_control->mutex);
}

void free_leaf(Leaf *leaf) {
	if (!leaf) return;
	uint32_t index = HASH_KEY(leaf->key, LEAF_HASH_TABLE_SIZE);
	LeafHashEntry *entry = mem_control->leaf_hash_table[index];
	LeafHashEntry *prev = NULL;
	while (entry) {
		if (entry->leaf == leaf) {
			if (prev) {
				prev->next = entry->next;
			} else {
				mem_control->leaf_hash_table[index] = entry->next;
			}
			//free(entry);
			mem_control->leaf_count--;
			break;
		}
		prev = entry;
		entry = entry->next;
	}
}

void free_node(Node *node) {
	if (!node) return;
	uint32_t index = HASH_KEY(node->key, NODE_HASH_TABLE_SIZE);
	NodeHashEntry *entry = mem_control->node_hash_table[index];
	NodeHashEntry *prev = NULL;
	while (entry) {
		if (entry->node == node) {
			if (prev) {
				prev->next = entry->next;
			} else {
				mem_control->node_hash_table[index] = entry->next;
			}
			mem_control->node_count--;
			break;
		}
		prev = entry;
		entry = entry->next;
	}
	Leaf *leaf = node->leaf;
	while (leaf) {
		Leaf *next = leaf->sibling;
		free_leaf(leaf);
		leaf = next;
	}
	if (node->child) {
		free_node(node->child);
	}
}

int serialize_node(FILE *f, Node *node) {
	uint32_t null_marker = 0xFFFFFFFF;
	if (!node) {
		fwrite(&null_marker, sizeof(uint32_t), 1, f);
		return 0;
	}
	uint32_t child_count = 0, sibling_count = 0, leaf_count = 0;
	Node *n;
	for (n = node->child; n; n = n->sibling) child_count++;
	for (n = node->sibling; n; n = n->sibling) sibling_count++;
	Leaf *l;
	for (l = node->leaf; l; l = l->sibling) leaf_count++;
	
	if (fwrite(&child_count, sizeof(uint32_t), 1, f) != 1 
		|| fwrite(&sibling_count, sizeof(uint32_t), 1, f) != 1
		|| fwrite(&leaf_count, sizeof(uint32_t), 1, f) != 1) {
		fprintf(stderr, "serialize_node() fwrite counts failed\n");
		return 1;
	}

	size_t path_len = strlen(node->path) + 1;
	size_t node_key_len = strlen(node->key) + 1;
	if (fwrite(&path_len, sizeof(size_t), 1, f) != 1
		|| fwrite(node->path, path_len, 1, f) != 1
		|| fwrite(&node_key_len, sizeof(size_t), 1, f) != 1
		|| fwrite(node->key, node_key_len, 1, f) != 1) {
		fprintf(stderr, "serialize_node() fwrite path and key failed\n");
		return 1;
	}

	for (l = node->leaf; l; l = l->sibling) {
		size_t leaf_key_len = strlen(l->key) + 1;
		if (fwrite(&leaf_key_len, sizeof(size_t), 1, f) != 1
			|| fwrite(l->key, leaf_key_len, 1, f) != 1
			|| fwrite(&l->type, sizeof(ValueType), 1, f) != 1) {
			fprintf(stderr, "serialize_node() fwrite leaf failed\n");
			return 1;
		}
		switch (l->type) {
			case VALUE_STRING:
				size_t value_len = strlen(l->value.string) + 1;
				if (fwrite(&value_len, sizeof(size_t), 1, f) != 1
					|| fwrite(l->value.string, value_len, 1, f) != 1) {
					fprintf(stderr, "serialize_node() fwrite string failed\n");
					return 1;
				}
				break;
			case VALUE_INT:
				if (fwrite(&l->value.integer, sizeof(int32_t), 1, f) != 1) {
					fprintf(stderr, "serialize_node() fwrite int failed\n");
					return 1;
				}
				break;
			case VALUE_DOUBLE:
				if (fwrite(&l->value.floating, sizeof(double), 1, f) != 1) {
					fprintf(stderr, "serialize_node() fwrite double failed\n");
					return 1;
				}
				break;
			case VALUE_BINARY:
				if (fwrite(&l->value.binary.size, sizeof(size_t), 1, f) != 1
					|| fwrite(l->value.binary.data, l->value.binary.size, 1, f) != 1
					|| fwrite(&l->value.binary.compressed, sizeof(int), 1, f) != 1) {
					fprintf(stderr, "serialize_node() fwrite binary failed\n");
					return 1;
				}
				break;
		}
	}

	if (serialize_node(f, node->child) || serialize_node(f, node->sibling)) {
		return 1;
	}
	return 0;
}


int serialize_all_nodes(FILE *f) {
	serialize_node(f, root);
	return 0;	
}
/*
int serialize_number_of_nodes(FILE *f) {
	if (fwrite(&mem_control->node_count, sizeof(size_t), 1, f) != 1) {
		fprintf(stderr, "Error serializing number of nodes\n");
		return 1;
	}
	fprintf(stderr, "Serialized success: number of nodes %ld\n", mem_control->node_count);
	return 0;
} */

void serialize_database(const char *filename) {
	//if (mem_control->user_count == 0 && mem_control->node_count <= 1 && mem_control->leaf_count == 0) return;
	pthread_mutex_lock(&mem_control->mutex);
	FILE *f = fopen(filename, "wb");
	if (!f) {
		fprintf(stderr, "save_database() fopen failure: %s\n", strerror(errno));
		pthread_mutex_unlock(&mem_control->mutex);
		return;
	}
	if (fwrite(&mem_control->user_count, sizeof(size_t), 1, f) != 1) {
		fprintf(stderr, "save_database() fwrite failure\n");
		pthread_mutex_unlock(&mem_control->mutex);
		return;
	}
	for (size_t i = 0; i < mem_control->user_count; i++) {
		if (fwrite(mem_control->users[i], sizeof(User), 1, f) != 1) {
			fprintf(stderr, "save_database() fwrite failure\n");
			pthread_mutex_unlock(&mem_control->mutex);
			return;
		}
	}
	if (mem_control->node_count > 1 || mem_control->leaf_count > 0) {
		fprintf(stderr, "Database has folders or files, saving...\n");
		/*if (serialize_number_of_nodes(f)) {
			pthread_mutex_unlock(&mem_control->mutex);
			return;
		} */
		if (serialize_all_nodes(f)) {
			fprintf(stderr, "serialize_database() serialize_all_nodes failed\n");
			fclose(f);
			pthread_mutex_unlock(&mem_control->mutex);
			return;
		}
	} else {
		fprintf(stderr, "Database has no folders or files, nothing to save.\n"); 
	}
	fclose(f);
	pthread_mutex_unlock(&mem_control->mutex);
	return;
}

Node *deserialize_node(FILE *f, Node *parent) {
	uint32_t child_count, sibling_count, leaf_count;
	if (fread(&child_count, sizeof(uint32_t), 1, f) != 1) {
		if (feof(f)) return NULL;
		fprintf(stderr, "deserialize_node() fread child_count failed\n");
		return NULL;
	}
	if (child_count == 0xFFFFFFFF) return NULL;
	if (fread(&sibling_count, sizeof(uint32_t), 1, f) != 1 
			|| fread(&leaf_count, sizeof(uint32_t), 1, f) != 1) {
		fprintf(stderr, "deserialize_node() fread sibling and leaf counts failed\n");
		return NULL;
	}

	Node *node = alloc_shared(sizeof(Node));
	if (!node) {
		fprintf(stderr, "deserialize_node() alloc shared failed\n");
		return NULL;
	}
	zero(node, sizeof(Node));
	node->parent = parent;
	size_t path_len;
	if (fread(&path_len, sizeof(size_t), 1, f) != 1 
			|| path_len > MAX_PATH_LEN 
			|| fread(node->path, path_len, 1, f) != 1) {
		fprintf(stderr, "deserialize_node() fread path failed\n");
		return NULL;
	}
	size_t node_key_len;
	if (fread(&node_key_len, sizeof(size_t), 1, f) != 1 
			|| node_key_len > MAX_KEY_LEN 
			|| fread(node->key, node_key_len, 1, f) != 1) {
		fprintf(stderr, "deserialize_node() fread key failed\n");
		return NULL;
	}
	add_node_to_table(node);
	
	Leaf *prev_leaf = NULL;
	for (uint32_t i = 0; i < leaf_count; i++) {
		Leaf *leaf = alloc_shared(sizeof(Leaf));
		if (!leaf) {
			fprintf(stderr, "deserialize_node() alloc shared leaf failed\n");
			return NULL;
		}
		zero(leaf, sizeof(Leaf));
		leaf->parent = node;
		size_t leaf_key_len;
		if (fread(&leaf_key_len, sizeof(size_t), 1, f) != 1 
				|| leaf_key_len > MAX_KEY_LEN 
				|| fread(leaf->key, leaf_key_len, 1, f) != 1 
				|| fread(&leaf->type, sizeof(ValueType), 1, f) != 1) {
			fprintf(stderr, "deserialize_node() fread leaf failed\n");
			return NULL;
		}
		switch(leaf->type) {
			case VALUE_STRING:
				size_t value_len;
				if (fread(&value_len, sizeof(size_t), 1, f) != 1) {
					fprintf(stderr, "deserialize_node() fread string length failed\n");
					return NULL;
				}
				leaf->value.string = alloc_shared(value_len);
				if (!leaf->value.string || fread(leaf->value.string, value_len, 1, f) != 1) {
					fprintf(stderr, "deserialize_node() fread string failed\n");
					return NULL;
				}
				break;
			case VALUE_INT:
				if (fread(&leaf->value.integer, sizeof(int32_t), 1, f) != 1) {
                    			fprintf(stderr, "deserialize_node: fread int failed\n");
                    			return NULL;
                		}
                		break;
            		case VALUE_DOUBLE:
                		if (fread(&leaf->value.floating, sizeof(double), 1, f) != 1) {
                    			fprintf(stderr, "deserialize_node: fread double failed\n");
                    			return NULL;
                		}
                		break;
            		case VALUE_BINARY:
                		if (fread(&leaf->value.binary.size, sizeof(size_t), 1, f) != 1) {
                    			fprintf(stderr, "deserialize_node: fread binary size failed\n");
                    			return NULL;
                		}
                		leaf->value.binary.data = alloc_shared(leaf->value.binary.size);
                		if (!leaf->value.binary.data 
						|| fread(leaf->value.binary.data, leaf->value.binary.size, 1, f) != 1) {
                    			fprintf(stderr, "deserialize_node: fread binary data failed\n");
                    			return NULL;
                		}
                		if (fread(&leaf->value.binary.compressed, sizeof(int), 1, f) != 1) {
                    			fprintf(stderr, "deserialize_node: fread binary compressed flag failed\n");
                    			return NULL;
                		}
                		break;
		}
		add_leaf_to_table(leaf);
		if (prev_leaf) prev_leaf->sibling = leaf;
		else node->leaf = leaf;
		prev_leaf = leaf;
	}

	node->child = deserialize_node(f, node);
	node->sibling = deserialize_node(f, parent);

	return node;
}

int deserialize_database(const char *filename) {
	pthread_mutex_lock(&mem_control->mutex);
	FILE *f = fopen(filename, "rb");
	if (!f) {
		fprintf(stderr, "deserialize_database fopen failed\n");
		pthread_mutex_unlock(&mem_control->mutex);
		return 1;
	}
	fprintf(stderr, "Database found. Initializing...\n");

	if (fread(&mem_control->user_count, sizeof(size_t), 1, f) != 1) {
		fclose(f);
		pthread_mutex_unlock(&mem_control->mutex);
		fprintf(stderr, "load_database() fread usercount failure\n");
		return 1;	
	}
	for (size_t i = 0; i < mem_control->user_count; i++) {
		mem_control->users[i] = alloc_shared(sizeof(User));
		if (fread(mem_control->users[i], sizeof(User), 1, f) != 1) {
			fclose(f);
			pthread_mutex_unlock(&mem_control->mutex);
			fprintf(stderr, "load_database() fread user failure\n");
			return 1;	
		}
	}

	/* if (fread(&mem_control->node_count, sizeof(int), 1, f) != 1) {
		fclose(f);
		pthread_mutex_unlock(&mem_control->mutex);
		fprintf(stderr, "load_database() fread nodecount failure\n");
		return 1;
	}
	fprintf(stderr, "Success read number of nodes: %ld\n", mem_control->node_count);
	*/
	root = deserialize_node(f, NULL);
	if (!root) {
		fprintf(stderr, "deserialize_database: deserialize_node failed\n");
		fclose(f);
		pthread_mutex_unlock(&mem_control->mutex);
		return 1;
	}

	fprintf(stderr, "Successfully loaded saved database from %s\n", filename);
	fclose(f);
	pthread_mutex_unlock(&mem_control->mutex);
	return 0;

}

void verify_database(const char *filename) {
	FILE *f = fopen(filename, "rb");
	if (!f) {
		fprintf(stderr, "verify_database: fopen failed: %s\n", strerror(errno));
		return;
	}
	size_t user_count;
	if (fread(&user_count, sizeof(size_t), 1, f) != 1) {
		fprintf(stderr, "verify_database: fread user_count failed: %s\n", strerror(errno));
		fclose(f);
		return;
	}
	printf("User count: %zu\n", user_count);
	for (size_t i = 0; i < user_count; i++) {
		User user;
		if (fread(&user, sizeof(User), 1, f) != 1) {
		    fprintf(stderr, "verify_database: fread user %zu failed: %s\n", i, strerror(errno));
		    fclose(f);
		    return;
		}
		printf("User %zu: username=%s, logged_in=%d\n", i, user.username, user.logged_in);
		printf("Password hash: ");
		for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
		    printf("%02x", user.password_hash[j]);
		}
		printf("\n");
	}

	printf("Node tree:\n");
	while (!feof(f)) {
		uint32_t child_count, sibling_count, leaf_count;
		if (fread(&child_count, sizeof(uint32_t), 1, f) != 1) {
		    if (feof(f)) break;
		    fprintf(stderr, "verify_database: fread child_count failed: %s\n", strerror(errno));
		    fclose(f);
		    return;
		}
		if (child_count == 0xFFFFFFFF) {
		    printf("(null node)\n");
		    continue;
		}
		if (fread(&sibling_count, sizeof(uint32_t), 1, f) != 1 ||
		    fread(&leaf_count, sizeof(uint32_t), 1, f) != 1) {
		    fprintf(stderr, "verify_database: fread counts failed: %s\n", strerror(errno));
		    fclose(f);
		    return;
		}
		size_t path_len;
		char path[MAX_PATH_LEN];
		size_t node_key_len;
		char node_key[MAX_KEY_LEN];
		if (fread(&path_len, sizeof(size_t), 1, f) != 1 
			|| path_len > MAX_PATH_LEN 
			|| fread(path, path_len, 1, f) != 1
			|| fread(&node_key_len, sizeof(size_t), 1, f) != 1
			|| node_key_len > MAX_KEY_LEN
			|| fread(node_key, node_key_len, 1, f) != 1) {
		    fprintf(stderr, "verify_database: fread path failed\n");
		    fclose(f);
		    return;
		}
		path[path_len - 1] = '\0';
		node_key[node_key_len - 1] = '\0';
		printf("Node: path=%s, key=%s, children=%u, siblings=%u, leaves=%u\n", path, node_key, child_count, sibling_count, leaf_count);
        
		for (uint32_t i = 0; i < leaf_count; i++) {
		    size_t key_len;
		    char key[MAX_KEY_LEN];
		    ValueType type;
		    if (fread(&key_len, sizeof(size_t), 1, f) != 1 ||
			key_len > MAX_KEY_LEN ||
			fread(key, key_len, 1, f) != 1 ||
			fread(&type, sizeof(ValueType), 1, f) != 1) {
			fprintf(stderr, "verify_database: fread leaf failed\n");
			fclose(f);
			return;
		    }
		    key[key_len - 1] = '\0';
		    printf("  Leaf: key=%s, type=", key);
		    switch (type) {
			case VALUE_STRING:
			    {
				size_t value_len;
				if (fread(&value_len, sizeof(size_t), 1, f) != 1) {
				    fprintf(stderr, "verify_database: fread string length failed\n");
                            fclose(f);
                            return;
                        }
                        char *value = malloc(value_len);
                        if (!value || fread(value, value_len, 1, f) != 1) {
                            fprintf(stderr, "verify_database: fread string failed\n");
                            free(value);
                            fclose(f);
                            return;
                        }
                        value[value_len - 1] = '\0';
                        printf("STRING, value=%s\n", value);
                        free(value);
                    }
                    break;
                case VALUE_INT:
                    {
                        int32_t value;
                        if (fread(&value, sizeof(int32_t), 1, f) != 1) {
                            fprintf(stderr, "verify_database: fread int failed\n");
                            fclose(f);
                            return;
                        }
                        printf("INT, value=%d\n", value);
                    }
                    break;
                case VALUE_DOUBLE:
                    {
                        double value;
                        if (fread(&value, sizeof(double), 1, f) != 1) {
                            fprintf(stderr, "verify_database: fread double failed\n");
                            fclose(f);
                            return;
                        }
                        printf("DOUBLE, value=%.2f\n", value);
                    }
                    break;
                case VALUE_BINARY:
                    {
                        size_t size;
                        int compressed;
                        if (fread(&size, sizeof(size_t), 1, f) != 1) {
                            fprintf(stderr, "verify_database: fread binary size failed\n");
                            fclose(f);
                            return;
                        }
                        fseek(f, size, SEEK_CUR); // Skip binary data
                        if (fread(&compressed, sizeof(int), 1, f) != 1) {
                            fprintf(stderr, "verify_database: fread binary compressed flag failed\n");
                            fclose(f);
                            return;
                        }
                        printf("BINARY, size=%zu, compressed=%d\n", size, compressed);
                    }
                    break;
            }
        }
    }
    fclose(f);
}


int init_saved_database(void) {
//	verify_database("database.dat");

	if (deserialize_database("database.dat")) {
		return 1;
	}
	return 0;

}

void cleanup_database(void) {
	fprintf(stderr, "Saving database\n");
	serialize_database("database.dat");
	if (mem_control && mem_control->shared_mem_pool) {
		munmap(mem_control->shared_mem_pool, mem_control->shared_mem_size);
		mem_control->shared_mem_pool = NULL;
		mem_control->shared_mem_used = 0;
		mem_control->shared_mem_size = 0;
	}
	if (mem_control) {
		pthread_mutex_destroy(&mem_control->mutex);
		munmap(mem_control, sizeof(SharedMemControl));
		mem_control = NULL;
	}
	root = NULL;
	return;
}


#pragma GCC diagnostic pop
