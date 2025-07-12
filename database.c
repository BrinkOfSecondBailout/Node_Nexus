/* database.c */

#include "database.h"
#include "base64.h"

static HashEntry *hash_table[HASH_TABLE_SIZE];


void zero(void *buf, size_t size) {
	memset(buf, 0, size);
}

void hash_table_init() {
	zero((void *)hash_table, (size_t)sizeof(hash_table));
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
	uint32_t index = HASH_KEY(key, HASH_TABLE_SIZE);
	HashEntry *entry = hash_table[index];
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
	}
	return NULL;
}

Node *find_node_linear(Node *root, char *path) {
	Node *n;
	for (n = root; n; n = n->child) {
		if (strstr(n->path, path)) {
			return n;
		}
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

Node *create_root_node() {
	Node *root = (Node *)malloc(sizeof(Node));
	CHECK_NULL(root, "Failed to allocate root");
	
	root->parent = NULL;
	root->sibling = NULL;
	root->child = NULL;
	root->leaf = NULL;
	strncpy(root->path, "/", sizeof(root->path) - 1);
	root->path[sizeof(root->path) - 1] = '\0';
	return root;
}

Node *create_new_node(Node *parent, char *path) {
	Node *new, *last;
	size_t size;
	CHECK_NULL(parent, "create_new_node() failure, invalid parent node");
	size = sizeof(Node);
	new = (Node *)malloc(size);
	zero((void *)new, size);
	char temp_path[MAX_PATH_LEN];
	size_t parent_len = strlen(parent->path);
	size_t new_len = strlen(path);	
	if (parent_len + new_len + 2 >= MAX_PATH_LEN) {
		fprintf(stderr, "Path too long in new node\n");
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

	CONCAT_PATH(temp_path, parent->path, path, MAX_PATH_LEN); 
	strncpy(new->path, temp_path, MAX_PATH_LEN - 1);
	
	return new;
}

static void add_leaf_to_table(Leaf *leaf) {	
	uint32_t index = HASH_KEY(leaf->key, HASH_TABLE_SIZE);
	HashEntry *entry = (HashEntry *)malloc(sizeof(HashEntry));
	zero((void *)entry, (size_t)sizeof(HashEntry));
	strncpy(entry->key, leaf->key, MAX_KEY_LEN);
	entry->leaf = leaf;
	entry->next = hash_table[index];
	hash_table[index] = entry;
}

static Leaf *create_new_leaf_prototype(Node *parent, char *key) {
	Leaf *last, *new;
	size_t size;
	CHECK_NULL(parent, "create_new_leaf() failure, invalid parent node");
	
	last = find_last_leaf(parent);
	size = sizeof(Leaf);
	new = (Leaf *)malloc(size);
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

	new->type = VALUE_STRING;
	new->value.string = (char *)malloc(count);
	if (!new->value.string) {
		fprintf(stderr, "create_new_leaf() failure, malloc failed\n");
		return NULL;
	}
	strncpy(new->value.string, value, count);
	
	add_leaf_to_table(new);
	return new;
}

Leaf *create_new_leaf_int(Node *parent, char *key, int32_t value) {
	Leaf *new;
	new = create_new_leaf_prototype(parent, key);
	new->type = VALUE_INT;
	new->value.integer = value;
	add_leaf_to_table(new);
	return new;
}

Leaf *create_new_leaf_double(Node *parent, char *key, double value) {
	Leaf *new;
	new = create_new_leaf_prototype(parent, key);
	new->type = VALUE_DOUBLE;
	new->value.floating = value;
	add_leaf_to_table(new);
	return new;
}

Leaf *create_new_leaf_binary(Node *parent, char *key, void *data, size_t size) {
	Leaf *new;
	new = create_new_leaf_prototype(parent, key);
	new->type = VALUE_BINARY;
	new->value.binary.data = (void *)malloc(size);
	if (!new->value.binary.data) {
		fprintf(stderr, "create_new_leaf_binary() malloc failure");
		return NULL;
	}
	memcpy(new->value.binary.data, data, size);
	new->value.binary.size = size;
	add_leaf_to_table(new);
	return new;
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
	
void free_leaf(Leaf *leaf) {
	if (!leaf) return;
	uint32_t index = HASH_KEY(leaf->key, HASH_TABLE_SIZE);
	HashEntry *entry = hash_table[index];
	HashEntry *prev = NULL;
	while (entry) {
		if (entry->leaf == leaf) {
			if (prev) {
				prev->next = entry->next;
			} else {
				hash_table[index] = entry->next;
			}
			free(entry);
			break;
		}
		prev = entry;
		entry = entry->next;
	}
	switch(leaf->type) {
		case VALUE_STRING:
			free(leaf->value.string);
			break;
		case VALUE_BINARY:
			free(leaf->value.binary.data);
			break;
		default:
			break;
	}
	free(leaf);
}

void free_node(Node *node) {
	if (!node) return;
	Leaf *leaf = node->leaf;
	while (leaf) {
		Leaf *next = leaf->sibling;
		free_leaf(leaf);
		leaf = next;
	}
	if (node->child) {
		free_node(node->child);
	}
	free(node);
}

void hash_table_free() {
	for (int i = 0; i < HASH_TABLE_SIZE; i++) {
		HashEntry *entry = hash_table[i];
		while (entry) {
			HashEntry *next = entry->next;
			free(entry);
			entry = next;
		}
		hash_table[i] = NULL;
	}
}


#pragma GCC diagnostic pop
