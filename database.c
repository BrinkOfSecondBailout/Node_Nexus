/* database.c */

#include "database.h"

static HashEntry *hash_table[HASH_TABLE_SIZE];


void zero(char *buf, int16 size) {
	char *p;
	int16 n;
	for (n = 0, p = buf; n < size; n++, p++)
		*p = 0;
	return;
}

char *indent(char n) {
	static char buf[256];
	if (n < 1 || n >= 120) {
		buf[0] = '\0';
	}
	int i;
	for (i = 0; i < n; i++) {
		memcpy(buf + i * 3, i == 0 ? "|--" : "---", 3);
	}
	buf[i * 3] = '\0';
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

void print_node_and_leaves(Node *n, char indentation, int fd) {
	char buf[512];
	Leaf *l, *first;
	
	if (!n) return;
	snprintf(buf, sizeof(buf), "%s%s\n", indent(indentation), n->path);
	if (write_str(fd, buf) < 0) return;

	if (n->right) {
		first = find_first_leaf(n);
		for (l = first; l; l = l->right) {
			switch (l->type) {
				case VALUE_STRING:
					snprintf(buf, sizeof(buf), "%s%s/..%s -> '%s'\n",
						indent(indentation), n->path, l->key, l->value.string);
					break;
				case VALUE_INT:
					snprintf(buf, sizeof(buf), "%s%s/..%s -> %d\n",
						indent(indentation), n->path, l->key, l->value.integer);
					break;
				case VALUE_DOUBLE:
					snprintf(buf, sizeof(buf), "%s%s/..%s -> %.2f\n",
						indent(indentation), n->path, l->key, l->value.floating);
					break;
				case VALUE_BINARY:
					snprintf(buf, sizeof(buf), "%s%s/..%s -> [binary data, size = %d]\n",
						indent(indentation), n->path, l->key, l->value.binary.size);
					break;
			}
			if (write_str(fd, buf) < 0) return;
		}
	}

/*
	print_f(buf, indent(indentation), fd);
	print_f(buf, n->path, fd);
	print_f(buf, "\n", fd);
	if (n->right) {
		first = find_first_leaf(n);
		if (first) {
			for (l = first; l; l = l->right) {
				print_f(buf, indent(indentation), fd);
				print_f(buf, n->path, fd);
				print_f(buf, "/..", fd);
				print_f(buf, l->key, fd);
				print_f(buf, " -> ", fd);
				switch (l->type) {
					case VALUE_STRING:
						print_f(buf, "'", fd);
						if (write(fd, l->value.string, strlen(l->value.string)) == -1) {
							fprintf(stderr, "print_tree() failure");
							return;
						}
						print_f(buf, "'", fd);
						break;
					case VALUE_INT:
						snprintf(buf, 256, "%d", l->value.integer);
						break;
					case VALUE_DOUBLE:
						snprintf(buf, 256, "%.2f", l->value.floating);
						break;
					case VALUE_BINARY:
						snprintf(buf, 256, "[binary data, size=%d]",
							l->value.binary.size);
						break;

				}
				print_f(buf, "\n", fd);
			}
		}
	}

	*/
}

void print_tree(int fd, Node *root) {
	if (!root) {
		fprintf(stderr, "print_tree() failure, invalid root\n");
		return;
	}
	char indentation = 0;
	Node *n, *placeholder;
	for (n = root; n; n = n->left) {
		placeholder = n;
		print_node_and_leaves(n, indentation, 2);
		while (n->next) {
			n = n->next;
			print_node_and_leaves(n, indentation, 2);	
		}	
		n = placeholder;	
		indentation++;
	} 

	printf("\n");
}

Node *create_root_node() {
	Node *root = malloc(sizeof(Node));
	if (!root) {
		fprintf(stderr, "Failed to allocate root\n");
		return NULL;
	}
	
	root->up = NULL;
	root->next = NULL;
	root->left = NULL;
	root->right = NULL;
	strncpy(root->path, "/", sizeof(root->path) - 1);
	root->path[sizeof(root->path) - 1] = '\0';
	return root;
}

Node *find_first_node(Node *parent) {
	Node *n;
	if (!parent) {
		fprintf(stderr, "find_first_node() failure, invalid parent node\n");
		return (Node *)0;
	}
	n = parent->left;
	if (!n) {
		fprintf(stderr, "find_first_node() failure, no node found\n");
		return (Node *)0;
	}
	return n;
}

Node *find_last_node_linear(Node *parent) {
	Node *n;
	if (!parent) {
		fprintf(stderr, "find_last_node_linear() failure, invalid parent node\n");
		return (Node *)0;
	}
	n = parent->left;
	if (!n) {
		return (Node *)0;	
	}
	while (n->next) {
		n = n->next;
	}
	if (!n) {
		return (Node *)0;
	}
	return n;
}

Node *create_new_node(Node *parent, char *path) {
	Node *new, *last;
	int16 size;
	if (!parent) {
		fprintf(stderr, "create_new_node() failure, invalid parent node\n");
		return (Node *)0;
	}
	size = sizeof(Node);
	new = (Node *)malloc((int)size);
	zero((char *)new, size);
	char temp_path[MAX_PATH_LEN];
	size_t parent_len = strlen(parent->path);
	size_t new_len = strlen(path);	
	if (parent_len + new_len + 1 >= MAX_PATH_LEN) {
		fprintf(stderr, "Path too long in new node\n");
		return 0;
	}

	last = find_last_node(parent);
	if (!last) {
		parent->left = new;
	} else {
		last->next = new;
	}

	new->up = parent;
	new->next = NULL;
	new->left = NULL;
	new->right = NULL; 

	if (!strcmp(parent->path, "/")) {
		snprintf(temp_path, MAX_PATH_LEN, "/%s", path);
	} else {
		snprintf(temp_path, MAX_PATH_LEN, "%s/%s", parent->path, path);
	}

	strncpy(new->path, temp_path, MAX_PATH_LEN - 1);
	
	new->path[MAX_PATH_LEN - 1] = '\0';
	return new;
}

Leaf *find_first_leaf(Node *parent) {
	Leaf *l;
	if (!parent) {
		fprintf(stderr, "find_first_leaf() failure, invalid parent node\n");
		return (Leaf *)0;
	}
	if (!parent->right)
		return (Leaf *)0;
	l = parent->right;

	if (!l) {
		fprintf(stderr, "find_first_leaf() failure, invalid leaf found\n");
		return (Leaf *)0;
	}
	return l;
}

Leaf *find_last_leaf_linear(Node *parent) {
	Leaf *l;
	if (!parent) {
		fprintf(stderr, "find_last_leaf() failure, invalid parent node\n");
		return (Leaf *)0;
	}
	
	if (!parent->right)
		return (Leaf *)0;
	for (l = parent->right; l->right; l = l->right);
	if (!l) {
		fprintf(stderr, "find_last_leaf() failure, invalid leaf found\n");
		return (Leaf *)0;
	}
	return l;
}

static uint32_t fnv1a_hash(const char *key) {
	uint32_t hash = 2166136261u;
	while (*key) {
		hash ^= (uint32_t)*key++;
		hash *= 16777619u;
	}
	return hash % HASH_TABLE_SIZE;
}

void hash_table_init() {
	zero((char *)hash_table, sizeof(hash_table));
}

void add_leaf_to_table(Leaf *leaf) {	
	uint32_t index = fnv1a_hash(leaf->key);
	HashEntry *entry = (HashEntry *)malloc(sizeof(HashEntry));
	zero((char *)entry, sizeof(HashEntry));
	strncpy(entry->key, leaf->key, MAX_KEY_LEN);
	entry->leaf = leaf;
	entry->next = hash_table[index];
	hash_table[index] = entry;
}

Leaf *create_new_leaf_prototype(Node *parent, char *key) {
	Leaf *last, *new;
	int16 size;
	if (!parent) {
		fprintf(stderr, "create_new_leaf() failure, invalid parent node\n");
		return (Leaf *)0;
	}
	
	last = find_last_leaf(parent);
	size = sizeof(Leaf);
	new = (Leaf *)malloc((int)size);
	zero((char *)new, size);
	if (last) {
		last->right = new;
	} else {
		parent->right = new;
	}
	new->left = parent;
	new->right = NULL;
	strncpy(new->key, key, 127);
	return new;
}


Leaf *create_new_leaf_string(Node *parent, char *key, char *value, int16 count) {
	Leaf *new;
	new = create_new_leaf_prototype(parent, key);	

	new->type = VALUE_STRING;
	new->value.string = (char *)malloc(count);
	if (!new->value.string) {
		fprintf(stderr, "create_new_leaf() failure, malloc failed\n");
		return (Leaf *)0;
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

Leaf *create_new_leaf_binary(Node *parent, char *key, void *data, int16 size) {
	Leaf *new;
	new = create_new_leaf_prototype(parent, key);
	new->type = VALUE_BINARY;
	new->value.binary.data = malloc(size);
	if (!new->value.binary.data) {
		fprintf(stderr, "create_new_leaf_binary() malloc failure");
		return (Leaf *)0;
	}
	memcpy(new->value.binary.data, data, size);
	new->value.binary.size = size;
	add_leaf_to_table(new);
	return new;
}

Leaf *find_leaf_hash(char *key) {
	uint32_t index = fnv1a_hash(key);
	HashEntry *entry = hash_table[index];
	while (entry) {
		if (!strcmp(entry->key, key)) {
			return entry->leaf;
		}
		entry = entry->next;
	}
	return (Leaf *) 0;
}

Leaf *find_leaf_linear(Node *root, char *key) {
	Node *n;
	Leaf *l;
	Leaf *ret = (Leaf *)0;
	for (n = root; n; n = n->left) {
		l = find_first_leaf(n);
		while (l) {
			if (!strcmp(l->key, key)) {
				ret = l;
				break;
			}
			l = l->right;
		}
	}
	return ret;
}

Node *find_node_linear(Node *root, char *path) {
	Node *n;
	Node *ret = (Node *)0;
	for (n = root; n; n = n->left) {
		if (strstr(n->path, path)) {
			ret = n;
			break;
		}
	}
	return ret;
}


void print_node(Node *n) {
	if (!n) {
		printf("Invalid node\n");
	} else {
		printf("**Node**\n");
		printf("Path: %s\n", n->path);
		if (n->right)
			printf("Folder has files inside\n");
		else
			printf("Folder is empty\n");
		printf("\n");
	}
	return;
}

void print_leaf(Leaf *l) {
	if (!l) {
		printf("Invalid leaf\n");
	} else {
		printf("**Leaf**\n");
		printf("Path: %s\n", l->left->path);
		printf("Key: %s\n", l->key);
		printf("Value: ");
		switch(l->type) {
			case VALUE_STRING:
				printf("'%s' (string)\n", l->value.string);
				break;
			case VALUE_INT:
				printf("%d (integer)\n", l->value.integer);
				break;
			case VALUE_DOUBLE:
				printf("%.2f (double)\n", l->value.floating);
				break;
			case VALUE_BINARY:
				printf("[binary data, size=%d]\n", l->value.binary.size);
				break;
		}

		printf("\n");
	}
	return;
}
	
void free_leaf(Leaf *leaf) {
	if (!leaf) return;
	uint32_t index = fnv1a_hash(leaf->key);
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
	Leaf *leaf = node->right;
	while (leaf) {
		Leaf *next = leaf->right;
		free_leaf(leaf);
		leaf = next;
	}
	if (node->left) {
		free_node(node->left);
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
