/* database.c */

#include "database.h"

void zero(char *buf, int16 size) {
	char *p;
	int16 n;
	for (n = 0, p = buf; n < size; n++, p++)
		*p = 0;
	return;
}

char *indent(char n) {
	int16 i;
	static char buf[256];
	char *p;
	if (n < 1)
		return (char *)"";
	assert(n < 120);
	zero(buf, 256);
	for (i = 0, p = buf; i < n; i++, p+=2)
		strncpy((char *)p, "  ", 2);
	return buf;
}

void print_tree(int fd, Node *root) {
	assert(root);
	char indentation;
	char buf[256];
	int16 size;
	ssize_t bytes;
	Node *n;
	Leaf *l, *first;

	indentation = 0;
	for (n = root; n; n = n->left) {
		Print(indent(indentation++));
		Print(n->path);
		Print("\n");
		if (n->right) {
			first = find_first_leaf(n);
			if (first) {
				for (l = first; l; l = l->right) {
					Print(indent(indentation));
					Print(n->path);
					Print("/ >> ");
					Print(l->key);
					Print(" -> '");
					bytes = write(fd, (char *)l->value, (int)l->size);
					if (bytes == -1) {
						fprintf(stderr, "print_tree() failure");
						return;
					}
					Print("'\n");
				}
			}
		}
	}	
}

Node *create_root_node() {
	Node *root = malloc(sizeof(Node));
	if (!root) {
		fprintf(stderr, "Failed to allocate root\n");
		return NULL;
	}
	
	root->up = NULL;
	root->left = NULL;
	root->right = NULL;
	strncpy(root->path, "/", sizeof(root->path) - 1);
	root->path[sizeof(root->path) - 1] = '\0';
	return root;
}

Node *create_new_node(Node *parent, char *path) {
	Node *n;
	int16 size;
	assert(parent);
	size = sizeof(Node);
	n = (Node *)malloc((int)size);
	zero((char *)n, size);
	char temp_path[MAX_PATH_LEN];
	size_t parent_len = strlen(parent->path);
	size_t new_len = strlen(path);	
	if (parent_len + new_len + 1 >= MAX_PATH_LEN) {
		fprintf(stderr, "Path too long in new node\n");
		return 0;
	}

	parent->left = n;
	n->up = parent;
	n->left = NULL;
	n->right = NULL; 

	if (!strcmp(parent->path, "/")) {
		snprintf(temp_path, MAX_PATH_LEN, "%s", path);
	} else {
		snprintf(temp_path, MAX_PATH_LEN, "%s%s", parent->path, path);
	}

	strncpy(n->path, temp_path, MAX_PATH_LEN - 1);
	n->path[MAX_PATH_LEN - 1] = '\0';
	return n;
}

Leaf *find_first_leaf(Node *parent) {
	Leaf *l;
	assert(parent);
	if (!parent->right)
		return (Leaf *)0;
	l = parent->right;
	assert(l);
	return l;
}

Leaf *find_last_leaf_linear(Node *parent) {
	Leaf *l;
	assert(parent);
	if (!parent->right)
		return (Leaf *)0;
	for (l = parent->right; l->right; l = l->right);
	assert(l);
	return l;
}

Leaf *create_new_leaf(Node *parent, char *key, char *value, int16 count) {
	Leaf *last, *new;
	int16 size;
	assert(parent);
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
	new->value = (char *)malloc(count);
	assert(new->value);
	strncpy(new->value, value, count);
	new->size = count;
	return new;
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
		printf("Value: %s\n", l->value);
		printf("\n");
	}
	return;
}



#pragma GCC diagnostic pop
