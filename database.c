/* database.c */

#include "database.h"

void zero(char *buf, int16 size) {
	char *p;
	int16 n;
	for (n = 0, p = buf; n < size; n++, p++)
		*p = 0;
	return;
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

	snprintf(temp_path, MAX_PATH_LEN, "%s%s", parent->path, path);
	strncpy(n->path, temp_path, MAX_PATH_LEN - 1);
	n->path[MAX_PATH_LEN - 1] = '\0';
	return n;
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




