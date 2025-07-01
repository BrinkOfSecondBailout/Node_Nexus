/* database.c */

#include "database.h"

Tree *create_root_node() {
	Tree *root = malloc(sizeof(Tree));
	if (!root) {
		fprintf(stderr, "Failed to allocate root\n");
		return NULL;
	}
	Node *node = malloc(sizeof(Node));
	if (!node) {
		fprintf(stderr, "Failed to allocate root node\n");
		free(root);
		return NULL;
	}
	node->up = NULL;
	node->left = NULL;
	node->right = NULL;
	strncpy(node->path, "/", sizeof(node->path) - 1);
	node->path[sizeof(node->path) - 1] = '\0';
	root->node = node;
	return root;
}

void print_tree(Tree *t) {
	if (!t) {
		printf("Invalid tree\n");
	}
	if (t->node) {
		printf("**Node**\n");
		printf("Path: %s\n", t->node->path);
		if (t->node->right)
			printf("Folder has files inside\n");
		else
			printf("Folder is empty\n");
	} else {
		printf("**Leaf**\n");
		printf("Path: %s\n", t->leaf->left->node->path);
		printf("Key: %s\n", t->leaf->key);
		printf("Value: %s\n", t->leaf->value);
	}
	return;
}
