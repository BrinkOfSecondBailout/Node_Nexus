/* database.h */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef union u_tree Tree;
typedef struct s_node Node;
typedef struct s_leaf Leaf;

typedef unsigned int int32;
typedef unsigned short int int16;

union u_tree {
	Node *node;
	Leaf *leaf;
};

struct s_node {
	struct s_node *up;
	struct s_node *left;
	Leaf *right;
	char path[256];
};

struct s_leaf {
	Tree *left;
	struct s_leaf *right;
	char key[128];
	char *value;
	int16 size;
};

Tree *create_root_node();
void print_tree(Tree *t);
