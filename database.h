/* database.h */

// #define NDEBUG

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#pragma GCC diagnostic ignored "-Wstringop-truncation"
#pragma GCC diagnostic push

#define MAX_PATH_LEN 256
#define MAX_KEY_LEN 128

#define find_last_leaf(x)		find_last_leaf_linear(x)
#define find_leaf(x, y)			find_leaf_linear(x, y)
#define find_node(x, y)			find_node_linear(x, y)

#define Print(x)						\
	zero(buf, 256);						\
	strncpy((char *)buf, (char *)(x), 255);			\
	size = (int16)strlen((char *)buf);			\
	if (size) {						\
		bytes = write(fd, (char *)buf, size);		\
		if (bytes == -1) {				\
			fprintf(stderr, "Print() failure");	\
			return;					\
		}						\
	}							\

typedef struct s_node Node;
typedef struct s_leaf Leaf;

typedef unsigned int int32;
typedef unsigned short int int16;

struct s_node {
	struct s_node *up;
	struct s_node *left;
	Leaf *right;
	char path[MAX_PATH_LEN];
};

struct s_leaf {
	struct s_node *left;
	struct s_leaf *right;
	char key[MAX_KEY_LEN];
	char *value;
	int16 size;
};

void zero(char *, int16);
char *indent(char);
void print_tree(int, Node *);
Node *create_root_node();
Node *create_new_node(Node *, char *);
Leaf *find_first_leaf(Node *);
Leaf *find_last_leaf_linear(Node *);
Leaf *create_new_leaf(Node *, char *, char *, int16);
Node *find_node_linear(Node *, char *);
Leaf *find_leaf_linear(Node *, char *);
void print_node(Node *);
void print_leaf(Leaf *);
