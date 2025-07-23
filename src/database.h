/* database.h */

#ifndef DATABASE_H
#define DATABASE_H

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <zlib.h>
#include <openssl/sha.h>
#include <pthread.h>

#pragma GCC diagnostic ignored "-Wstringop-truncation"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic push

#define MAX_PATH_LEN 256
#define MAX_KEY_LEN 128
#define LEAF_HASH_TABLE_SIZE 1024
#define MAX_BASE64_LEN 1048576 //1MB
#define SHARED_MEM_INITIAL_SIZE 1024 * 1024 //1MB
#define MAX_USERNAME_LEN 32
#define MAX_USERS 100

#define find_last_leaf(x)		find_last_leaf_linear(x)
#define find_last_child_node(x)		find_last_child_node_linear(x)
#define find_leaf(x)			find_leaf_hash(x)
#define find_node(x, y)			find_node_linear(x, y)

#define CONCAT_PATH(dest, parent_path, child_path, max_len)			\
	do {									\
		if (strcmp((parent_path), "/") == 0)				\
			snprintf((dest), (max_len), "/%s", (child_path));	\
		else								\
			snprintf((dest), (max_len), "%s/%s",			\
					(parent_path), (child_path));		\
	} while (0)

#define CHECK_NULL(ptr, err_message)						\
	do {									\
		if (!(ptr)) {							\
			fprintf(stderr, "%s\n", err_message);			\
			return NULL;						\
		}								\
	} while (0)

#define HASH_KEY(key, size)							\
	({									\
	 	uint32_t hash = 2166136261u;					\
		const char *k = (key);						\
		while (*k) {							\
			hash ^= (uint32_t)*k++;					\
			hash *= 16777619u;					\
		}								\
		hash % (size);							\
	})

typedef struct s_node Node;
typedef struct s_leaf Leaf;
typedef struct s_leaf_hash_entry LeafHashEntry;
typedef struct s_user User;

typedef unsigned int int32;
typedef unsigned short int int16;
typedef unsigned char int8;

typedef enum {
	VALUE_STRING,
	VALUE_INT,
	VALUE_DOUBLE,
	VALUE_BINARY
} ValueType;

typedef union {
	char *string;
	int32_t integer;
	double floating;
	struct {
		void *data;
		size_t size;
		int compressed;
	} binary;
} LeafValue;


struct s_node {
	struct s_node *parent;
	struct s_node *child;
	struct s_node *sibling;
	Leaf *leaf;
	char path[MAX_PATH_LEN];
};

struct s_leaf {
	struct s_node *parent;
	struct s_leaf *sibling;
	char key[MAX_KEY_LEN];
	LeafValue value;
	ValueType type;
};

struct s_leaf_hash_entry {
	char key[MAX_KEY_LEN];
	Leaf *leaf;
	struct s_leaf_hash_entry *next;
};

struct s_user {
	char username[MAX_USERNAME_LEN];
	unsigned char password_hash[SHA256_DIGEST_LENGTH]; //32bytes
	int logged_in;
};

typedef struct SharedMemControl {
	void *shared_mem_pool;
	size_t shared_mem_size;
	size_t shared_mem_used;
	LeafHashEntry *leaf_hash_table[LEAF_HASH_TABLE_SIZE];
	size_t leaf_count;
	User *users[MAX_USERS];
	size_t user_count;
	pthread_mutex_t mutex;
} SharedMemControl;

extern SharedMemControl *mem_control;
extern Node *root;

void *alloc_shared(size_t size);
void zero(void *, size_t);
// char *indent(int8);
// void print_original_node(Node *, int8, int);
// void print_leaves_of_node(Node *, int8, int);
// void print_node_and_leaves(Node *, int8, int );
void print_tree(int, Node *);
Node *create_root_node();
// Node *find_first_child_node(Node *);
// Node *find_last_child_node_linear(Node *);
Node *create_new_node(Node *, char *);
// Leaf *find_first_leaf(Node *);
// Leaf *find_last_leaf_linear(Node *);
// void add_leaf_to_table(Leaf *);
Leaf *find_leaf_by_hash(char *);
// Leaf *create_new_leaf_prototype(Node *, char *);
Leaf *create_new_leaf_string(Node *, char *, char *, size_t);
Leaf *create_new_leaf_int(Node *, char *, int32_t);
Leaf *create_new_leaf_double(Node *, char *, double);
Leaf *create_new_leaf_binary(Node *, char *, void *, size_t);
User *create_new_user(const char *, const char *);
User *find_user(const char *);
int mark_user_logged_in(const char *);
int mark_user_logged_out(const char *);
int verify_user(const char *, const char *);
Node *find_node_linear(Node *, char *);
Leaf *find_leaf_linear(Node *, char *);
void print_node(Node *);
void print_leaf(int, Leaf *);
int delete_node(Node *);
int delete_leaf(char *);
void reset_database();
void free_leaf(Leaf *);
void free_node(Node *);
void leaf_hash_table_init();
void leaf_hash_table_free();
void cleanup_database(void);
void init_saved_database();

#endif
