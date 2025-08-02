/* database.h */

#ifndef DATABASE_H
#define DATABASE_H

#include "classifier.h"
#include "base64.h"

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

#define MAX_CONNECTIONS 10
#define ADMIN_USERNAME "admin"
#define MAX_PATH_LEN 256
#define MAX_KEY_LEN 128
#define NODE_HASH_TABLE_SIZE 1024
#define LEAF_HASH_TABLE_SIZE 1024
#define MAX_BASE64_LEN 1048576 //1MB
#define SHARED_MEM_INITIAL_SIZE 1024 * 1024 //1MB
#define MAX_USERNAME_LEN 32
#define MAX_USERS 20
#define MAX_PASSWORD_LEN 40

#define PRINT_CHECK			fprintf(stderr, "CHECK_POINT\n")
#define MUTEX_LOCK			pthread_mutex_lock(&mem_control->mutex)
#define MUTEX_UNLOCK			pthread_mutex_unlock(&mem_control->mutex)

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
typedef struct s_client Client;
typedef struct s_client_hash_entry ClientHashEntry;
typedef struct s_node_hash_entry NodeHashEntry;
typedef struct s_leaf_hash_entry LeafHashEntry;
typedef struct s_user User;
typedef struct s_user_hash_entry UserHashEntry;

typedef unsigned int int32;
typedef unsigned short int int16;
typedef unsigned char int8;

typedef enum {
	VALUE_STRING,
	VALUE_INT,
	VALUE_BINARY
} ValueType;

typedef union {
	char *string;
	int32_t integer;
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
	char key[MAX_KEY_LEN];
	char path[MAX_PATH_LEN];
};

struct s_leaf {
	struct s_node *parent;
	struct s_leaf *sibling;
	char key[MAX_KEY_LEN];
	LeafValue value;
	ValueType type;
};

struct s_client {
	int s;
	char ip[16];
	int16 port;
	size_t logged_in;
	char username[MAX_USERNAME_LEN];
};

struct s_node_hash_entry {
	char key[MAX_KEY_LEN];
	Node *node;
	struct s_node_hash_entry *next;
};

struct s_leaf_hash_entry {
	char key[MAX_KEY_LEN];
	Leaf *leaf;
	struct s_leaf_hash_entry *next;
};

struct s_client_hash_entry {
	char key[MAX_KEY_LEN];
	Client *client;
	struct s_client_hash_entry *next;
};

struct s_user_hash_entry {
	char key[MAX_KEY_LEN];
	User *user;
	struct s_user_hash_entry *next;
};

struct s_user {
	char username[MAX_USERNAME_LEN];
	unsigned char password_hash[SHA256_DIGEST_LENGTH]; //32bytes
	size_t logged_in;
};

typedef struct SharedMemControl {
	Node *root;
	size_t active_connections;
	void *shared_mem_pool;
	size_t shared_mem_size;
	size_t shared_mem_used;
	NodeHashEntry *node_hash_table[NODE_HASH_TABLE_SIZE];
	size_t node_count;
	LeafHashEntry *leaf_hash_table[LEAF_HASH_TABLE_SIZE];
	size_t leaf_count;
	UserHashEntry *user_hash_table[MAX_USERS];
	size_t user_count;
	ClientHashEntry *logged_in_clients[MAX_CONNECTIONS];
	size_t logged_in_client_count;
	pthread_mutex_t mutex;
	int dirty;
} SharedMemControl;

extern SharedMemControl *mem_control;
extern Node *root;

void *alloc_shared(size_t size);
void zero(void *, size_t);
void node_hash_table_init();
void leaf_hash_table_init();
void user_hash_table_init();
void client_hash_table_init();
Node *find_node_by_hash(char *);
Leaf *find_leaf_by_hash(char *);
void print_tree(int, Node *);
User *create_admin_user();
Node *create_root_node();
Node *create_new_node(Node *, char *);
Leaf *create_new_leaf_string(Node *, char *, char *, size_t);
Leaf *create_new_leaf_int(Node *, char *, int32_t);
Leaf *create_new_leaf_binary(Node *, char *, void *, size_t);
User *create_new_user(const char *, const char *);
User *find_user(const char *);
int delete_user(User *);
int change_user_password(User *, const char *);
void mark_user_logged_in(User *);
void mark_user_logged_out(User *);
int verify_user(const char *, const char *);
void print_node(int, Node *);
void print_leaf(int, Leaf *);
int delete_node(Node *);
int delete_leaf(char *);
void init_database();
void reset_database();
void cleanup_database(void);
int init_saved_database();
void verify_database(const char *);

#endif
