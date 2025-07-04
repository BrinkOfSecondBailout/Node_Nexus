/* based_data.c */

#include "based_data.h"

int main(int argc, char* argv[]) {
	
	Node *root = create_root_node();
	Node *docs = create_new_node(root, "docs");
	Node *users = create_new_node(root, "users");
	Node *temp = create_new_node(docs, "temp");
	Node *main_users = create_new_node(users, "main_users");
	
	
	Leaf *leaf1 = create_new_leaf_string(docs, "note", "Hello, world!", 13);
	Leaf *leaf2 = create_new_leaf_int(docs, "size", 1024);
	Leaf *leaf3 = create_new_leaf_double(temp, "time", 1234567.123);
	char binary_data[] = {0x01, 0x02, 0x03};
	Leaf *leaf4 = create_new_leaf_binary(users, "data", binary_data, 3);

/*
	print_leaf(leaf1);
	print_leaf(leaf2);
	print_leaf(leaf3);
	print_leaf(leaf4);
	print_node(docs);
*/

	print_node(temp);

	print_tree(1, root);

	free_node(root);
	hash_table_free();

//	start_server(argc, argv);
	return 0;
}
