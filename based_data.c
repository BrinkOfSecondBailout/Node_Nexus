/* based_data.c */

#include "based_data.h"

int main(int argc, char* argv[]) {
	
	Node *root = create_root_node();
	Node *node = create_new_node(root, "users");
	Node *node2 = create_new_node(node, "login");
	Node *node3 = create_new_node(node2, "temp");
	char *val = "duong";
	char *val2 = "riley";
	char *val3 = "lewis";
	char *val4 = "saylor";

	Leaf *leaf = create_new_leaf(node2, "danny", val, (int16)strlen(val));
	Leaf *leaf2 = create_new_leaf(node2, "lindsey", val2, (int16)strlen(val2));
	Leaf *leaf3 = create_new_leaf(node, "shawn", val3, (int16)strlen(val3));
	Leaf *leaf4 = create_new_leaf(node3, "michael", val4, (int16)strlen(val4));
	print_tree(1, root);
	
	print_leaf(find_leaf_hash("shawn"));

	print_node(find_node(root, "temp"));


//	start_server(argc, argv);
	return 0;
}
