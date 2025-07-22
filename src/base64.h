/* base64.h */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void build_decoding_table(void);
void base64_cleanup(void);
char *base64_encode(const unsigned char *, size_t, size_t *);
unsigned char *base64_decode(const char *, size_t, size_t *);


