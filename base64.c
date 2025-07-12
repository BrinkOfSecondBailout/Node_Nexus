/* base64.c */

#include "base64.h"

static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static unsigned char *decoding_table = NULL;

void build_decoding_table(void) {
        decoding_table = malloc(256);
        for (int i = 0; i < 64; i++) {
                decoding_table[(unsigned char)encoding_table[i]] = i;
        }
}

void base64_cleanup(void) {
        free(decoding_table);
        decoding_table = NULL;
}

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    if (!decoding_table) build_decoding_table();
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);
    if (!encoded_data) return NULL;
    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = (i > input_length - 2) ? '=' : encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = (i > input_length - 1) ? '=' : encoding_table[triple & 0x3F];
    }
    encoded_data[*output_length] = '\0';
    return encoded_data;
}

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {
        if (!decoding_table) build_decoding_table();
        if (input_length % 4 != 0) return NULL;
        *output_length = input_length / 4 * 3;
        if (data[input_length - 1] == '=') (*output_length)--;
        if (data[input_length - 2] == '=') (*output_length)--;
        unsigned char *decoded_data = malloc(*output_length);
        if (!decoded_data) return NULL;
        for (size_t i = 0, j = 0; i < input_length;) {
                uint32_t sextet_a = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i++]];
                uint32_t sextet_b = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i++]];
                uint32_t sextet_c = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i++]];
                uint32_t sextet_d = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i++]];
                uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;
                if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
                if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
                if (j < *output_length) decoded_data[j++] = triple & 0xFF;
        }
        return decoded_data;
}
