#include "internal.h"
#include <stdlib.h>
#include <string.h>
#include "memzero.h"

void wally_clear(void *p, size_t len) {
    crypto_bip39_memzero(p, len);
}
void wally_free(void *ptr) {
    if (ptr)
        free(ptr);
}
void *wally_malloc(size_t size) {
    return malloc(size);
}
char *wally_strdup(const char *str) {
    size_t len = strlen(str) + 1;
    char *new_str = (char *)wally_malloc(len);
    if (new_str)
        memcpy(new_str, str, len); /* Copies terminating nul */
    return new_str;
}
void clear_and_free(void *p, size_t len)
{
    if (p) {
        wally_clear(p, len);
        wally_free(p);
    }
}