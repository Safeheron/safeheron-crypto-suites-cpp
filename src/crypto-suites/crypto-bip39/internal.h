#ifndef CRYPTOBIP39_INTERNAL_H
#define CRYPTOBIP39_INTERNAL_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void clear_and_free(void *p, size_t len);
void wally_clear(void *p, size_t len);
void wally_free(void *ptr);
void *wally_malloc(size_t size);
char *wally_strdup(const char *str);;
#ifdef __cplusplus
}
#endif
#endif //CRYPTOBIP39_INTERNAL_H
