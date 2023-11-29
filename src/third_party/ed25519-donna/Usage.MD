# Usage
- No configuration is needed if you are compiling against OpenSSL.
  What you need is just a empty config file: ed25519-donna-optional.h

- To use a custom hash function, use -DED25519_CUSTOMHASH when compiling ed25519.c and put your custom hash implementation in ed25519-hash-custom.h. The hash must have a 512bit digest and implement

```c
struct ed25519_hash_context;

void ed25519_hash_init(ed25519_hash_context *ctx);
void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen);
void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash);
void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen);
```
