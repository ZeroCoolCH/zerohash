#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>
#include <cstddef> // Para size_t
#include <cstdint> // Para uint8_t

// Interface C para ser chamada pelo Rust
extern "C" {
    void calculate_hash160_batch_cpp(
        const uint8_t* pubkeys_ptr, // Ponteiro para as chaves públicas concatenadas
        size_t num_keys,           // Número de chaves no lote
        uint8_t* hashes_out_ptr    // Ponteiro para o buffer de saída (hashes concatenados)
    ) {
        unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
        unsigned char ripemd160_digest[RIPEMD160_DIGEST_LENGTH];

        for (size_t i = 0; i < num_keys; ++i) {
            // Aponta para a chave pública atual (33 bytes)
            const uint8_t* current_pubkey = pubkeys_ptr + i * 33;

            // 1. SHA256
            SHA256_CTX sha256_ctx;
            SHA256_Init(&sha256_ctx);
            SHA256_Update(&sha256_ctx, current_pubkey, 33);
            SHA256_Final(sha256_digest, &sha256_ctx);

            // 2. RIPEMD160
            RIPEMD160_CTX ripemd160_ctx;
            RIPEMD160_Init(&ripemd160_ctx);
            RIPEMD160_Update(&ripemd160_ctx, sha256_digest, SHA256_DIGEST_LENGTH);
            RIPEMD160_Final(ripemd160_digest, &ripemd160_ctx);

            // Copia o resultado RIPEMD-160 (20 bytes) para o buffer de saída
            uint8_t* current_out_ptr = hashes_out_ptr + i * 20;
            for (int j = 0; j < RIPEMD160_DIGEST_LENGTH; ++j) {
                current_out_ptr[j] = ripemd160_digest[j];
            }
        }
    }
}
