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
    
    // Nova função para extrair o estado do contexto SHA256
    void extract_sha256_state_cpp(
        const uint8_t* data,      // Dados a processar
        size_t data_length,       // Comprimento dos dados
        uint32_t* state_out       // Saída: estado SHA-256 (8 inteiros de 32 bits)
    ) {
        // Inicializar contexto SHA-256
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        
        // Processar os dados fornecidos
        SHA256_Update(&ctx, data, data_length);
        
        // Extrair o estado H0-H7
        // Em OpenSSL, o estado interno está em ctx.h[]
        for (int i = 0; i < 8; ++i) {
            state_out[i] = ctx.h[i];
        }
    }
    
    // Nova função para restaurar um contexto SHA256 de um estado salvo e continuar processamento
    void resume_sha256_from_state_cpp(
        const uint32_t* saved_state,   // Estado SHA-256 salvo (8 inteiros de 32 bits)
        size_t processed_bytes,        // Número de bytes já processados
        const uint8_t* new_data,       // Novos dados a processar
        size_t new_data_length,        // Comprimento dos novos dados
        uint8_t* digest_out            // Saída: hash final (32 bytes)
    ) {
        // Inicializar contexto SHA-256
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        
        // Restaurar o estado
        for (int i = 0; i < 8; ++i) {
            ctx.h[i] = saved_state[i];
        }
        
        // Definir número de bits processados
        // Em OpenSSL, isso é armazenado como total bits processados em Nl, Nh
        ctx.Nl = (processed_bytes * 8) & 0xffffffffUL;
        ctx.Nh = ((processed_bytes * 8) >> 32) & 0xffffffffUL;
        
        // Processar os novos dados
        SHA256_Update(&ctx, new_data, new_data_length);
        
        // Finalizar o hash
        SHA256_Final(digest_out, &ctx);
    }
    
    // Nova função hash160 que utiliza estados intermediários do cache
    void hash160_with_cached_state_cpp(
        const uint32_t* saved_state,    // Estado SHA-256 salvo (8 inteiros de 32 bits)
        size_t processed_bytes,         // Número de bytes já processados
        const uint8_t* remaining_data,  // Dados restantes a processar
        size_t remaining_length,        // Comprimento dos dados restantes
        uint8_t* hash160_out            // Saída: hash RIPEMD160 (20 bytes)
    ) {
        unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
        
        // Restaurar estado SHA-256 e continuar processamento
        resume_sha256_from_state_cpp(
            saved_state,
            processed_bytes,
            remaining_data,
            remaining_length,
            sha256_digest
        );
        
        // Aplicar RIPEMD-160 ao resultado SHA-256
        RIPEMD160_CTX ripemd160_ctx;
        RIPEMD160_Init(&ripemd160_ctx);
        RIPEMD160_Update(&ripemd160_ctx, sha256_digest, SHA256_DIGEST_LENGTH);
        RIPEMD160_Final(hash160_out, &ripemd160_ctx);
    }
}
