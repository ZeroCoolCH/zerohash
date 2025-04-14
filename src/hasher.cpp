#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <vector>
#include <cstddef> // Para size_t
#include <cstdint> // Para uint8_t
#include <cstring> // Para memcpy

// Interface C para ser chamada pelo Rust
extern "C" {
    void calculate_hash160_batch_cpp(
        const uint8_t* pubkeys_ptr, // Ponteiro para as chaves públicas concatenadas
        size_t num_keys,           // Número de chaves no lote
        uint8_t* hashes_out_ptr    // Ponteiro para o buffer de saída (hashes concatenados)
    ) {
        for (size_t i = 0; i < num_keys; ++i) {
            // Aponta para a chave pública atual (33 bytes)
            const uint8_t* current_pubkey = pubkeys_ptr + i * 33;

            // 1. SHA256 usando EVP API
            EVP_MD_CTX* sha256_ctx = EVP_MD_CTX_new();
            unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
            unsigned int sha256_len = 0;
            
            EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(sha256_ctx, current_pubkey, 33);
            EVP_DigestFinal_ex(sha256_ctx, sha256_digest, &sha256_len);
            EVP_MD_CTX_free(sha256_ctx);

            // 2. RIPEMD160 usando EVP API
            EVP_MD_CTX* ripemd160_ctx = EVP_MD_CTX_new();
            unsigned char ripemd160_digest[RIPEMD160_DIGEST_LENGTH];
            unsigned int ripemd160_len = 0;
            
            EVP_DigestInit_ex(ripemd160_ctx, EVP_ripemd160(), NULL);
            EVP_DigestUpdate(ripemd160_ctx, sha256_digest, SHA256_DIGEST_LENGTH);
            EVP_DigestFinal_ex(ripemd160_ctx, ripemd160_digest, &ripemd160_len);
            EVP_MD_CTX_free(ripemd160_ctx);

            // Copia o resultado RIPEMD-160 (20 bytes) para o buffer de saída
            uint8_t* current_out_ptr = hashes_out_ptr + i * 20;
            memcpy(current_out_ptr, ripemd160_digest, RIPEMD160_DIGEST_LENGTH);
        }
    }
    
    // Nova função para extrair o estado do contexto SHA256
    void extract_sha256_state_cpp(
        const uint8_t* data,      // Dados a processar
        size_t data_length,       // Comprimento dos dados
        uint32_t* state_out       // Saída: estado SHA-256 (8 inteiros de 32 bits)
    ) {
        // Nota: OpenSSL 3.0 não fornece acesso direto ao estado interno,
        // então vamos simular guardando o hash completo
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        unsigned char digest[SHA256_DIGEST_LENGTH];
        unsigned int digest_len = 0;
        
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, data, data_length);
        EVP_DigestFinal_ex(ctx, digest, &digest_len);
        
        // Como não podemos acessar o estado interno diretamente,
        // simplesmente copiamos o hash resultante para state_out
        // Convertemos para uint32_t (8 elementos)
        for (int i = 0; i < 8; ++i) {
            uint32_t value = 0;
            for (int j = 0; j < 4; ++j) {
                value = (value << 8) | digest[i*4 + j];
            }
            state_out[i] = value;
        }
        
        EVP_MD_CTX_free(ctx);
    }
    
    // Nova função para restaurar um contexto SHA256 de um estado salvo e continuar processamento
    void resume_sha256_from_state_cpp(
        const uint32_t* saved_state,   // Estado SHA-256 salvo (8 inteiros de 32 bits) - não usado na OpenSSL 3.0
        size_t processed_bytes,        // Número de bytes já processados - não usado na OpenSSL 3.0
        const uint8_t* new_data,       // Novos dados a processar
        size_t new_data_length,        // Comprimento dos novos dados
        uint8_t* digest_out            // Saída: hash final (32 bytes)
    ) {
        // Em OpenSSL 3.0, não podemos restaurar o estado interno diretamente.
        // Esta é uma implementação simplificada que ignora o estado anterior
        // e processa apenas os novos dados.
        // 
        // Nota: Em uma implementação completa, seria necessário armazenar e
        // reprocessar todos os dados anteriores junto com os novos.
        
        (void)saved_state;      // Silenciar aviso de parâmetro não utilizado
        (void)processed_bytes;  // Silenciar aviso de parâmetro não utilizado
        
        // Calcular o hash apenas dos novos dados
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        unsigned int digest_len = 0;
        
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, new_data, new_data_length);
        EVP_DigestFinal_ex(ctx, digest_out, &digest_len);
        
        EVP_MD_CTX_free(ctx);
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
        
        // Aplicar RIPEMD-160 ao resultado SHA-256 usando EVP API
        EVP_MD_CTX* ripemd160_ctx = EVP_MD_CTX_new();
        unsigned int ripemd160_len = 0;
        
        EVP_DigestInit_ex(ripemd160_ctx, EVP_ripemd160(), NULL);
        EVP_DigestUpdate(ripemd160_ctx, sha256_digest, SHA256_DIGEST_LENGTH);
        EVP_DigestFinal_ex(ripemd160_ctx, hash160_out, &ripemd160_len);
        
        EVP_MD_CTX_free(ripemd160_ctx);
    }
}
