// batch_hash.rs - Implementação de hashing ultra-otimizado para Bitcoin
use rayon::prelude::*;
use bitcoin::hashes::{sha256, ripemd160, Hash};
use std::sync::Mutex;

// Tamanho do lote para hashing - Aumentado para melhorar desempenho
const HASH_BATCH_SIZE: usize = 65536; // Aumentado de 16384 para 65536

// Implementação do hash160 (SHA256 + RIPEMD160) otimizada para processamento em lote
pub fn batch_hash160(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 20]>,
) -> usize {
    // Verificar suporte a instruções avançadas
    if supports_avx2() {
        hash160_avx2(pubkeys, hashes_out)
    } else {
        hash160_fallback(pubkeys, hashes_out)
    }
}

// Implementação específica para CPUs com suporte a AVX2
#[cfg(target_arch = "x86_64")]
fn hash160_avx2(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 20]>,
) -> usize {
    let num_keys = pubkeys.len();
    
    // Limpar buffer de saída e reservar espaço
    hashes_out.clear();
    hashes_out.resize(num_keys, [0u8; 20]);
    
    // Processamento em lotes paralelos usando map_collect
    let results: Vec<_> = pubkeys.par_chunks(HASH_BATCH_SIZE)
        .enumerate()
        .flat_map(|(chunk_idx, pubkey_chunk)| {
            let mut local_results = Vec::with_capacity(pubkey_chunk.len());
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * HASH_BATCH_SIZE + i;
                if abs_idx >= num_keys {
                    break;
                }
                
                // Usar hash SHA-256 seguido de RIPEMD-160
                let sha256_digest = sha256::Hash::hash(pubkey);
                let ripemd160_digest = ripemd160::Hash::hash(&sha256_digest[..]);
                
                // Adicionar ao resultado local
                let mut hash_array = [0u8; 20];
                hash_array.copy_from_slice(&ripemd160_digest[..]);
                local_results.push((abs_idx, hash_array));
            }
            
            local_results
        })
        .collect();
    
    // Copiar resultados para o buffer de saída
    for (abs_idx, hash) in results {
        if abs_idx < hashes_out.len() {
            hashes_out[abs_idx].copy_from_slice(&hash);
        }
    }
    
    num_keys
}

// Implementação de fallback para CPUs sem suporte a AVX2
fn hash160_fallback(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 20]>,
) -> usize {
    let num_keys = pubkeys.len();
    
    // Limpar buffer de saída e reservar espaço
    hashes_out.clear();
    hashes_out.resize(num_keys, [0u8; 20]);
    
    // Processamento em lotes paralelos usando map_collect
    let results: Vec<_> = pubkeys.par_chunks(HASH_BATCH_SIZE)
        .enumerate()
        .flat_map(|(chunk_idx, pubkey_chunk)| {
            let mut local_results = Vec::with_capacity(pubkey_chunk.len());
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * HASH_BATCH_SIZE + i;
                if abs_idx >= num_keys {
                    break;
                }
                
                // Implementação fallback usando crates bitcoin padronizadas
                let sha256_digest = sha256::Hash::hash(pubkey);
                let ripemd160_digest = ripemd160::Hash::hash(&sha256_digest[..]);
                
                // Adicionar ao resultado local
                let mut hash_array = [0u8; 20];
                hash_array.copy_from_slice(&ripemd160_digest[..]);
                local_results.push((abs_idx, hash_array));
            }
            
            local_results
        })
        .collect();
    
    // Copiar resultados para o buffer de saída
    for (abs_idx, hash) in results {
        if abs_idx < hashes_out.len() {
            hashes_out[abs_idx].copy_from_slice(&hash);
        }
    }
    
    num_keys
}

// Verificar suporte a AVX2
#[inline]
pub fn supports_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

// Implementação que combina hashing e verificação em um único passo
// Recebe uma função de predicado para verificar se um hash corresponde ao padrão desejado
pub fn hash160_and_match<F>(
    pubkeys: &[[u8; 33]],
    predicate: F,
) -> Vec<(usize, [u8; 20])>
where 
    F: Fn(&[u8]) -> bool + Send + Sync,
{
    // Cache de mutex para resultados, reduzindo contenção
    let results = Vec::new();
    let results_mutex = Mutex::new(results);
    
    // Configuração para melhor divisão de trabalho
    let num_threads = rayon::current_num_threads();
    let chunk_size = ((pubkeys.len() / num_threads) + 1).max(HASH_BATCH_SIZE / 16);
    
    // Processar em lotes paralelos com tamanho de lote otimizado
    pubkeys.par_chunks(chunk_size)
        .enumerate()
        .for_each(|(chunk_idx, pubkey_chunk)| {
            let mut local_matches = Vec::new();
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * chunk_size + i;
                
                // Implementação direta para reduzir overhead
                // 1. Calcular SHA-256
                let sha256_digest = sha256::Hash::hash(pubkey);
                
                // 2. Calcular RIPEMD-160
                let ripemd160_digest = ripemd160::Hash::hash(&sha256_digest[..]);
                
                // 3. Verificar correspondência
                if predicate(&ripemd160_digest[..]) {
                    let mut hash_array = [0u8; 20];
                    hash_array.copy_from_slice(&ripemd160_digest[..]);
                    local_matches.push((abs_idx, hash_array));
                }
            }
            
            // Só adquirir o mutex se encontramos correspondências
            if !local_matches.is_empty() {
                let mut guard = results_mutex.lock().unwrap();
                guard.extend(local_matches);
            }
        });
    
    // Retornar resultados encontrados
    results_mutex.into_inner().unwrap()
}

// Nova implementação mais rápida para comparações diretas
// Quando sabemos exatamente qual hash procurar, essa versão é muito mais rápida
pub fn hash160_and_match_direct(
    pubkeys: &[[u8; 33]],
    target_hash: &[u8; 20],
) -> Vec<(usize, [u8; 20])> {
    // Cache de mutex para resultados
    let results = Vec::new();
    let results_mutex = Mutex::new(results);
    
    // Configuração para melhor divisão de trabalho
    let num_threads = rayon::current_num_threads();
    let chunk_size = ((pubkeys.len() / num_threads) + 1).max(HASH_BATCH_SIZE / 16);
    
    // Processar em lotes paralelos com tamanho de lote otimizado
    pubkeys.par_chunks(chunk_size)
        .enumerate()
        .for_each(|(chunk_idx, pubkey_chunk)| {
            let mut local_matches = Vec::new();
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * chunk_size + i;
                
                // Calcular hash160 diretamente
                let sha256_digest = sha256::Hash::hash(pubkey);
                let ripemd160_digest = ripemd160::Hash::hash(&sha256_digest[..]);
                
                // Comparação direta de bytes para máxima performance
                let digest_bytes: &[u8] = ripemd160_digest.as_ref();
                let mut is_match = true;
                
                for j in 0..20 {
                    if digest_bytes[j] != target_hash[j] {
                        is_match = false;
                        break;
                    }
                }
                
                if is_match {
                    let mut hash_array = [0u8; 20];
                    hash_array.copy_from_slice(digest_bytes);
                    local_matches.push((abs_idx, hash_array));
                }
            }
            
            // Só adquirir o mutex se encontramos correspondências
            if !local_matches.is_empty() {
                let mut guard = results_mutex.lock().unwrap();
                guard.extend(local_matches);
            }
        });
    
    // Retornar resultados encontrados
    results_mutex.into_inner().unwrap()
} 
