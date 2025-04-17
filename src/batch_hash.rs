// batch_hash.rs - Implementação de hashing ultra-otimizado para Bitcoin
use rayon::prelude::*;
use bitcoin::hashes::{sha256, ripemd160, Hash};
use std::sync::Mutex;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use std::sync::Arc;
use hex;
use sha3::{Sha3_256, Digest};

// Declarações de funções externas em C
extern "C" {
    fn calculate_hash160_batch_cpp(
        pubkeys_ptr: *const u8, 
        num_keys: usize,
        hashes_out_ptr: *mut u8
    );
    
    fn extract_sha256_state_cpp(
        data: *const u8,
        data_length: usize,
        state_out: *mut u32
    );
    
    fn resume_sha256_from_state_cpp(
        saved_state: *const u32,
        processed_bytes: usize,
        new_data: *const u8,
        new_data_length: usize,
        digest_out: *mut u8
    );
    
    fn hash160_with_cached_state_cpp(
        saved_state: *const u32,
        processed_bytes: usize,
        remaining_data: *const u8,
        remaining_length: usize,
        hash160_out: *mut u8
    );
}

// Tamanho do lote para hashing - Aumentado para melhorar desempenho
const HASH_BATCH_SIZE: usize = 65536; // Aumentado de 16384 para 65536

// Tamanho do prefixo para caching (em bytes)
const PREFIX_SIZE: usize = 5; // Primeiros 5 bytes da chave pública são frequentemente compartilhados

// Tipo para armazenar estado intermediário do SHA-256
#[derive(Clone)]
struct Sha256State {
    state: [u32; 8],    // Estado interno do SHA-256
    processed_bytes: usize, // Quantos bytes já foram processados
}

// Estrutura do Cache Contextual Dinâmico
struct DynamicContextualCache {
    // Mapeia prefixos para estados intermediários do SHA-256
    sha256_states: HashMap<Vec<u8>, Sha256State>,
    // Contadores de uso para adaptação dinâmica
    usage_counts: HashMap<Vec<u8>, usize>,
    // Limitar tamanho do cache
    max_size: usize,
}

// Cache global usando Lazy para inicialização preguiçosa e thread-safe
static CONTEXTUAL_CACHE: Lazy<Mutex<DynamicContextualCache>> = Lazy::new(|| {
    Mutex::new(DynamicContextualCache {
        sha256_states: HashMap::new(),
        usage_counts: HashMap::new(),
        max_size: 1024, // Tamanho máximo do cache
    })
});

impl DynamicContextualCache {
    // Obter estado do SHA-256 para um prefixo, ou None se não estiver em cache
    fn get_sha256_state(&mut self, prefix: &[u8]) -> Option<Sha256State> {
        if let Some(state) = self.sha256_states.get(prefix) {
            // Incrementar contador de uso
            *self.usage_counts.entry(prefix.to_vec()).or_insert(0) += 1;
            Some(state.clone())
        } else {
            None
        }
    }
    
    // Armazenar um novo estado de SHA-256 para um prefixo
    fn store_sha256_state(&mut self, prefix: Vec<u8>, state: Sha256State) {
        // Verificar se o cache está cheio
        if self.sha256_states.len() >= self.max_size {
            // Estratégia de adaptação: remover o prefixo menos usado
            if let Some((least_used_prefix, _)) = self.usage_counts
                .iter()
                .min_by_key(|(_, &count)| count) {
                let least_used_prefix = least_used_prefix.clone();
                self.sha256_states.remove(&least_used_prefix);
                self.usage_counts.remove(&least_used_prefix);
            }
        }
        
        // Adicionar novo estado ao cache
        self.sha256_states.insert(prefix.clone(), state);
        self.usage_counts.insert(prefix, 1);
    }
    
    // Limpar cache completamente (útil para mudanças drásticas no padrão de entrada)
    fn clear(&mut self) {
        self.sha256_states.clear();
        self.usage_counts.clear();
    }
}

// Funções para extrair e manipular estados do SHA-256 (usando OpenSSL via FFI)
fn extract_sha256_state_cpp_wrapper(data: &[u8]) -> Sha256State {
    let mut state = [0u32; 8];
    
    unsafe {
        extract_sha256_state_cpp(
            data.as_ptr(),
            data.len(),
            state.as_mut_ptr()
        );
    }
    
    Sha256State {
        state,
        processed_bytes: data.len(),
    }
}

// Criar um contexto SHA-256 a partir de um estado intermediário usando OpenSSL
fn create_sha256_from_state_cpp_wrapper(state: &Sha256State, data: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    
    unsafe {
        resume_sha256_from_state_cpp(
            state.state.as_ptr(),
            state.processed_bytes,
            data.as_ptr(),
            data.len(),
            digest.as_mut_ptr()
        );
    }
    
    digest
}

// Hash160 direto de um estado salvo usando OpenSSL
fn hash160_with_state_cpp_wrapper(state: &Sha256State, data: &[u8]) -> [u8; 20] {
    let mut hash160 = [0u8; 20];
    
    unsafe {
        hash160_with_cached_state_cpp(
            state.state.as_ptr(),
            state.processed_bytes,
            data.as_ptr(),
            data.len(),
            hash160.as_mut_ptr()
        );
    }
    
    hash160
}

// Função para calcular o hash SHA3-256 de uma chave pública
pub fn calculate_sha3_256(pubkey: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(pubkey);
    hasher.finalize().to_vec()
}

// Função para calcular o hash160 usando SHA3-256 seguido de RIPEMD160
pub fn hash160_sha3(pubkeys: &[[u8; 33]], hashes_out: &mut Vec<[u8; 20]>) {
    hashes_out.clear();
    hashes_out.reserve(pubkeys.len());

    for pubkey in pubkeys {
        // Calcular SHA3-256
        let sha3_hash = calculate_sha3_256(pubkey);

        // Calcular RIPEMD160 do resultado SHA3-256
        let ripemd160_hash = ripemd160::Hash::hash(&sha3_hash);

        // Adicionar ao vetor de saída
        hashes_out.push(ripemd160_hash.to_byte_array());
    }
}

// Implementação do hash160 (SHA256 + RIPEMD160) otimizada para processamento em lote
// Agora com suporte a Cache Contextual Dinâmico
pub fn batch_hash160(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 20]>,
) -> usize {
    // Verificar suporte a instruções avançadas
    if supports_avx2() {
        hash160_avx2_cached(pubkeys, hashes_out)
    } else {
        hash160_fallback_cached(pubkeys, hashes_out)
    }
}

// Nova implementação que usa o cache contextual
#[cfg(target_arch = "x86_64")]
fn hash160_avx2_cached(
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
            // Obter acesso ao cache - Cada thread tem sua própria cópia temporária do cache
            let mut cache_access = CONTEXTUAL_CACHE.lock().unwrap();
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * HASH_BATCH_SIZE + i;
                if abs_idx >= num_keys {
                    break;
                }
                
                // Extrair prefixo para verificar no cache
                let prefix = &pubkey[0..PREFIX_SIZE.min(pubkey.len())];
                let remaining = &pubkey[PREFIX_SIZE.min(pubkey.len())..];
                
                // Tentar usar o cache
                let hash_array = if let Some(cached_state) = cache_access.get_sha256_state(prefix) {
                    // Usar estado intermediário do cache - agora com FFI para OpenSSL
                    hash160_with_state_cpp_wrapper(&cached_state, remaining)
                } else {
                    // Cache miss - calcular normalmente
                    let mut hash_array = [0u8; 20];
                    
                    // Calcular o hash completo
                    let sha256_digest = sha256::Hash::hash(pubkey);
                    let ripemd160_digest = ripemd160::Hash::hash(&sha256_digest[..]);
                    hash_array.copy_from_slice(&ripemd160_digest[..]);
                    
                    // Armazenar no cache para uso futuro
                    let state = extract_sha256_state_cpp_wrapper(prefix);
                    cache_access.store_sha256_state(prefix.to_vec(), state);
                    
                    hash_array
                };
                
                // Adicionar ao resultado local
                local_results.push((abs_idx, hash_array));
            }
            
            // Liberar o lock do cache
            drop(cache_access);
            
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

// Implementação fallback com cache contextual
fn hash160_fallback_cached(
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
            // Obter acesso ao cache - Cada thread tem sua própria cópia temporária do cache
            let mut cache_access = CONTEXTUAL_CACHE.lock().unwrap();
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * HASH_BATCH_SIZE + i;
                if abs_idx >= num_keys {
                    break;
                }
                
                // Extrair prefixo para verificar no cache
                let prefix = &pubkey[0..PREFIX_SIZE.min(pubkey.len())];
                let remaining = &pubkey[PREFIX_SIZE.min(pubkey.len())..];
                
                // Tentar usar o cache
                let hash_array = if let Some(cached_state) = cache_access.get_sha256_state(prefix) {
                    // Usar estado intermediário do cache - agora com FFI para OpenSSL
                    hash160_with_state_cpp_wrapper(&cached_state, remaining)
                } else {
                    // Cache miss - calcular normalmente
                    let mut hash_array = [0u8; 20];
                    
                    // Calcular o hash completo
                    let sha256_digest = sha256::Hash::hash(pubkey);
                    let ripemd160_digest = ripemd160::Hash::hash(&sha256_digest[..]);
                    hash_array.copy_from_slice(&ripemd160_digest[..]);
                    
                    // Armazenar no cache para uso futuro
                    let state = extract_sha256_state_cpp_wrapper(prefix);
                    cache_access.store_sha256_state(prefix.to_vec(), state);
                    
                    hash_array
                };
                
                // Adicionar ao resultado local
                local_results.push((abs_idx, hash_array));
            }
            
            // Liberar o lock do cache
            drop(cache_access);
            
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

// Implementação direta para comparação com target específico
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
    
    // Processar em lotes paralelos
    pubkeys.par_chunks(chunk_size)
        .enumerate()
        .for_each(|(chunk_idx, pubkey_chunk)| {
            let mut local_matches = Vec::new();
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * chunk_size + i;
                
                // Usar o algoritmo tradicional Bitcoin: SHA256 seguido por RIPEMD160
                let sha256_digest = sha256::Hash::hash(pubkey);
                let ripemd160_digest = ripemd160::Hash::hash(&sha256_digest[..]);
                let mut hash_array = [0u8; 20];
                hash_array.copy_from_slice(&ripemd160_digest[..]);
                
                // Comparação direta de bytes para máxima performance
                let mut is_match = true;
                for j in 0..20 {
                    if hash_array[j] != target_hash[j] {
                        is_match = false;
                        break;
                    }
                }
                
                if is_match {
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

// Implementação que combina hashing e verificação em um único passo
pub fn hash160_and_match<F>(
    pubkeys: &[[u8; 33]],
    predicate: F,
) -> Vec<(usize, [u8; 20])>
where 
    F: Fn(&[u8]) -> bool + Send + Sync,
{
    // Cache de mutex para resultados
    let results = Vec::new();
    let results_mutex = Mutex::new(results);
    
    // Configuração para melhor divisão de trabalho
    let num_threads = rayon::current_num_threads();
    let chunk_size = ((pubkeys.len() / num_threads) + 1).max(HASH_BATCH_SIZE / 16);
    
    // Processar em lotes paralelos
    pubkeys.par_chunks(chunk_size)
        .enumerate()
        .for_each(|(chunk_idx, pubkey_chunk)| {
            let mut local_matches = Vec::new();
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * chunk_size + i;
                
                // Usar o algoritmo tradicional Bitcoin: SHA256 seguido por RIPEMD160
                let sha256_digest = sha256::Hash::hash(pubkey);
                let ripemd160_digest = ripemd160::Hash::hash(&sha256_digest[..]);
                let mut hash_array = [0u8; 20];
                hash_array.copy_from_slice(&ripemd160_digest[..]);
                
                // Verificar correspondência
                if predicate(&hash_array) {
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

// Nova função para pré-aquecer o cache com valores conhecidos
pub fn warm_up_cache(known_prefixes: &[&[u8]]) {
    let mut cache = CONTEXTUAL_CACHE.lock().unwrap();
    for &prefix in known_prefixes {
        if prefix.len() >= PREFIX_SIZE {
            let prefix_slice = &prefix[0..PREFIX_SIZE];
            
            // Extrair e armazenar o estado usando o wrapper C++
            let state = extract_sha256_state_cpp_wrapper(prefix_slice);
            cache.store_sha256_state(prefix_slice.to_vec(), state);
        }
    }
}

// Função para adaptar o tamanho do prefixo com base em padrões observados
pub fn adapt_prefix_size(pubkeys_sample: &[[u8; 33]]) {
    // Analisar a amostra para determinar o tamanho de prefixo ideal
    // Implementação simplificada - na prática seria mais sofisticado
    let mut prefixes = HashMap::new();
    
    for pubkey in pubkeys_sample {
        for size in 1..=8 {
            if size <= pubkey.len() {
                let prefix = &pubkey[0..size];
                *prefixes.entry(prefix.to_vec()).or_insert(0) += 1;
            }
        }
    }
    
    // Analisar prefixos para encontrar tamanho ideal
    // Implementação completa seria mais sofisticada
}

// Implementação de hash completo usando apenas SHA3-256 (sem RIPEMD160)
pub fn batch_hash_sha3_direct(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 32]>,
) -> usize {
    let num_keys = pubkeys.len();
    
    // Limpar buffer de saída e reservar espaço
    hashes_out.clear();
    hashes_out.resize(num_keys, [0u8; 32]);
    
    // Processamento em lotes paralelos
    let results: Vec<_> = pubkeys.par_chunks(HASH_BATCH_SIZE)
        .enumerate()
        .flat_map(|(chunk_idx, pubkey_chunk)| {
            let mut local_results = Vec::with_capacity(pubkey_chunk.len());
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * HASH_BATCH_SIZE + i;
                if abs_idx >= num_keys {
                    break;
                }
                
                // Calcular SHA3-256 diretamente
                let mut hasher = Sha3_256::new();
                hasher.update(pubkey);
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&hasher.finalize());
                
                local_results.push((abs_idx, hash_array));
            }
            
            local_results
        })
        .collect();
    
    // Copiar resultados para o buffer de saída
    for (idx, hash) in results {
        if idx < hashes_out.len() {
            hashes_out[idx].copy_from_slice(&hash);
        }
    }
    
    num_keys
}

// Função para truncar o hash SHA3-256 para 20 bytes (como alternativa ao RIPEMD160)
pub fn batch_hash_sha3_truncated(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 20]>,
) -> usize {
    let num_keys = pubkeys.len();
    
    // Limpar buffer de saída e reservar espaço
    hashes_out.clear();
    hashes_out.resize(num_keys, [0u8; 20]);
    
    // Processamento em lotes paralelos
    let results: Vec<_> = pubkeys.par_chunks(HASH_BATCH_SIZE)
        .enumerate()
        .flat_map(|(chunk_idx, pubkey_chunk)| {
            let mut local_results = Vec::with_capacity(pubkey_chunk.len());
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * HASH_BATCH_SIZE + i;
                if abs_idx >= num_keys {
                    break;
                }
                
                // Calcular SHA3-256
                let mut hasher = Sha3_256::new();
                hasher.update(pubkey);
                let result = hasher.finalize();
                
                // Truncar para 20 bytes
                let mut hash_array = [0u8; 20];
                hash_array.copy_from_slice(&result[0..20]);
                
                local_results.push((abs_idx, hash_array));
            }
            
            local_results
        })
        .collect();
    
    // Copiar resultados para o buffer de saída
    for (idx, hash) in results {
        if idx < hashes_out.len() {
            hashes_out[idx].copy_from_slice(&hash);
        }
    }
    
    num_keys
}

// Implementação que combina hashing SHA3 e verificação em um único passo
pub fn hash_sha3_and_match<F>(
    pubkeys: &[[u8; 33]],
    predicate: F,
) -> Vec<(usize, [u8; 32])>
where 
    F: Fn(&[u8]) -> bool + Send + Sync,
{
    // Cache de mutex para resultados
    let results = Vec::new();
    let results_mutex = Mutex::new(results);
    
    // Configuração para melhor divisão de trabalho
    let num_threads = rayon::current_num_threads();
    let chunk_size = ((pubkeys.len() / num_threads) + 1).max(HASH_BATCH_SIZE / 16);
    
    // Processar em lotes paralelos
    pubkeys.par_chunks(chunk_size)
        .enumerate()
        .for_each(|(chunk_idx, pubkey_chunk)| {
            let mut local_matches = Vec::new();
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * chunk_size + i;
                
                // Calcular SHA3-256
                let mut hasher = Sha3_256::new();
                hasher.update(pubkey);
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&hasher.finalize());
                
                // Verificar correspondência
                if predicate(&hash_array) {
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

// Versão truncada do hash_sha3_and_match
pub fn hash_sha3_truncated_and_match<F>(
    pubkeys: &[[u8; 33]],
    predicate: F,
) -> Vec<(usize, [u8; 20])>
where 
    F: Fn(&[u8]) -> bool + Send + Sync,
{
    // Cache de mutex para resultados
    let results = Vec::new();
    let results_mutex = Mutex::new(results);
    
    // Configuração para melhor divisão de trabalho
    let num_threads = rayon::current_num_threads();
    let chunk_size = ((pubkeys.len() / num_threads) + 1).max(HASH_BATCH_SIZE / 16);
    
    // Processar em lotes paralelos
    pubkeys.par_chunks(chunk_size)
        .enumerate()
        .for_each(|(chunk_idx, pubkey_chunk)| {
            let mut local_matches = Vec::new();
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * chunk_size + i;
                
                // Calcular SHA3-256
                let mut hasher = Sha3_256::new();
                hasher.update(pubkey);
                let result = hasher.finalize();
                
                // Truncar para 20 bytes
                let mut hash_array = [0u8; 20];
                hash_array.copy_from_slice(&result[0..20]);
                
                // Verificar correspondência
                if predicate(&hash_array) {
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

// Nova implementação direta para comparação SHA3 com target específico
pub fn hash_sha3_and_match_direct(
    pubkeys: &[[u8; 33]],
    target_hash: &[u8; 32],
) -> Vec<(usize, [u8; 32])> {
    // Cache de mutex para resultados
    let results = Vec::new();
    let results_mutex = Mutex::new(results);
    
    // Configuração para melhor divisão de trabalho
    let num_threads = rayon::current_num_threads();
    let chunk_size = ((pubkeys.len() / num_threads) + 1).max(HASH_BATCH_SIZE / 16);
    
    // Processar em lotes paralelos
    pubkeys.par_chunks(chunk_size)
        .enumerate()
        .for_each(|(chunk_idx, pubkey_chunk)| {
            let mut local_matches = Vec::new();
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * chunk_size + i;
                
                // Calcular SHA3-256
                let mut hasher = Sha3_256::new();
                hasher.update(pubkey);
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&hasher.finalize());
                
                // Comparação direta de bytes para máxima performance
                let mut is_match = true;
                for j in 0..32 {
                    if hash_array[j] != target_hash[j] {
                        is_match = false;
                        break;
                    }
                }
                
                if is_match {
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

// Inicializa o Cache Contextual Dinâmico para uso com SHA3
pub fn initialize_contextual_cache_sha3() {
    let mut cache = CONTEXTUAL_CACHE.lock().unwrap();
    cache.clear();
    println!("Cache Contextual Dinâmico inicializado para SHA3");
} 
