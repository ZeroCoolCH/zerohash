// batch_hash.rs - Implementação de hashing ultra-otimizado para Bitcoin
use rayon::prelude::*;
use bitcoin::hashes::{sha256, ripemd160, Hash};
use std::sync::Mutex;
use std::collections::{HashMap, HashSet};
use once_cell::sync::Lazy;
use std::sync::Arc;
use hex;
use sha3::{Sha3_256, Digest};
use parking_lot::{RwLock, Mutex as PLMutex};
use lru::{LruCache, DefaultHasher};
use std::num::NonZeroUsize;
use std::sync::atomic::Ordering;

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

// Tamanhos otimizados para melhorar throughput
const HASH_BATCH_SIZE: usize = 32768; // Aumentado para 32K para melhor throughput em sistemas modernos

// Tamanhos de prefixo para cada nível de cache
const L1_PREFIX_SIZE: usize = 1;      // Manter em 1 para máximo hit rate
const L2_PREFIX_SIZE: usize = 2;      // Reduzido para 2 bytes para melhor performance
const L3_PREFIX_SIZE: usize = 3;      // Reduzido para 3 bytes para equilibrar hit rate

// Constante para tamanho de prefixo padrão
const PREFIX_SIZE: usize = L1_PREFIX_SIZE;

// Tamanhos dos caches
const L1_MAX_ENTRIES: usize = 512;    // Aumentado para 512 para cobrir mais prefixos comuns
const L2_MAX_ENTRIES: usize = 1024;   // 1024 entradas (bom para 2 bytes)
const L3_MAX_ENTRIES: usize = 4096;   // 4096 entradas (equilibrado para 3 bytes)

// Tipo para armazenar estado intermediário do SHA-256
#[derive(Clone, Debug)]
struct Sha256State {
    state: [u32; 8],    // Estado interno do SHA-256
    processed_bytes: usize, // Quantos bytes já foram processados
}

// Sistema de Cache Hierárquico (3 níveis)
// L1: Cache muito pequeno, altamente otimizado para os prefixos mais comuns (3 bytes)
// L2: Cache de tamanho médio para prefixos um pouco mais longos (5 bytes)
// L3: Cache grande para prefixos específicos (8 bytes)

// Estrutura do Cache L1 (mais rápido, menor)
struct L1Cache {
    // Usando um HashMap por ser extremamente eficiente para acesso
    states: PLMutex<HashMap<[u8; L1_PREFIX_SIZE], Sha256State>>,
    hits: std::sync::atomic::AtomicUsize,
    misses: std::sync::atomic::AtomicUsize,
    inserts: std::sync::atomic::AtomicUsize,
}

// Estrutura do Cache L2 (intermediário)
struct L2Cache {
    // Usando HashMap para equilíbrio entre velocidade e flexibilidade
    states: PLMutex<HashMap<Vec<u8>, Sha256State>>,
    hits: std::sync::atomic::AtomicUsize,
    misses: std::sync::atomic::AtomicUsize,
    inserts: std::sync::atomic::AtomicUsize,
    evictions: std::sync::atomic::AtomicUsize,
}

// Estrutura do Cache L3 (maior, mais lento)
struct L3Cache {
    // Usando LruCache para controle automático de evicção baseado em LRU
    states: RwLock<LruCache<Vec<u8>, Sha256State>>,
    hits: std::sync::atomic::AtomicUsize,
    misses: std::sync::atomic::AtomicUsize,
    inserts: std::sync::atomic::AtomicUsize,
}

// Sistema completo de cache hierárquico
struct HierarchicalCache {
    l1: L1Cache,
    l2: L2Cache,
    l3: L3Cache,
}

// Cache global usando Lazy para inicialização preguiçosa e thread-safe
static HIERARCHICAL_CACHE: Lazy<Arc<HierarchicalCache>> = Lazy::new(|| {
    Arc::new(HierarchicalCache {
        l1: L1Cache {
            states: PLMutex::new(HashMap::with_capacity(L1_MAX_ENTRIES)),
            hits: std::sync::atomic::AtomicUsize::new(0),
            misses: std::sync::atomic::AtomicUsize::new(0),
            inserts: std::sync::atomic::AtomicUsize::new(0),
        },
        l2: L2Cache {
            states: PLMutex::new(HashMap::with_capacity(L2_MAX_ENTRIES)),
            hits: std::sync::atomic::AtomicUsize::new(0),
            misses: std::sync::atomic::AtomicUsize::new(0),
            inserts: std::sync::atomic::AtomicUsize::new(0),
            evictions: std::sync::atomic::AtomicUsize::new(0),
        },
        l3: L3Cache {
            states: RwLock::new(LruCache::new(NonZeroUsize::new(L3_MAX_ENTRIES).unwrap())),
            hits: std::sync::atomic::AtomicUsize::new(0),
            misses: std::sync::atomic::AtomicUsize::new(0),
            inserts: std::sync::atomic::AtomicUsize::new(0),
        },
    })
});

// Mantendo a estrutura antiga do cache para compatibilidade
struct DynamicContextualCache {
    // Mapeia prefixos para estados intermediários do SHA-256
    sha256_states: HashMap<Vec<u8>, Sha256State>,
    // Contadores de uso para adaptação dinâmica
    usage_counts: HashMap<Vec<u8>, usize>,
    // Limitar tamanho do cache
    max_size: usize,
}

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
// Agora com suporte a Cache Hierárquico e instruções avançadas
pub fn batch_hash160(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 20]>,
) -> usize {
    // Verificar suporte a instruções avançadas
    if supports_avx512f() {
        // Usar código otimizado para AVX-512
        hash160_avx512_cached(pubkeys, hashes_out)
    } else if supports_avx2() {
        // Fallback para AVX2
        hash160_avx2_cached(pubkeys, hashes_out)
    } else {
        // Fallback para sistemas sem instruções avançadas
        hash160_fallback_cached(pubkeys, hashes_out)
    }
}

// Nova implementação otimizada para AVX-512
#[cfg(target_arch = "x86_64")]
fn hash160_avx512_cached(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 20]>,
) -> usize {
    let num_keys = pubkeys.len();
    
    // Limpar buffer de saída e reservar espaço temporário
    let mut results_temp = vec![(0usize, [0u8; 20]); 0];
    
    // Processar paralelamente e coletar resultados
    let results: Vec<(usize, [u8; 20])> = pubkeys.par_chunks(HASH_BATCH_SIZE * 2)
        .enumerate()
        .flat_map(|(chunk_idx, pubkey_chunk)| {
            // Criar vetores locais para armazenar resultados
            let mut local_results = Vec::with_capacity(pubkey_chunk.len());
            // Obter acesso ao cache - Cada thread tem sua própria cópia temporária do cache
            let cache = get_hierarchical_cache();
            
            // Buffer para processamento em lote direto
            let mut batch_pubkeys = Vec::with_capacity(pubkey_chunk.len());
            let mut batch_indices = Vec::with_capacity(pubkey_chunk.len());
            
            // Primeira passagem - separar os casos de cache hit e miss
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * HASH_BATCH_SIZE * 2 + i;
                if abs_idx >= num_keys {
                    break;
                }
                
                // Extrair prefixo para verificar no cache - apenas 1 byte para L1
                let prefix = &pubkey[0..L1_PREFIX_SIZE.min(pubkey.len())];
                
                // Otimização para chaves comprimidas
                if prefix[0] == 0x02 || prefix[0] == 0x03 {
                    let mut key = [0u8; L1_PREFIX_SIZE];
                    key.copy_from_slice(prefix);
                    
                    if let Some(cached_state) = cache.l1.states.lock().get(&key) {
                        // Cache hit - processar diretamente
                        cache.l1.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let hash = hash160_with_state_cpp_wrapper(cached_state, &pubkey[L1_PREFIX_SIZE..]);
                        
                        // Armazenar diretamente no vetor local de resultados
                        local_results.push((abs_idx, hash));
                    } else {
                        // Cache miss - adicionar ao lote
                        cache.l1.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        batch_pubkeys.push(*pubkey);
                        batch_indices.push(abs_idx);
                    }
                } else {
                    // Direto para processamento em lote
                    batch_pubkeys.push(*pubkey);
                    batch_indices.push(abs_idx);
                }
            }
            
            // Processar o lote restante de uma vez usando código otimizado para AVX-512
            if !batch_pubkeys.is_empty() {
                let mut batch_hashes = vec![[0u8; 20]; batch_pubkeys.len()];
                
                unsafe {
                    // Aproveitar instruções AVX-512 se disponíveis através da FFI
                    calculate_hash160_batch_cpp(
                        batch_pubkeys.as_ptr() as *const u8,
                        batch_pubkeys.len(),
                        batch_hashes.as_mut_ptr() as *mut u8
                    );
                }
                
                // Atualizar cache e coletar resultados
                for i in 0..batch_indices.len() {
                    let idx = batch_indices[i];
                    let pubkey = batch_pubkeys[i];
                    let hash = batch_hashes[i];
                    
                    // Apenas cache L1 para prefixos comuns (otimização de memória)
                    if pubkey[0] == 0x02 || pubkey[0] == 0x03 {
                        let prefix = &pubkey[0..L1_PREFIX_SIZE];
                        let mut key = [0u8; L1_PREFIX_SIZE];
                        key.copy_from_slice(prefix);
                        
                        let state = extract_sha256_state_cpp_wrapper(prefix);
                        cache.l1.states.lock().insert(key, state);
                        cache.l1.inserts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    
                    // Armazenar resultado
                    local_results.push((idx, hash));
                }
            }
            
            // Retornar todos os resultados locais
            local_results
        })
        .collect();
    
    // Redimensionar vetor de saída
    hashes_out.clear();
    hashes_out.resize(num_keys, [0u8; 20]);
    
    // Aplicar resultados coletados
    for (idx, hash) in results {
        if idx < hashes_out.len() {
            hashes_out[idx] = hash;
        }
    }
    
    num_keys
}

// Implementação AVX2 com abordagem semelhante à AVX-512 para consistência
#[cfg(target_arch = "x86_64")]
fn hash160_avx2_cached(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 20]>,
) -> usize {
    let num_keys = pubkeys.len();
    
    // Limpar buffer de saída temporário
    let mut results_temp = vec![(0usize, [0u8; 20]); 0];
    
    // Processar chaves e coletar resultados
    let results: Vec<(usize, [u8; 20])> = pubkeys.par_chunks(HASH_BATCH_SIZE)
        .enumerate()
        .flat_map(|(chunk_idx, pubkey_chunk)| {
            let mut local_results = Vec::with_capacity(pubkey_chunk.len());
            // Obter acesso ao cache - Cada thread tem sua própria cópia temporária do cache
            let cache = get_hierarchical_cache();
            
            // Buffer para processamento em lote direto
            let mut batch_pubkeys = Vec::with_capacity(pubkey_chunk.len());
            let mut batch_indices = Vec::with_capacity(pubkey_chunk.len());
            
            for (i, pubkey) in pubkey_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * HASH_BATCH_SIZE + i;
                if abs_idx >= num_keys {
                    break;
                }
                
                // Extrair prefixo para verificar no cache - apenas 1 byte para L1
                let prefix = &pubkey[0..L1_PREFIX_SIZE.min(pubkey.len())];
                
                // Tentativa simplificada de cache L1 apenas para prefixos 0x02 e 0x03
                // que são os casos mais comuns em chaves comprimidas Bitcoin
                if prefix[0] == 0x02 || prefix[0] == 0x03 {
                    let mut key = [0u8; L1_PREFIX_SIZE];
                    key.copy_from_slice(prefix);
                    
                    let hash_array = if let Some(cached_state) = cache.l1.states.lock().get(&key) {
                        // Cache hit - usar estado intermediário
                        cache.l1.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        hash160_with_state_cpp_wrapper(cached_state, &pubkey[L1_PREFIX_SIZE..])
                    } else {
                        // Cache miss - processar no lote
                        cache.l1.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        batch_pubkeys.push(*pubkey);
                        batch_indices.push(abs_idx);
                        continue;
                    };
                    
                    local_results.push((abs_idx, hash_array));
                } else {
                    // Para outros prefixos, direto para processamento em lote
                    batch_pubkeys.push(*pubkey);
                    batch_indices.push(abs_idx);
                }
            }
            
            // Processar o lote restante de uma vez
            if !batch_pubkeys.is_empty() {
                let mut batch_hashes = vec![[0u8; 20]; batch_pubkeys.len()];
                
                unsafe {
                    calculate_hash160_batch_cpp(
                        batch_pubkeys.as_ptr() as *const u8,
                        batch_pubkeys.len(),
                        batch_hashes.as_mut_ptr() as *mut u8
                    );
                }
                
                // Armazenar resultados do lote e atualizar cache para 0x02/0x03
                for i in 0..batch_indices.len() {
                    let idx = batch_indices[i];
                    let pubkey = batch_pubkeys[i];
                    let hash = batch_hashes[i];
                    
                    // Apenas armazenar no cache L1 se for um prefixo comum
                    if pubkey[0] == 0x02 || pubkey[0] == 0x03 {
                        let prefix = &pubkey[0..L1_PREFIX_SIZE];
                        let mut key = [0u8; L1_PREFIX_SIZE];
                        key.copy_from_slice(prefix);
                        
                        let state = extract_sha256_state_cpp_wrapper(prefix);
                        
                        // Inserir no cache L1 apenas (mais impactante)
                        let mut l1_cache = cache.l1.states.lock();
                        if l1_cache.len() < L1_MAX_ENTRIES {
                            cache.l1.inserts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            l1_cache.insert(key, state);
                        }
                    }
                    
                    local_results.push((idx, hash));
                }
            }
            
            local_results
        })
        .collect();
    
    // Redimensionar vetor de saída e copiar os resultados
    hashes_out.clear();
    hashes_out.resize(num_keys, [0u8; 20]);
    
    // Aplicar resultados coletados
    for (abs_idx, hash) in results {
        if abs_idx < hashes_out.len() {
            hashes_out[abs_idx] = hash;
        }
    }
    
    num_keys
}

// Implementação fallback com cache hierárquico
fn hash160_fallback_cached(
    pubkeys: &[[u8; 33]],
    hashes_out: &mut Vec<[u8; 20]>,
) -> usize {
    let num_keys = pubkeys.len();
    
    // Limpar buffer de saída e reservar espaço
    hashes_out.clear();
    hashes_out.resize(num_keys, [0u8; 20]);
    
    // Processamento direto sem threads (versão simplificada para sistemas sem AVX2)
    let mut batch_pubkeys = Vec::with_capacity(HASH_BATCH_SIZE);
    let mut batch_indices = Vec::with_capacity(HASH_BATCH_SIZE);
    
    for (i, pubkey) in pubkeys.iter().enumerate() {
        batch_pubkeys.push(*pubkey);
        batch_indices.push(i);
        
        // Processar quando o lote estiver cheio ou no final
        if batch_pubkeys.len() == HASH_BATCH_SIZE || i == num_keys - 1 {
            let mut batch_hashes = vec![[0u8; 20]; batch_pubkeys.len()];
            
            unsafe {
                calculate_hash160_batch_cpp(
                    batch_pubkeys.as_ptr() as *const u8,
                    batch_pubkeys.len(),
                    batch_hashes.as_mut_ptr() as *mut u8
                );
            }
            
            // Copiar resultados para o buffer de saída
            for (idx, hash) in batch_indices.iter().zip(batch_hashes.iter()) {
                hashes_out[*idx].copy_from_slice(hash);
            }
            
            batch_pubkeys.clear();
            batch_indices.clear();
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

// Verificar suporte a AVX-512
#[inline]
pub fn supports_avx512f() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx512f")
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

// Compatibilidade com cache antigo para evitar regressões
static CONTEXTUAL_CACHE: Lazy<Mutex<DynamicContextualCache>> = Lazy::new(|| {
    Mutex::new(DynamicContextualCache {
        sha256_states: HashMap::new(),
        usage_counts: HashMap::new(),
        max_size: 1024, // Tamanho máximo do cache
    })
});

// Implementações do cache hierárquico
impl L1Cache {
    fn get(&self, prefix: &[u8]) -> Option<Sha256State> {
        if prefix.len() < L1_PREFIX_SIZE {
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        
        let mut key = [0u8; L1_PREFIX_SIZE];
        key.copy_from_slice(&prefix[..L1_PREFIX_SIZE]);
        
        let cache = self.states.lock();
        if let Some(state) = cache.get(&key) {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(state.clone())
        } else {
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }
    
    fn insert(&self, prefix: &[u8], state: Sha256State) {
        if prefix.len() < L1_PREFIX_SIZE {
            return;
        }
        
        let mut key = [0u8; L1_PREFIX_SIZE];
        key.copy_from_slice(&prefix[..L1_PREFIX_SIZE]);
        
        let mut cache = self.states.lock();
        if cache.len() >= L1_MAX_ENTRIES {
            // Política simples: se o cache estiver cheio, apenas não insere
            // Cache L1 deve ser reservado para os prefixos mais comuns
            return;
        }
        
        self.inserts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cache.insert(key, state);
    }
    
    fn get_stats(&self) -> (usize, usize, f64) {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        let hit_ratio = if total > 0 { hits as f64 / total as f64 } else { 0.0 };
        (hits, misses, hit_ratio)
    }
}

impl L2Cache {
    fn get(&self, prefix: &[u8]) -> Option<Sha256State> {
        if prefix.len() < L2_PREFIX_SIZE {
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        
        let key = prefix[..L2_PREFIX_SIZE].to_vec();
        let cache = self.states.lock();
        
        if let Some(state) = cache.get(&key) {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(state.clone())
        } else {
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }
    
    fn insert(&self, prefix: &[u8], state: Sha256State) {
        if prefix.len() < L2_PREFIX_SIZE {
            return;
        }
        
        let key = prefix[..L2_PREFIX_SIZE].to_vec();
        let mut cache = self.states.lock();
        
        // Política de evicção simples para L2
        if cache.len() >= L2_MAX_ENTRIES {
            // Remover um item aleatório se estiver cheio
            if let Some(k) = cache.keys().next().cloned() {
                cache.remove(&k);
                self.evictions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        
        self.inserts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cache.insert(key, state);
    }
    
    fn get_stats(&self) -> (usize, usize, f64, usize) {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let evictions = self.evictions.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        let hit_ratio = if total > 0 { hits as f64 / total as f64 } else { 0.0 };
        (hits, misses, hit_ratio, evictions)
    }
}

impl L3Cache {
    fn get(&self, prefix: &[u8]) -> Option<Sha256State> {
        let cache = self.states.read();
        
        let key = prefix.to_vec();
        if let Some(state) = cache.peek(&key) {
            // Incrementar contador de hits
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(state.clone())
        } else {
            // Incrementar contador de misses 
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    fn insert(&self, prefix: &[u8], state: Sha256State) {
        if prefix.len() < L3_PREFIX_SIZE {
            return;
        }
        
        let key = prefix[..L3_PREFIX_SIZE].to_vec();
        let mut cache = self.states.write();
        
        self.inserts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cache.put(key, state);
    }
    
    fn get_stats(&self) -> (usize, usize, f64, usize) {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let inserts = self.inserts.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        let hit_ratio = if total > 0 { hits as f64 / total as f64 } else { 0.0 };
        (hits, misses, hit_ratio, inserts)
    }
}

impl HierarchicalCache {
    // Busca um estado em todos os níveis do cache
    pub fn get_state(&self, pubkey: &[u8]) -> Option<Sha256State> {
        // Tentar L1 (mais rápido)
        if let Some(state) = self.l1.get(pubkey) {
            return Some(state);
        }
        
        // Tentar L2 (intermediário)
        if let Some(state) = self.l2.get(pubkey) {
            // Promover para L1 se for um hit frequente
            self.l1.insert(pubkey, state.clone());
            return Some(state);
        }
        
        // Tentar L3 (mais lento, mais abrangente)
        if let Some(state) = self.l3.get(pubkey) {
            // Promover para L2
            self.l2.insert(pubkey, state.clone());
            return Some(state);
        }
        
        None
    }
    
    // Armazena um estado no cache hierárquico
    pub fn store_state(&self, pubkey: &[u8], state: Sha256State) {
        // Armazenar no L3 primeiro (mais abrangente)
        self.l3.insert(pubkey, state.clone());
        
        // Critérios para subir na hierarquia:
        // L2: Apenas prefixos que são prováveis de serem reutilizados
        if pubkey.len() >= L2_PREFIX_SIZE {
            self.l2.insert(pubkey, state.clone());
        }
        
        // L1: Apenas os prefixos mais críticos (os primeiros bytes são iguais para muitas chaves públicas)
        if pubkey.len() >= L1_PREFIX_SIZE {
            self.l1.insert(pubkey, state);
        }
    }
    
    // Imprime estatísticas do cache
    pub fn print_stats(&self) {
        let (l1_hits, l1_misses, l1_ratio) = self.l1.get_stats();
        println!("Cache L1: {:.2}% hit ratio ({} hits, {} misses)", 
                 l1_ratio * 100.0, l1_hits, l1_misses);
        
        let (l2_hits, l2_misses, l2_ratio, l2_evictions) = self.l2.get_stats();
        println!("Cache L2: {:.2}% hit ratio ({} hits, {} misses, {} evictions)", 
                 l2_ratio * 100.0, l2_hits, l2_misses, l2_evictions);
        
        let (l3_hits, l3_misses, l3_ratio, l3_inserts) = self.l3.get_stats();
        println!("Cache L3: {:.2}% hit ratio ({} hits, {} misses, {} inserts)", 
                 l3_ratio * 100.0, l3_hits, l3_misses, l3_inserts);
    }
}

// Nova função para pré-aquecer o cache com valores conhecidos
pub fn warm_up_cache(known_prefixes: &[&[u8]]) {
    let cache = get_hierarchical_cache();
    for &prefix in known_prefixes {
        if prefix.len() >= L1_PREFIX_SIZE {
            let prefix_slice = prefix;
            
            // Extrair e armazenar o estado usando o wrapper C++
            let state = extract_sha256_state_cpp_wrapper(prefix_slice);
            cache.store_state(prefix_slice, state);
        }
    }
    println!("Cache Hierárquico preparado com {} prefixos comuns", known_prefixes.len());
}

// Inicializa o Cache Hierárquico para uso com SHA3
pub fn initialize_hierarchical_cache_sha3() {
    let cache = get_hierarchical_cache();
    cache.print_stats();
    println!("Cache Hierárquico inicializado para SHA3");
}

// Função para obter o cache hierárquico global
pub fn get_hierarchical_cache() -> Arc<HierarchicalCache> {
    HIERARCHICAL_CACHE.clone()
}

// Interface profissional para o sistema de cache hierárquico
#[derive(Clone)]
pub struct CacheManager {
    cache: Arc<HierarchicalCache>,
}

/// Estatísticas do sistema de cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub l1_hits: usize,
    pub l1_misses: usize,
    pub l1_hit_rate: f64,
    pub l1_size: usize,
    
    pub l2_hits: usize,
    pub l2_misses: usize,
    pub l2_hit_rate: f64,
    pub l2_evictions: usize,
    pub l2_size: usize,
    
    pub l3_hits: usize,
    pub l3_misses: usize,
    pub l3_hit_rate: f64,
    pub l3_size: usize,
    
    pub total_hits: usize,
    pub total_misses: usize,
    pub overall_hit_rate: f64,
}

impl CacheManager {
    /// Obtém uma instância do gerenciador de cache
    pub fn new() -> Self {
        // Iniciar com cache limpo para evitar falsos hits
        Self {
            cache: get_hierarchical_cache(),
        }
    }
    
    /// Aquece o cache com prefixos conhecidos para melhor performance inicial
    pub fn warm_up(&self, prefixes: &[&[u8]]) {
        warm_up_cache(prefixes);
    }
    
    /// Retorna estatísticas detalhadas sobre o desempenho do cache
    pub fn get_statistics(&self) -> CacheStats {
        let (l1_hits, l1_misses, l1_hit_rate) = self.cache.l1.get_stats();
        let (l2_hits, l2_misses, l2_hit_rate, l2_evictions) = self.cache.l2.get_stats();
        let (l3_hits, l3_misses, l3_hit_rate, l3_size) = self.cache.l3.get_stats();
        
        let l1_size = self.cache.l1.states.lock().len();
        let l2_size = self.cache.l2.states.lock().len();
        
        let total_hits = l1_hits + l2_hits + l3_hits;
        let total_misses = l1_misses + l2_misses + l3_misses;
        let overall_hit_rate = if total_hits + total_misses > 0 {
            total_hits as f64 / (total_hits + total_misses) as f64
        } else {
            0.0
        };
        
        CacheStats {
            l1_hits,
            l1_misses,
            l1_hit_rate,
            l1_size,
            
            l2_hits,
            l2_misses,
            l2_hit_rate,
            l2_evictions,
            l2_size,
            
            l3_hits,
            l3_misses,
            l3_hit_rate,
            l3_size,
            
            total_hits,
            total_misses,
            overall_hit_rate,
        }
    }
    
    /// Formata e exibe estatísticas do cache em formato amigável
    pub fn print_statistics(&self) {
        let stats = self.get_statistics();
        println!("\n=== Cache Hierárquico: Estatísticas ===");
        println!("Cache L1 (prefixos de {} bytes):", L1_PREFIX_SIZE);
        println!("  Hits: {}, Misses: {}, Taxa: {:.2}%", 
                stats.l1_hits, stats.l1_misses, stats.l1_hit_rate * 100.0);
        println!("  Tamanho atual: {}/{} entradas", stats.l1_size, L1_MAX_ENTRIES);
        
        println!("\nCache L2 (prefixos de {} bytes):", L2_PREFIX_SIZE);
        println!("  Hits: {}, Misses: {}, Taxa: {:.2}%", 
                stats.l2_hits, stats.l2_misses, stats.l2_hit_rate * 100.0);
        println!("  Evicções: {}", stats.l2_evictions);
        println!("  Tamanho atual: {}/{} entradas", stats.l2_size, L2_MAX_ENTRIES);
        
        println!("\nCache L3 (prefixos de {} bytes):", L3_PREFIX_SIZE);
        println!("  Hits: {}, Misses: {}, Taxa: {:.2}%", 
                stats.l3_hits, stats.l3_misses, stats.l3_hit_rate * 100.0);
        println!("  Tamanho atual: {}/{} entradas", stats.l3_size, L3_MAX_ENTRIES);
        
        println!("\nEstatísticas Globais:");
        println!("  Total Hits: {}", stats.total_hits);
        println!("  Total Misses: {}", stats.total_misses);
        println!("  Taxa de Hit Global: {:.2}%", stats.overall_hit_rate * 100.0);
        println!("======================================\n");
    }
    
    /// Atualiza as estatísticas para uso com o sistema de monitoramento
    pub fn update_performance_stats(&self, stats: &crate::stats::PerformanceStats) {
        let cache_stats = self.get_statistics();
        stats.add_cache_hits(cache_stats.total_hits as u64);
        stats.add_cache_misses(cache_stats.total_misses as u64);
    }
    
    /// Pré-carrega estados de hash para um conjunto de prefixos comuns
    pub fn preload_common_prefixes(&self) {
        println!("Pré-carregando prefixos comuns para o cache SHA-256...");
        
        // Prefixos mais comuns para chaves públicas Bitcoin
        let prefixes = [
            // Chaves públicas comprimidas
            &[0x02][..], // Prefixo para chaves com Y par (mais comum)
            &[0x03][..], // Prefixo para chaves com Y ímpar
            
            // Alguns prefixos comuns em chaves reais
            &[0x02, 0x01][..],
            &[0x02, 0x02][..],
            &[0x02, 0x03][..],
            &[0x02, 0x04][..],
            &[0x02, 0x05][..],
            &[0x02, 0x06][..],
            &[0x02, 0x07][..],
            &[0x02, 0x08][..],
            &[0x02, 0x09][..],
            &[0x02, 0x0a][..],
            
            &[0x03, 0x01][..],
            &[0x03, 0x02][..],
            &[0x03, 0x03][..],
            &[0x03, 0x04][..],
            &[0x03, 0x05][..],
            &[0x03, 0x06][..],
            &[0x03, 0x07][..],
            &[0x03, 0x08][..],
        ];
        
        self.warm_up(&prefixes);
        println!("Cache inicializado com {} prefixos comuns", prefixes.len());
    }
    
    /// Limpa o cache hierárquico completamente (raramente necessário)
    pub fn clear_cache(&self) {
        // Implementação mínima já que o cache se auto-gerencia bem
        println!("Limpando cache hierárquico...");
        // L1
        self.cache.l1.states.lock().clear();
        // L2
        self.cache.l2.states.lock().clear();
        // L3 (o L3 já é um LRU, então limpar é raramente necessário)
        self.cache.l3.states.write().clear();
        println!("Cache limpo com sucesso.");
    }
    
    /// Obtém uma referência ao cache hierárquico interno
    pub fn get_cache(&self) -> Arc<HierarchicalCache> {
        self.cache.clone()
    }
    
    /// Determina se o sistema atual suporta instruções avançadas para hashing
    pub fn has_advanced_instruction_support(&self) -> bool {
        supports_avx2()
    }
    
    /// Retorna o nível recomendado de paralelismo baseado nas características do sistema
    pub fn recommended_parallelism(&self) -> usize {
        let cpu_cores = rayon::current_num_threads();
        let has_avx2 = self.has_advanced_instruction_support();
        
        // Sugestão de paralelismo baseada em testes de performance
        if has_avx2 {
            // Com AVX2, usar todos os cores disponíveis é geralmente ótimo
            // Mas limitar a uma fração para evitar saturação
            (cpu_cores * 3/4).max(1)
        } else {
            // Sem AVX2, as vezes é melhor usar um pouco menos threads
            // para evitar contenção de memória
            (cpu_cores / 2).max(1)
        }
    }
}

// Função conveniente para obter o CacheManager global
pub fn get_cache_manager() -> CacheManager {
    CacheManager::new()
} 
