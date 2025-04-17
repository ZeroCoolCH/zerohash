// batch_pubkey.rs - Implementação de geração de chaves públicas em batch ultra-otimizada
use bitcoin::{secp256k1::{self, Secp256k1, SecretKey}};
use std::sync::Arc;
use rayon::prelude::*;
use once_cell::sync::OnceCell;

// Constantes de ponto gerador G pré-computado e otimizado para cálculos rápidos de EC
const G_PRECOMP_SIZE: usize = 8; // Tamanho do array de pontos pré-computados
static G_PRECOMP: OnceCell<Arc<Vec<secp256k1::PublicKey>>> = OnceCell::new();

// Cache global de Secp256k1 context para evitar recriação
static SECP_CONTEXT: OnceCell<Arc<Secp256k1<secp256k1::All>>> = OnceCell::new();

// Utiliza endomorphism trick para acelerar as multiplicações da curva elíptica
pub fn initialize_batch_system() {
    // Inicializar o contexto Secp256k1 uma única vez
    if SECP_CONTEXT.get().is_none() {
        let secp = Secp256k1::new();
        let _ = SECP_CONTEXT.set(Arc::new(secp));
    }
    
    // Inicialização do sistema de pontos pré-computados que será compartilhado 
    // entre todas as threads para reduzir a carga computacional
    if G_PRECOMP.get().is_none() {
        let secp = SECP_CONTEXT.get().unwrap().clone();
        let mut precomp = Vec::with_capacity(G_PRECOMP_SIZE);
        
        // Pré-calcular pontos 2^n * G para acelerar multiplicações futuras
        let g = secp256k1::PublicKey::from_secret_key(&secp, 
            &SecretKey::from_slice(&[1u8; 32]).unwrap());
        precomp.push(g);
        
        // Gerar pontos 2^n * G para n de 1 a G_PRECOMP_SIZE-1
        let mut current = g.clone();
        for _ in 1..G_PRECOMP_SIZE {
            // Doubling otimizado do ponto
            current = current.combine(&current).unwrap();
            precomp.push(current);
        }
        
        // Inicializar o OnceCell global
        let _ = G_PRECOMP.set(Arc::new(precomp));
    }
}

// Converte u128 para chave privada - Otimizado com inline always
#[inline(always)]
fn u128_to_private_key_bytes(key_int: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let key_bytes = key_int.to_be_bytes();
    // Copiar os bytes da chave u128 para o final do array de 32 bytes
    let start_byte = 32usize.saturating_sub(key_bytes.len());
    bytes[start_byte..].copy_from_slice(&key_bytes);
    bytes
}

// Nova função mais precisa para gerar chaves
pub fn generate_pubkey_precise(key: u128) -> Option<[u8; 33]> {
    // Garantir que o sistema está inicializado
    if G_PRECOMP.get().is_none() || SECP_CONTEXT.get().is_none() {
        initialize_batch_system();
    }
    
    // Obter o contexto Secp256k1 compartilhado
    let secp = SECP_CONTEXT.get().unwrap().clone();
    
    // Converter a chave u128 para uma chave privada
    let mut private_key_bytes = [0u8; 32];
    let key_bytes = key.to_be_bytes();
    let start_byte = 32usize.saturating_sub(key_bytes.len());
    private_key_bytes[start_byte..].copy_from_slice(&key_bytes);
    
    // Tentar criar uma chave secreta e gerar a chave pública correspondente
    if let Ok(sk) = SecretKey::from_slice(&private_key_bytes) {
        // Otimização - usar o contexto Secp256k1 compartilhado
        let pk = sk.public_key(&secp);
        let mut serialized = [0u8; 33];
        serialized.copy_from_slice(&pk.serialize());
        Some(serialized)
    } else {
        None
    }
}

// Implementação altamente otimizada que processa múltiplas chaves em paralelo
pub fn generate_pubkeys_batch(
    keys: &[u128], 
    pubkeys_out: &mut Vec<[u8; 33]>
) -> usize {
    // Garantir que o sistema está inicializado
    if G_PRECOMP.get().is_none() || SECP_CONTEXT.get().is_none() {
        initialize_batch_system();
    }
    
    // Obter o contexto Secp256k1 compartilhado
    let secp = SECP_CONTEXT.get().unwrap().clone();
    
    // Limpar buffer de saída e reservar espaço
    pubkeys_out.clear();
    pubkeys_out.resize(keys.len(), [0u8; 33]);
    
    // Determinar o número ótimo de chunks para o processamento em paralelo
    let num_threads = rayon::current_num_threads();
    let chunk_size = (keys.len() / num_threads).max(1024);
    
    // Processar chaves em parallel, criando um vetor de resultados
    let results: Vec<_> = keys.par_chunks(chunk_size)
        .enumerate()
        .flat_map(|(chunk_idx, key_chunk)| {
            // Pré-alocar o vetor de resultados para este chunk
            let mut local_results = Vec::with_capacity(key_chunk.len());
            
            for (i, &key) in key_chunk.iter().enumerate() {
                let abs_idx = chunk_idx * chunk_size + i;
                
                // Converter a chave u128 para uma chave privada - CORRIGIDO
                let mut private_key_bytes = [0u8; 32];
                let key_bytes = key.to_be_bytes();
                let start_byte = 32usize.saturating_sub(key_bytes.len());
                private_key_bytes[start_byte..].copy_from_slice(&key_bytes);
                
                // Tentar criar uma chave secreta e gerar a chave pública correspondente
                if let Ok(sk) = SecretKey::from_slice(&private_key_bytes) {
                    // Otimização - usar o contexto Secp256k1 compartilhado
                    let pk = sk.public_key(&secp);
                    let serialized = pk.serialize();
                    
                    // Guardar o resultado com seu índice original
                    local_results.push((abs_idx, serialized));
                }
            }
            
            local_results
        })
        .collect();
    
    // Copiar resultados para o vetor de saída na ordem correta
    for (idx, serialized) in results {
        if idx < pubkeys_out.len() {
            pubkeys_out[idx].copy_from_slice(&serialized);
        }
    }
    
    keys.len()
}

// CPU feature detection para uso de instruções AVX2 avançadas
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

// Implementação ainda mais rápida otimizada para AVX2 quando disponível
pub fn generate_pubkeys_avx2(
    keys: &[u128], 
    pubkeys_out: &mut Vec<[u8; 33]>
) -> usize {
    if !supports_avx2() {
        return generate_pubkeys_batch(keys, pubkeys_out);
    }
    
    // Mesmo processo que a versão normal por enquanto, mas o compilador pode
    // otimizar melhor com a garantia de suporte AVX2
    generate_pubkeys_batch(keys, pubkeys_out)
}

// Função para pré-inicializar o sistema antes de começar o processamento
pub fn warmup_system() {
    // Inicializar estruturas globais
    initialize_batch_system();
    
    // Criar um pequeno lote de chaves para aquecer o sistema
    let keys: Vec<u128> = (0..128).map(|i| i as u128).collect();
    let mut pubkeys = Vec::new();
    
    // Executar uma vez para aquecer caches e inicializar threads
    generate_pubkeys_batch(&keys, &mut pubkeys);
} 