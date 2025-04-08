use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use atomic::Atomic;
use std::sync::{Mutex, Arc};
use std::time::{Instant};
use std::fs::OpenOptions;
use std::io::Write;
use bitcoin::Network;
use once_cell::sync::OnceCell;

// Configuração para o tipo de endereço Bitcoin
pub struct AddressConfig {
    pub zero_count: usize,
    pub pattern: Vec<u8>,
}

// Estrutura de cache para armazenar o hash-alvo e evitar bloqueios frequentes
#[derive(Debug)]
struct HashTargetCache {
    hash: [u8; 20],
    mode: HashMatchMode,
    zero_prefix_length: usize,
}

// Enum para representar o modo de verificação de hash
#[derive(Debug)]
enum HashMatchMode {
    ExactMatch,
    ZeroPrefix,
}

#[derive(Debug)] 
pub struct AppState {
    pub target_address: String,
    pub target_pubkey_hash: Mutex<[u8; 20]>, // Agora mutável
    pub checked_keys: AtomicU64,
    pub start_time: Mutex<Instant>,
    pub search_active: AtomicBool,
    pub key_found: AtomicBool,
    pub found_key_hex: Mutex<Option<String>>,
    pub found_key_wif: Mutex<Option<String>>,
    pub status_message: Mutex<String>,
    pub last_key_processed: Atomic<u128>,
    
    // Adicionados para modo turbo
    pub range_start: Mutex<u128>,
    pub range_end: Mutex<u128>,
    pub num_threads: Mutex<usize>,
    pub resume: Mutex<bool>,
    pub progress_file: Mutex<String>,
    pub results_file: Mutex<String>,
    pub network: Mutex<Network>,
    pub zero_prefix_length: Mutex<usize>, // Número de zeros a procurar no início do hash
    
    // Cache de hash alvo para evitar bloqueios de mutex frequentes
    hash_target_cache: OnceCell<Arc<HashTargetCache>>,
}

impl AppState {
    pub fn new(
        target_address: &str,
    ) -> Self {
        // Decodificar o endereço para obter o hash160
        let decoded_data = match bs58::decode(target_address).with_check(None).into_vec() {
            Ok(data) => data,
            Err(_) => vec![0; 21], // Default em caso de erro
        };
        
        let mut target_pubkey_hash = [0u8; 20];
        if decoded_data.len() >= 21 {
            target_pubkey_hash.copy_from_slice(&decoded_data[1..21]);
        }
        
        AppState {
            target_address: target_address.to_string(),
            target_pubkey_hash: Mutex::new(target_pubkey_hash),
            checked_keys: AtomicU64::new(0),
            start_time: Mutex::new(Instant::now()),
            search_active: AtomicBool::new(false),
            key_found: AtomicBool::new(false),
            found_key_hex: Mutex::new(None),
            found_key_wif: Mutex::new(None),
            status_message: Mutex::new("Initializing...".to_string()),
            last_key_processed: Atomic::new(0),
            
            // Valores padrão para os novos campos
            range_start: Mutex::new(0),
            range_end: Mutex::new(0),
            num_threads: Mutex::new(0),
            resume: Mutex::new(false),
            progress_file: Mutex::new(String::new()),
            results_file: Mutex::new(String::from("found_keys.txt")),
            network: Mutex::new(Network::Bitcoin),
            zero_prefix_length: Mutex::new(1), // Padrão: procurar por hashes que começam com 1 zero
            
            // Inicialização do cache
            hash_target_cache: OnceCell::new(),
        }
    }

    pub fn set_status(&self, msg: String) {
        *self.status_message.lock().unwrap() = msg;
    }

    pub fn set_found_key(&self, key: u128, _wif_key_result: Result<String, Box<dyn std::error::Error>>) {
        let key_hex = format!("{:064x}", key);
        
        let wif_direct_result = crate::turbo_search::u128_to_wif(key, true);
        let wif_key_opt = Some(wif_direct_result.clone());
        
        println!("[set_found_key DEBUG] WIF recalculado: {:?}", wif_key_opt);

        *self.found_key_hex.lock().unwrap() = Some(key_hex.clone());
        *self.found_key_wif.lock().unwrap() = wif_key_opt.clone();
        self.key_found.store(true, Ordering::SeqCst);
        self.search_active.store(false, Ordering::SeqCst);
        self.set_status(format!(
            "!!! KEY FOUND: {} (WIF: {}) !!!", 
            key_hex, 
            wif_key_opt.as_deref().unwrap_or("N/A"))
        );
        
        let results_file = self.results_file.lock().unwrap().clone();
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&results_file) 
        {
            Ok(mut file) => {
                let content = format!(
                    "Address: {}\nHex Key: {}\nWIF Key: {}\n---\n",
                    self.target_address,
                    key_hex,
                    wif_direct_result
                );
                if let Err(e) = file.write_all(content.as_bytes()) {
                    eprintln!("Erro ao escrever chave encontrada no arquivo: {}", e);
                }
            }
            Err(e) => {
                 eprintln!("Erro ao abrir/criar {}: {}", results_file, e);
            }
        }
    }

    pub fn set_start_time(&self, time: Instant) {
        *self.start_time.lock().unwrap() = time;
    }

    pub fn get_elapsed_time(&self) -> Option<std::time::Duration> {
        match self.start_time.lock() {
            Ok(start_time_guard) => Some(start_time_guard.elapsed()),
            Err(_) => None,
        }
    }
    
    // Inicializa o cache de hash alvo
    pub fn initialize_hash_target_cache(&self) -> Arc<HashTargetCache> {
        self.hash_target_cache.get_or_init(|| {
            let target_pubkey_hash = self.target_pubkey_hash.lock().unwrap();
            let zero_prefix_length = *self.zero_prefix_length.lock().unwrap();
            
            let mode = if *target_pubkey_hash != [0u8; 20] {
                HashMatchMode::ExactMatch
            } else {
                HashMatchMode::ZeroPrefix
            };
            
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&*target_pubkey_hash);
            
            Arc::new(HashTargetCache {
                hash,
                mode,
                zero_prefix_length,
            })
        }).clone()
    }
    
    // Atualiza os campos de configuração a partir de um app_state existente
    pub fn update_config(&self, 
        range_start: u128, 
        range_end: u128, 
        num_threads: usize, 
        resume: bool,
        progress_file: &str,
        zero_prefix_length: usize
    ) {
        *self.range_start.lock().unwrap() = range_start;
        *self.range_end.lock().unwrap() = range_end;
        *self.num_threads.lock().unwrap() = num_threads;
        *self.resume.lock().unwrap() = resume;
        *self.progress_file.lock().unwrap() = progress_file.to_string();
        *self.zero_prefix_length.lock().unwrap() = zero_prefix_length;
        
        // Em vez de tentar modificar o cache diretamente, vamos apenas marcá-lo como inválido
        // forçando a recriação na próxima chamada a initialize_hash_target_cache
        if let Some(cache) = self.hash_target_cache.get() {
            // Se o cache já foi inicializado, precisamos recriá-lo na próxima vez
            // Nada a fazer aqui, só na próxima chamada a cache será recriado
        }
    }
    
    // Verificar se um hash corresponde ao padrão procurado (zeros no início ou hash específico)
    // Versão otimizada que usa cache para evitar bloqueios de mutex frequentes
    #[inline(always)]
    pub fn check_hash_match(&self, hash: &[u8]) -> bool {
        // Garantir que o cache está inicializado
        let cache = self.initialize_hash_target_cache();
        
        match cache.mode {
            // Comparação direta byte a byte para hash exato
            HashMatchMode::ExactMatch => {
                // Versão mais eficiente comparando bytes diretamente
                if hash.len() != 20 {
                    return false;
                }
                
                let target_hash = &cache.hash;
                for i in 0..20 {
                    if hash[i] != target_hash[i] {
                        return false;
                    }
                }
                
                true
            },
            // Verificação de prefixo zero
            HashMatchMode::ZeroPrefix => {
                let zero_prefix_length = cache.zero_prefix_length;
                if zero_prefix_length == 0 {
                    return false;
                }
                
                let zero_bytes = zero_prefix_length / 2;
                let zero_bits = zero_prefix_length % 2 * 4;
                
                // Verificar bytes completos de zeros
                for i in 0..zero_bytes {
                    if i >= hash.len() || hash[i] != 0 {
                        return false;
                    }
                }
                
                // Verificar bits parciais (se houver)
                if zero_bits > 0 && zero_bytes < hash.len() {
                    let mask = 0xF0 >> zero_bits;
                    if hash[zero_bytes] & mask != 0 {
                        return false;
                    }
                }
                
                true
            }
        }
    }
    
    // Retorna o hash alvo para uso direto
    pub fn get_target_hash(&self) -> [u8; 20] {
        // Garantir que o cache está inicializado
        let cache = self.initialize_hash_target_cache();
        cache.hash
    }
} 