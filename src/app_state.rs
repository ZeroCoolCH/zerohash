use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use atomic::Atomic;
use std::sync::{Mutex, Arc};
use std::time::{Instant};
use std::fs::OpenOptions;
use std::io::Write;
use bitcoin::Network;
use once_cell::sync::OnceCell;

// Variável estática para armazenar a última instância do AppState
static CURRENT_APP_STATE: Mutex<Option<Arc<AppState>>> = Mutex::new(None);

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
    pub start_time: Mutex<Option<Instant>>,
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
    
    // --- Adicionado para modo aleatório ---
    pub random_mode: AtomicBool,
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
            start_time: Mutex::new(None),
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
            
            // --- Inicializar modo aleatório como false ---
            random_mode: AtomicBool::new(false),
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
        *self.start_time.lock().unwrap() = Some(time);
    }

    pub fn get_elapsed_time(&self) -> Option<std::time::Duration> {
        self.start_time.lock().unwrap().map(|start| start.elapsed())
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
        zero_prefix_length: usize,
        random_mode: bool,
    ) {
        *self.range_start.lock().unwrap() = range_start;
        *self.range_end.lock().unwrap() = range_end;
        *self.num_threads.lock().unwrap() = num_threads;
        *self.resume.lock().unwrap() = resume;
        *self.progress_file.lock().unwrap() = progress_file.to_string();
        *self.zero_prefix_length.lock().unwrap() = zero_prefix_length;
        
        // Em vez de tentar modificar o cache diretamente, vamos apenas marcá-lo como inválido
        // forçando a recriação na próxima chamada a initialize_hash_target_cache
        // self.hash_target_cache.take(); // Comentado pois requer &mut self
        
        // Atualizar modo aleatório
        self.random_mode.store(random_mode, Ordering::Relaxed);
    }
    
    // Verifica se um hash corresponde ao hash alvo atual
    pub fn check_hash_match(&self, hash: &[u8]) -> bool {
        // Usar o cache de hash para uma melhor performance
        if let Some(_cache) = self.hash_target_cache.get() {
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
        } else {
            // Implementação de fallback caso o cache não esteja disponível
            let target_hash = self.get_target_hash();
            
            // Verificar se é um hash exato
            if target_hash != [0u8; 20] {
                // Comparação direta byte a byte para hash exato
                if hash.len() != 20 {
                    return false;
                }
                
                for i in 0..20 {
                    if hash[i] != target_hash[i] {
                        return false;
                    }
                }
                
                return true;
            } else {
                // Verificação de prefixo zero
                let zero_prefix_length = *self.zero_prefix_length.lock().unwrap();
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
                
                return true;
            }
        }
    }
    
    // Renomeado para corresponder ao erro de compilação
    pub fn get_target_hash(&self) -> [u8; 20] {
        *self.target_pubkey_hash.lock().unwrap()
    }
    // Adicionar alias para manter compatibilidade onde era chamado get_target_hash160
    pub fn get_target_hash160(&self) -> [u8; 20] {
        self.get_target_hash()
    }

    // ... is_search_active() ...

    // ... was_key_found() ...

    // ... get_keys_processed() ...

    // ... get_hashes_calculated() ...

    // Renomeado para corresponder ao erro de compilação
    pub fn get_progress_file(&self) -> String {
        self.progress_file.lock().unwrap().clone()
    }
    // Adicionar alias para manter compatibilidade onde era chamado get_progress_file_path
     pub fn get_progress_file_path(&self) -> String {
         self.get_progress_file()
     }

    // Renomeado para corresponder ao erro de compilação
    pub fn get_results_file(&self) -> String {
        self.results_file.lock().unwrap().clone()
    }
    // Adicionar alias para manter compatibilidade onde era chamado get_results_file_path
    pub fn get_results_file_path(&self) -> String {
         self.get_results_file()
     }

    // Renomeado para corresponder ao erro de compilação
    pub fn get_network_config(&self) -> Network {
        *self.network.lock().unwrap()
    }
    // Adicionar alias para manter compatibilidade onde era chamado get_network
    pub fn get_network(&self) -> Network {
         self.get_network_config()
     }

    // Renomeado para corresponder ao erro de compilação
    pub fn get_start_range(&self) -> u128 {
        *self.range_start.lock().unwrap()
    }
    // Adicionar alias para manter compatibilidade onde era chamado get_range_start
    pub fn get_range_start(&self) -> u128 {
        self.get_start_range()
    }

    // Renomeado para corresponder ao erro de compilação
    pub fn get_end_range(&self) -> u128 {
        *self.range_end.lock().unwrap()
    }
    // Adicionar alias para manter compatibilidade onde era chamado get_range_end
     pub fn get_range_end(&self) -> u128 {
        self.get_end_range()
     }

    // Renomeado para corresponder ao erro de compilação
    pub fn get_thread_count(&self) -> usize {
        *self.num_threads.lock().unwrap()
    }
    // Adicionar alias para manter compatibilidade onde era chamado get_num_threads
     pub fn get_num_threads(&self) -> usize {
        self.get_thread_count()
     }

    // Renomeado para corresponder ao erro de compilação
    pub fn get_resume_flag(&self) -> bool {
        *self.resume.lock().unwrap()
    }
    // Adicionar alias para manter compatibilidade onde era chamado should_resume
    pub fn should_resume(&self) -> bool {
         self.get_resume_flag()
     }

    // Armazena a instância do AppState para acesso global
    pub fn set_as_current(app_state: Arc<AppState>) {
        if let Ok(mut current) = CURRENT_APP_STATE.lock() {
            *current = Some(app_state);
        }
    }
    
    // Obtém a instância atual do AppState, se disponível
    pub fn get_current() -> Option<Arc<AppState>> {
        if let Ok(current) = CURRENT_APP_STATE.lock() {
            current.clone()
        } else {
            None
        }
    }
}

// Função pública para acessar o AppState atual de qualquer módulo
pub fn get_current_app_state() -> Option<Arc<AppState>> {
    AppState::get_current()
} 