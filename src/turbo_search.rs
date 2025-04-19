// turbo_search.rs - Implementação de busca de alta performance capaz de processar milhões de chaves/s
use crate::app_state::AppState;
use crate::batch_pubkey::{generate_pubkeys_batch, generate_pubkey_precise, warmup_system};
use crate::batch_hash::{
    hash160_and_match_direct, 
    warm_up_cache, 
    // Comentar importações não usadas para evitar avisos
    // batch_hash_sha3_direct, 
    // hash_sha3_and_match_direct
};
use crate::stats::{PerformanceStats, Dashboard, clear_terminal, format_hex};
use crossbeam::channel::{bounded};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering, AtomicU64, AtomicUsize};
use std::time::{Duration, Instant};
use rand::{Rng, rng};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufRead, BufReader, BufWriter};
use crossbeam::thread;
use rayon::prelude::*;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::hashes::Hash;
use bitcoin::{Address};
// Remover Network importação não utilizada
use bitcoin::hashes::{sha256};
use bs58;
use std::sync::Mutex;
use serde::{Serialize, Deserialize};
use std::path::Path;
use colored::*;
use std::fmt;

// Otimizações de batch size para melhor performance
const MEGA_BATCH_SIZE: usize = 65536;  // Reduzido para 64K para menor uso de memória
const SUB_BATCH_SIZE: usize = 16384;    // Reduzido para 16K para melhor utilização de CPU e memória
const CHANNEL_BUFFER: usize = 64;       // Aumentado para pipeline mais eficiente
const TURBO_BATCH_SIZE: usize = 32768;  // Reduzido para 32K para balancear throughput
const DYNAMIC_CHUNK_SIZE: usize = 65536; // Reduzido para 64K para melhor balanceamento em ranges grandes

// Constantes para controle de exibição e UI
const MIN_UI_UPDATE_INTERVAL_MS: u64 = 100;  // Intervalo mínimo entre atualizações da UI
const PROGRESS_SAVE_INTERVAL_MS: u64 = 3000; // Salvar progresso a cada 3 segundos

// Definir constante para o arquivo de progresso
pub const PROGRESS_FILE: &str = "zerohash_progress.txt";
pub const JSON_PROGRESS_FILE: &str = "zerohash_progress.json";

// Estrutura para armazenar informações de progresso para um endereço e range específicos
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgressEntry {
    pub address: String,
    pub range_start: String,  // Valor hex do início do range
    pub range_end: String,    // Valor hex do fim do range
    pub current_key: String,  // Valor hex da última chave processada
    pub timestamp: u64,       // Timestamp da última atualização
}

// Estrutura completa para armazenar todos os progressos
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProgressData {
    pub entries: Vec<ProgressEntry>,
}

// Estrutura que representa um lote de chaves privadas para processamento
struct KeyBatch {
    keys: Vec<u128>,
    batch_number: u64,
}

// Estrutura que representa um lote de chaves públicas para hashing
struct PubkeyBatch {
    pubkeys: Vec<[u8; 33]>,
    original_keys: Vec<u128>,
    batch_number: u64,
}

// Estrutura que representa os resultados do hashing
struct HashResult {
    hashes: Vec<[u8; 20]>,
    original_keys: Vec<u128>,
    batch_number: u64,
}

// Estrutura para representar um intervalo de trabalho para balanceamento dinâmico
struct WorkRange {
    start: u128,
    end: u128,
}

impl WorkRange {
    /// Cria um novo intervalo de trabalho
    pub fn new(start: u128, end: u128) -> Self {
        WorkRange { start, end }
    }

    /// Retorna o tamanho (quantidade de chaves) no intervalo
    pub fn size(&self) -> u128 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    /// Verifica se o intervalo está vazio
    pub fn is_empty(&self) -> bool {
        self.end < self.start
    }

    /// Divide o intervalo em dois, retornando o segundo intervalo
    /// e mantendo o primeiro no objeto atual
    pub fn split(&mut self) -> Option<Self> {
        let size = self.size();
        if size <= 1 {
            return None;
        }

        let mid = self.start.saturating_add(size / 2);
        let second = WorkRange::new(mid, self.end);
        self.end = mid.saturating_sub(1);
        Some(second)
    }

    /// Divide o intervalo em n partes aproximadamente iguais
    pub fn split_into(&self, n: usize) -> Vec<Self> {
        if n <= 1 || self.is_empty() {
            return vec![self.clone()];
        }

        let size = self.size();
        let chunk_size = size / n as u128;
        let mut remainder = size % n as u128;
        
        let mut results = Vec::with_capacity(n);
        let mut current_start = self.start;
        
        for _ in 0..n {
            // Adiciona 1 extra para distribuir o resto uniformemente
            let extra = if remainder > 0 { 1 } else { 0 };
            remainder = remainder.saturating_sub(1);
            
            let current_size = chunk_size + extra;
            let current_end = current_start.saturating_add(current_size).saturating_sub(1);
            
            // Garante que o último pedaço não ultrapasse o final
            let adjusted_end = current_end.min(self.end);
            
            if current_start <= adjusted_end {
                results.push(WorkRange::new(current_start, adjusted_end));
            }
            
            current_start = adjusted_end.saturating_add(1);
            
            // Se já chegamos ao fim, paramos
            if current_start > self.end {
                break;
            }
        }
        
        results
    }
    
    /// Divide o intervalo em pedaços de tamanho específico
    pub fn split_by_chunk_size(&self, chunk_size: u128) -> Vec<Self> {
        if chunk_size == 0 || self.is_empty() {
            return vec![self.clone()];
        }
        
        let size = self.size();
        let num_chunks = (size + chunk_size - 1) / chunk_size; // Arredonda para cima
        let mut results = Vec::with_capacity(num_chunks as usize);
        
        let mut current_start = self.start;
        while current_start <= self.end {
            let current_end = (current_start + chunk_size - 1).min(self.end);
            results.push(WorkRange::new(current_start, current_end));
            current_start = current_end.saturating_add(1);
        }
        
        results
    }
}

impl Clone for WorkRange {
    fn clone(&self) -> Self {
        WorkRange {
            start: self.start,
            end: self.end,
        }
    }
}

impl fmt::Display for WorkRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}-{:x} ({} chaves)", self.start, self.end, self.size())
    }
}

/// Helper para salvar o progresso em um arquivo JSON.
fn save_progress_json(address: &str, range_start: u128, range_end: u128, current_key: u128) -> Result<(), String> {
    println!("Salvando progresso em JSON '{}': endereço {}, range {:x}-{:x}, valor atual {:x}", 
             JSON_PROGRESS_FILE, address, range_start, range_end, current_key);
    
    // Carregar dados existentes ou criar estrutura vazia
    let mut progress_data = load_progress_data().unwrap_or_default();
    
    // Verificar se já existe entrada para este endereço e range
    let range_start_hex = format!("{:x}", range_start);
    let range_end_hex = format!("{:x}", range_end);
    let current_key_hex = format!("{:x}", current_key);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let entry_index = progress_data.entries.iter().position(|entry| 
        entry.address == address && 
        entry.range_start == range_start_hex && 
        entry.range_end == range_end_hex
    );
    
    if let Some(index) = entry_index {
        // Atualizar entrada existente
        progress_data.entries[index].current_key = current_key_hex;
        progress_data.entries[index].timestamp = timestamp;
    } else {
        // Adicionar nova entrada
        progress_data.entries.push(ProgressEntry {
            address: address.to_string(),
            range_start: range_start_hex,
            range_end: range_end_hex,
            current_key: current_key_hex,
            timestamp,
        });
    }
    
    // Salvar arquivo JSON
    println!("Tentando criar arquivo JSON: {}", JSON_PROGRESS_FILE);
    match File::create(JSON_PROGRESS_FILE) {
        Ok(file) => {
            println!("Arquivo JSON criado com sucesso, serializando dados...");
            match serde_json::to_writer_pretty(file, &progress_data) {
                Ok(_) => {
                    println!("✓ Progresso JSON salvo com sucesso para endereço {} e range {:x}-{:x}", 
                             address, range_start, range_end);
                    Ok(())
                },
                Err(e) => {
                    println!("Erro ao serializar JSON: {}", e);
                    Err(format!("Falha ao serializar JSON: {}", e))
                }
            }
        },
        Err(e) => {
            println!("Erro ao criar arquivo JSON: {}", e);
            Err(format!("Falha ao criar arquivo: {}", e))
        }
    }
}

/// Carrega todos os dados de progresso do arquivo JSON
pub fn load_progress_data() -> Result<ProgressData, String> {
    if !Path::new(JSON_PROGRESS_FILE).exists() {
        return Ok(ProgressData::default());
    }
    
    match File::open(JSON_PROGRESS_FILE) {
        Ok(file) => {
            match serde_json::from_reader(file) {
                Ok(data) => Ok(data),
                Err(e) => Err(format!("Falha ao desserializar JSON: {}", e))
            }
        },
        Err(e) => Err(format!("Falha ao abrir arquivo JSON: {}", e))
    }
}

/// Carrega o progresso específico para um endereço e range
pub fn load_specific_progress(address: &str, range_start: u128, range_end: u128) -> Result<u128, String> {
    let range_start_hex = format!("{:x}", range_start);
    let range_end_hex = format!("{:x}", range_end);
    
    match load_progress_data() {
        Ok(data) => {
            for entry in data.entries {
                if entry.address == address && 
                   entry.range_start == range_start_hex && 
                   entry.range_end == range_end_hex {
                    
                    match u128::from_str_radix(&entry.current_key, 16) {
                        Ok(value) => {
                            println!("✓ Progresso JSON carregado com sucesso para endereço {} e range {:x}-{:x}: valor atual {:x}",
                                    address, range_start, range_end, value);
                            return Ok(value);
                        },
                        Err(e) => return Err(format!("Falha ao converter valor hexadecimal: {}", e))
                    }
                }
            }
            
            Err(format!("Nenhum progresso encontrado para endereço {} e range {:x}-{:x}", 
                       address, range_start, range_end))
        },
        Err(e) => Err(e)
    }
}

/// Helper para salvar o progresso em um arquivo (para compatibilidade).
fn save_progress_helper(progress_path: &str, current_key: u128) -> Result<(), String> {
    println!("Salvando progresso em '{}': valor atual {:x} ({})", progress_path, current_key, current_key);
    match File::create(progress_path) {
        Ok(file) => {
            let mut writer = BufWriter::new(file);
            // Converter para hexadecimal e salvar
            let hex_string = format!("{:x}", current_key);
            match writer.write_all(hex_string.as_bytes()) {
                Ok(_) => {
                    match writer.flush() {
                        Ok(_) => Ok(()),
                        Err(e) => Err(format!("Falha ao fazer flush no arquivo de progresso: {}", e))
                    }
                },
                Err(e) => Err(format!("Falha ao escrever no arquivo: {}", e))
            }
        },
        Err(e) => Err(format!("Falha ao criar arquivo: {}", e))
    }
}

/// Carrega o progresso anterior de um arquivo (para compatibilidade).
pub fn load_progress(progress_path: &str) -> Result<u128, String> {
    match File::open(progress_path) {
        Ok(file) => {
            let mut reader = BufReader::new(file);
            let mut line = String::new();
            
            match reader.read_line(&mut line) {
                Ok(_) => {
                    // Verificar se a linha está em formato hexadecimal
                    let trimmed_line = line.trim();
                    if trimmed_line.is_empty() {
                        return Err(format!("Arquivo de progresso vazio: {}", progress_path));
                    }
                    
                    println!("Carregando progresso de '{}': valor lido '{}'", progress_path, trimmed_line);
                    
                    if trimmed_line.starts_with("0x") {
                        // Remover o prefixo 0x se existir
                        let hex_value = &trimmed_line[2..];
                        match u128::from_str_radix(hex_value, 16) {
                            Ok(value) => {
                                println!("✓ Progresso carregado com sucesso: {:x} (formato hexadecimal com prefixo 0x)", value);
                                Ok(value)
                            },
                            Err(e) => Err(format!("Falha ao converter valor hexadecimal com prefixo 0x: {}", e))
                        }
                    } else {
                        // Tentar como formato hexadecimal sem prefixo 0x
                        match u128::from_str_radix(trimmed_line, 16) {
                            Ok(value) => {
                                println!("✓ Progresso carregado com sucesso: {:x} (formato hexadecimal)", value);
                                Ok(value)
                            },
                            Err(_) => {
                                // Se falhar, tentar como formato decimal
                                match trimmed_line.parse::<u128>() {
                                    Ok(value) => {
                                        println!("✓ Progresso carregado com sucesso: {:x} (formato decimal)", value);
                                        Ok(value)
                                    },
                                    Err(e) => Err(format!("Não foi possível interpretar o valor '{}' como hex ou decimal: {}", trimmed_line, e))
                                }
                            }
                        }
                    }
                },
                Err(e) => Err(format!("Falha ao ler arquivo: {}", e))
            }
        },
        Err(e) => Err(format!("Falha ao abrir arquivo: {}", e))
    }
}

/// Salva o progresso atual da busca em um arquivo JSON.
pub fn save_progress(progress_path: &str, current_key: u128) -> std::io::Result<()> {
    // Se o AppState estiver disponível, salvar no formato JSON
    if let Some(app_state) = crate::app_state::get_current_app_state() {
        let range_start = match app_state.range_start.lock() {
            Ok(guard) => *guard,
            Err(_) => 0,
        };
        
        let range_end = match app_state.range_end.lock() {
            Ok(guard) => *guard,
            Err(_) => u128::MAX,
        };
        
        let result = save_progress_json(
            &app_state.target_address,
            range_start,
            range_end,
            current_key
        );
        
        if result.is_err() {
            eprintln!("Erro ao salvar progresso em JSON: {:?}", result.err());
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Falha ao salvar progresso em JSON"));
        }
    } else {
        eprintln!("AppState não disponível para salvar progresso.");
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "AppState não disponível"));
    }
    
    Ok(())
}

/// Converte uma chave privada u128 para o formato WIF (Wallet Import Format).
pub fn u128_to_wif(key: u128, compressed: bool) -> String {
    // Converter para bytes
    let key_bytes = key.to_be_bytes().to_vec();
    
    // Adicionar o prefixo 0x80 para a rede principal
    let mut wif_bytes = vec![0x80];
    
    // Adicionar os bytes da chave
    wif_bytes.extend_from_slice(&key_bytes);
    
    // Adicionar o sufixo 0x01 para chaves comprimidas
    if compressed {
        wif_bytes.push(0x01);
    }
    
    // Calcular o duplo hash SHA-256
    let first_hash = sha256::Hash::hash(&wif_bytes);
    let second_hash = sha256::Hash::hash(first_hash.as_ref());
    
    // Adicionar os primeiros 4 bytes do segundo hash como checksum
    wif_bytes.extend_from_slice(&second_hash[0..4]);
    
    // Codificar em Base58
    bs58::encode(wif_bytes).into_string()
}

/// Função para inicializar o cache contextual / hierárquico
fn initialize_contextual_cache() {
    // Usar a nova interface profissional do CacheManager
    let cache_manager = crate::batch_hash::get_cache_manager();
    
    println!("Inicializando Cache Hierárquico para SHA256...");
    
    // Pré-carregar os prefixos comuns
    cache_manager.preload_common_prefixes();
    
    // Verificar e informar o suporte a instruções avançadas
    let has_avx2 = cache_manager.has_advanced_instruction_support();
    println!("Suporte a instruções AVX2: {}", if has_avx2 { "Sim ✓" } else { "Não ✗" });
    
    // Informar sobre o paralelismo recomendado
    let recommended_threads = cache_manager.recommended_parallelism();
    println!("Paralelismo recomendado: {} threads", recommended_threads);
    
    // Exibir estatísticas iniciais do cache
    cache_manager.print_statistics();
}

/// Função principal de busca turbo
pub fn turbo_search(app_state: Arc<AppState>) {
    // Obter opções de busca do app_state
    let num_threads = *app_state.num_threads.lock().unwrap();
    let range_start = app_state.get_range_start();
    let range_end = app_state.get_range_end();
    let total_keys_in_range = range_end.saturating_sub(range_start).saturating_add(1);
    let progress_path = app_state.get_progress_file_path();
    let use_precise_method = true; // Usar método mais preciso para geração de chaves
    
    // Mais eficiente verificar uma vez e armazenar o valor
    let is_random_mode = app_state.random_mode.load(Ordering::Relaxed);
    
    // Ajustar ponto de início efetivo baseado no progresso anterior
    let effective_range_start = if app_state.should_resume() && !is_random_mode {
        if let Ok(last_key) = load_specific_progress(&app_state.target_address, range_start, range_end) {
            if last_key >= range_start && last_key < range_end {
                let next_key = last_key.saturating_add(1);
                println!("Retomando busca a partir da chave {:x}", next_key);
                next_key
            } else {
                println!("Progresso carregado {:x} fora do range atual [{:x}-{:x}], iniciando do começo", 
                         last_key, range_start, range_end);
                range_start
            }
        } else {
            println!("Sem arquivo de progresso ou erro ao ler, iniciando do começo do range");
            range_start
        }
    } else {
        range_start
    };
    
    // Inicializar cache contextual para estados SHA-256
    initialize_contextual_cache();
    
    // Inicializar sistema de geração de chaves públicas
    warmup_system();
    
    // Configurar cache para prefixos comuns
    let prefixes = [
        &[0x02][..], // Prefixo para chaves com Y par (mais comum)
        &[0x03][..], // Prefixo para chaves com Y ímpar
        // Adicionar mais prefixos comuns pode aumentar hits no cache
    ];
    warm_up_cache(&prefixes);
    
    // Mostrar informações sobre o modo selecionado
    if is_random_mode {
        println!("{}", format!("Iniciando busca turbo em MODO ALEATÓRIO com {} threads", num_threads).bold());
        println!("Range de busca (hex): {:x} a {:x}", range_start, range_end);
        if app_state.should_resume() {
            println!("Aviso: Flag --resume ignorada no modo aleatório.");
            *app_state.resume.lock().unwrap() = false;
        }
        *app_state.progress_file.lock().unwrap() = String::new();
    } else {
        println!("{}", format!("Iniciando busca turbo SEQUENCIAL com {} threads", num_threads).bold());
        println!("Range de busca efetivo (hex): {:x} a {:x}", effective_range_start, range_end);
        if effective_range_start > range_end {
            println!("Range inválido após carregar progresso. Nada a fazer.");
            return;
        }
        *app_state.range_start.lock().unwrap() = effective_range_start;
    }

    // Inicializar sistema de estatísticas
    let performance_stats = PerformanceStats::new(total_keys_in_range, effective_range_start);
    let mut dashboard = Dashboard::new(performance_stats.clone());
    
    // Mostrar dashboard inicial
    clear_terminal();
    println!("{}", dashboard.render());

    // Inicializar variáveis compartilhadas
    let found = Arc::new(AtomicBool::new(false));
    let processed_keys = Arc::new(AtomicU64::new(0));
    let last_report_time = Arc::new(Mutex::new(Instant::now()));
    let last_save_time = Arc::new(Mutex::new(Instant::now()));
    let last_cache_stat_time = Arc::new(Mutex::new(Instant::now()));
    let target_hash = app_state.get_target_hash160();
    
    // Contador de taxa de processamento instantânea
    let last_processed_keys = Arc::new(AtomicU64::new(0));
    let last_rate_update_time = Arc::new(Mutex::new(Instant::now()));
    
    // Clones para usar fora do escopo do thread
    let app_state_final = app_state.clone();
    let found_final = found.clone();

    // Criar canal para relatórios de resultados - aumentado buffer para reduzir contenção
    let (result_sender, result_receiver) = bounded::<(u128, Vec<u8>, [u8; 33])>(512);
    
    // Criar escopo de threads com crossbeam
    thread::scope(|s| {
        // Thread para processar e relatar resultados
        let results_app_state = app_state.clone();
        let results_found = found.clone();
        s.spawn(move |_| {
            let mut results_file: Option<BufWriter<File>> = {
                let results_path = results_app_state.get_results_file_path();
                if !results_path.is_empty() {
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&*results_path)
                        .map(BufWriter::new)
                        .ok()
                } else {
                    None
                }
            };
            
            while let Ok((key, hash, _pubkey)) = result_receiver.recv() {
                results_found.store(true, Ordering::SeqCst);
                let secp = Secp256k1::new();
                let mut key_bytes = [0u8; 32];
                let key_u128_bytes = key.to_be_bytes();
                let start_byte = 32usize.saturating_sub(key_u128_bytes.len());
                key_bytes[start_byte..].copy_from_slice(&key_u128_bytes);

                println!("\n{}", format!("!!! PROCESSANDO RESULTADO ENCONTRADO: chave = {:x}", key).green().bold());
                println!("!!! Hash160 recebido: {}", hex::encode(&hash));
                
                if let Ok(secret_key) = SecretKey::from_slice(&key_bytes) {
                    let network = results_app_state.get_network();
                    let pk = bitcoin::PrivateKey::new(secret_key, network);
                    let pubkey = pk.public_key(&secp);
                    
                    // Verificação extra do hash160 para confirmar a correspondência
                    let pubkey_bytes = pubkey.inner.serialize();
                    let hash160_manual = bitcoin::hashes::hash160::Hash::hash(&pubkey_bytes).to_byte_array();
                    
                    // Verificar se há correspondência com o hash alvo
                    let target_hash160 = results_app_state.get_target_hash160();
                    println!("{}", format!("!!! Hash160 calculado: {}", hex::encode(&hash160_manual)).cyan());
                    println!("{}", format!("!!! Hash160 alvo:      {}", hex::encode(&target_hash160)).cyan());
                    
                    // Atualização para API do bitcoin 0.32.5
                    let p2pkh = Address::p2pkh(&pubkey, network);
                    
                    // Criar um CompressedPublicKey a partir do PublicKey para p2wpkh
                    // Na versão 0.32.5, precisamos usar bitcoin_internals::XOnlyPublicKey
                    let compressed_pubkey_bytes = pubkey.inner.serialize();
                    let bip340_pubkey = bitcoin::key::CompressedPublicKey::from_slice(&compressed_pubkey_bytes).unwrap();
                    
                    let p2wpkh = Address::p2wpkh(&bip340_pubkey, network);
                    let p2sh_p2wpkh = Address::p2shwpkh(&bip340_pubkey, network);
                    
                    let wif = pk.to_wif();
                    let key_hex = hex::encode(key_bytes);
                    let hash_hex = hex::encode(hash);

                    let result = format!(
                        "\n{}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n",
                        "!!! ENCONTRADO ENDEREÇO CORRESPONDENTE !!!".green().bold(),
                        "Chave Privada (Hex)".bold(), key_hex,
                        "Chave Privada (WIF)".bold(), wif,
                        "P2PKH".bold(), p2pkh,
                        "P2WPKH".bold(), p2wpkh,
                        "P2SH-P2WPKH".bold(), p2sh_p2wpkh,
                        "Hash160".bold(), hash_hex
                    );
                    println!("{}", result);

                    if let Some(ref mut file) = results_file {
                        if let Err(e) = writeln!(file, "{}", result) {
                            eprintln!("Erro ao escrever no arquivo de resultados: {}", e);
                        }
                        if let Err(e) = file.flush() {
                             eprintln!("Erro ao fazer flush no arquivo de resultados: {}", e);
                        }
                    }
                } else {
                     eprintln!("Erro ao converter u128 {:x} para SecretKey", key);
                }
            }
        });
        
        let process_app_state = app_state.clone();
        let process_found = found.clone();
        let process_processed_keys = processed_keys.clone();
        let process_last_report_time = last_report_time.clone();
        let process_last_save_time = last_save_time.clone();
        let process_last_cache_stat_time = last_cache_stat_time.clone();
        let process_last_processed_keys = last_processed_keys.clone();
        let process_last_rate_update_time = last_rate_update_time.clone();
        let stats = performance_stats.clone();

        s.spawn(move |_| {
            let thread_range_start = process_app_state.get_range_start();
            let thread_range_end = process_app_state.get_range_end();
            let thread_is_random = process_app_state.random_mode.load(Ordering::Relaxed);

            if thread_is_random {
                println!("Iniciando workers em modo ALEATÓRIO");
                (0..num_threads).into_par_iter().for_each(|_| {
                    // Atualização para rand 0.9.0
                    let mut rng = rng();
                    let mut keys = Vec::with_capacity(TURBO_BATCH_SIZE);
                    let mut pubkeys_buffer = Vec::with_capacity(TURBO_BATCH_SIZE);
                    let result_sender = result_sender.clone();
                    let stats_clone = stats.clone();

                    loop {
                        if process_found.load(Ordering::Relaxed) || !process_app_state.search_active.load(Ordering::Relaxed) {
                            break;
                        }

                        keys.clear();
                        for _ in 0..TURBO_BATCH_SIZE {
                            if thread_range_start > thread_range_end {
                                 eprintln!("Erro: Range inválido no modo aleatório ({:x} > {:x})", thread_range_start, thread_range_end);
                                 process_found.store(true, Ordering::Relaxed);
                                 break;
                            }
                            // Atualização para rand 0.9.0
                            keys.push(rng.random_range(thread_range_start..=thread_range_end));
                        }
                        if process_found.load(Ordering::Relaxed) || !process_app_state.search_active.load(Ordering::Relaxed) { break; }
                        
                        pubkeys_buffer.clear();
                        
                        if use_precise_method {
                            // Usar método preciso para todas as chaves
                            for key in &keys {
                                if let Some(pubkey) = generate_pubkey_precise(*key) {
                                    pubkeys_buffer.push(pubkey);
                                } else {
                                    // Colocar uma chave inválida para manter o índice
                                    pubkeys_buffer.push([0u8; 33]);
                                }
                            }
                        } else {
                            // Método normal batch
                            generate_pubkeys_batch(&keys, &mut pubkeys_buffer);
                        }
                        
                        let matches = hash160_and_match_direct(&pubkeys_buffer, &target_hash);

                        // Atualizar estatísticas diretamente sem bloqueio
                        stats_clone.add_processed_keys(TURBO_BATCH_SIZE as u64);
                        stats_clone.add_hashes_computed(TURBO_BATCH_SIZE as u64);
                        
                        // Incrementar contador para cálculo de taxa
                        process_processed_keys.fetch_add(TURBO_BATCH_SIZE as u64, Ordering::Relaxed);

                        for (idx, hash) in matches {
                             if !process_found.load(Ordering::Relaxed) {
                                 let key = keys[idx];
                                 println!("\n{}", format!("!! ENCONTRADA CORRESPONDÊNCIA DE HASH EM WORKER ALEATÓRIO: chave = {:x}", key).green().bold());
                                 let _ = result_sender.send((key, hash.to_vec(), pubkeys_buffer[idx]));
                                 process_found.store(true, Ordering::SeqCst);
                             }
                        }
                    }
                });
            } else {
                println!("Iniciando workers em modo SEQUENCIAL com balanceamento dinâmico");
                println!("Sistema de balanceamento dinâmico: chunks iniciais de ~{} chaves", DYNAMIC_CHUNK_SIZE);
                
                // Calcular o número de chunks baseado no range, mas limitado a um valor máximo seguro
                const MAX_CHUNKS: usize = 10_000;
                
                // Para ranges extremamente grandes, calcular chunks de forma segura para evitar problemas de memória
                let range_size = thread_range_end.saturating_sub(thread_range_start).saturating_add(1);
                
                // Calcular o número de chunks de forma segura para ranges extremamente grandes
                let num_chunks = {
                    // Converter para valor mais seguro primeiro
                    let chunk_count = range_size as f64 / DYNAMIC_CHUNK_SIZE as f64;
                    
                    // Limitar ao número máximo de chunks
                    if chunk_count > MAX_CHUNKS as f64 {
                        MAX_CHUNKS
                    } else {
                        chunk_count.ceil() as usize
                    }
                };
                
                // Garantir pelo menos 4 chunks por thread
                let num_chunks = num_chunks.max(num_threads * 4);
                
                // Calcular o tamanho de cada chunk com base no número real de chunks
                // Usar divisão de ponto flutuante para evitar problemas com ranges muito grandes
                let chunk_size_f64 = range_size as f64 / num_chunks as f64;
                let chunk_size = chunk_size_f64.round() as u128;
                
                println!("Dividindo range em {} chunks de ~{} chaves cada", 
                         num_chunks, chunk_size);
                
                // Criar range principal para divisão
                let main_range = WorkRange::new(thread_range_start, thread_range_end);
                
                // Verificar se o range é extremamente grande para usar uma abordagem diferente
                let use_lazy_chunks = main_range.size() > 1_000_000_000_000_000u128; // 1 quatrilhão
                
                // Criar chunks para processamento usando métodos otimizados
                let chunk_ranges: Vec<WorkRange> = if use_lazy_chunks {
                    // Para ranges extremamente grandes, criar apenas um número limitado de chunks
                    println!("Range muito grande detectado ({} valores). Usando abordagem otimizada.", main_range.size());
                    
                    // Criar chunks iniciais (1 por thread) com tamanho limitado
                    let initial_chunks_per_thread = 1; // Reduzido para 1 por thread
                    let initial_chunks_count = num_threads * initial_chunks_per_thread;
                    
                    // Limitar o tamanho máximo de cada chunk para evitar alocações excessivas
                    const MAX_CHUNK_SIZE: u128 = 1_000_000_000_000; // 1 trilhão de chaves por chunk
                    println!("Criando {} chunks iniciais ({} por thread) com tamanho máximo de {} chaves", initial_chunks_count, initial_chunks_per_thread, MAX_CHUNK_SIZE);
                    
                    // Usar o método split_into para criar chunks de tamanho uniforme, mas limitar o tamanho
                    let mut limited_chunks = Vec::new();
                    let total_range_size = main_range.size();
                    let chunk_size = (total_range_size / initial_chunks_count as u128).min(MAX_CHUNK_SIZE);
                    let mut current_start = main_range.start;
                    for _ in 0..initial_chunks_count {
                        let current_end = (current_start + chunk_size - 1).min(main_range.end);
                        if current_start <= current_end {
                            limited_chunks.push(WorkRange::new(current_start, current_end));
                        }
                        current_start = current_end.saturating_add(1);
                        if current_start > main_range.end {
                            break;
                        }
                    }
                    limited_chunks
                } else {
                    // Para ranges normais, criar todos os chunks usando split_by_chunk_size
                    println!("Criando {} chunks usando método otimizado", num_chunks);
                    
                    // Usar o método split_by_chunk_size para garantir tamanhos uniformes
                    main_range.split_by_chunk_size(chunk_size)
                };
                
                println!("Criados {} chunks. Primeiro: {}, Último: {}", 
                         chunk_ranges.len(),
                         chunk_ranges.first().map_or("Nenhum".to_string(), |r| r.to_string()),
                         chunk_ranges.last().map_or("Nenhum".to_string(), |r| r.to_string()));
                
                // Encapsular os chunks em um Mutex para acesso concorrente
                let chunk_ranges_mutex = Arc::new(Mutex::new(chunk_ranges));
                
                // Processar os chunks em paralelo
                (0..num_threads).into_par_iter().for_each(|_| {
                    let result_sender = result_sender.clone();
                    let chunk_ranges_mutex = Arc::clone(&chunk_ranges_mutex);
                    let stats_clone = stats.clone();
                    let process_found_clone = Arc::clone(&process_found);
                    let process_app_state_clone = Arc::clone(&process_app_state);
                    let process_processed_keys_clone = Arc::clone(&process_processed_keys);
                    
                    let mut keys = Vec::with_capacity(TURBO_BATCH_SIZE);
                    let mut pubkeys_buffer = Vec::with_capacity(TURBO_BATCH_SIZE);
                    
                    while !process_found_clone.load(Ordering::Relaxed) && 
                          process_app_state_clone.search_active.load(Ordering::Relaxed) {
                        
                        // Obter próximo chunk disponível
                        let work_range = {
                            let mut ranges = chunk_ranges_mutex.lock().unwrap();
                            if ranges.is_empty() {
                                // Verificar se devemos criar mais chunks em modo adaptativo
                                if use_lazy_chunks && !process_found_clone.load(Ordering::Relaxed) {
                                    // Calcular o progresso atual
                                    let current_key = stats_clone.get_current_key();
                                    let progress_pct = (current_key - thread_range_start) as f64 / range_size as f64 * 100.0;
                                    
                                    // Se ainda estamos abaixo de 90% do progresso, criar mais chunks
                                    if progress_pct < 90.0 {
                                        let remaining_range = WorkRange::new(current_key, thread_range_end);
                                        if !remaining_range.is_empty() && remaining_range.size() > chunk_size {
                                            // Criar mais chunks (2 por thread)
                                            let new_chunks_per_thread = 2;
                                            let new_chunks_count = num_threads * new_chunks_per_thread;
                                            
                                            let new_chunks = remaining_range.split_into(new_chunks_count);
                                            println!("Gerando mais {} chunks sob demanda a partir de {:x}", 
                                                     new_chunks.len(), current_key);
                                            
                                            // Adicionar novos chunks
                                            for chunk in new_chunks {
                                                ranges.push(chunk);
                                            }
                                        }
                                    }
                                }
                                
                                // Se ainda estiver vazio após tentar criar mais chunks, sair
                                if ranges.is_empty() {
                                    break;
                                }
                            }
                            ranges.pop()
                        };
                        
                        if let Some(range) = work_range {
                            // Verificar se o tamanho do chunk é grande demais para processar de uma vez
                            if range.size() > MEGA_BATCH_SIZE as u128 * 2 {
                                // Dividir em subchunks e recolocar na fila
                                let mut ranges = chunk_ranges_mutex.lock().unwrap();
                                let subchunks = range.split_by_chunk_size(MEGA_BATCH_SIZE as u128);
                                for chunk in subchunks {
                                    ranges.push(chunk);
                                }
                                continue; // Continuar para pegar o próximo chunk
                            }
                            
                            // Processar o chunk
                            let mut current_key = range.start;
                            
                            while current_key <= range.end && 
                                  !process_found_clone.load(Ordering::Relaxed) && 
                                  process_app_state_clone.search_active.load(Ordering::Relaxed) {
                                  
                                // Determinar quantas chaves processar neste batch
                                let keys_left = range.end.saturating_sub(current_key).saturating_add(1);
                                let batch_size = TURBO_BATCH_SIZE.min(keys_left as usize);
                                
                                if batch_size == 0 {
                                    break;
                                }
                                
                                // Limpar buffers
                                keys.clear();
                                pubkeys_buffer.clear();
                                
                                // Gerar chaves sequenciais para este batch
                                for i in 0..batch_size {
                                    keys.push(current_key.saturating_add(i as u128));
                                }
                                
                                // Gerar chaves públicas
                                if use_precise_method {
                                    for key in &keys {
                                        if let Some(pubkey) = generate_pubkey_precise(*key) {
                                            pubkeys_buffer.push(pubkey);
                                        } else {
                                            pubkeys_buffer.push([0u8; 33]);
                                        }
                                    }
                                } else {
                                    generate_pubkeys_batch(&keys, &mut pubkeys_buffer);
                                }
                                
                                // Verificar correspondências
                                let matches = hash160_and_match_direct(&pubkeys_buffer, &target_hash);
                                
                                // Atualizar estatísticas
                                stats_clone.add_processed_keys(batch_size as u64);
                                stats_clone.add_hashes_computed(batch_size as u64);
                                process_processed_keys_clone.fetch_add(batch_size as u64, Ordering::Relaxed);
                                
                                // Atualizar a chave atual para o próximo lote
                                current_key = current_key.saturating_add(batch_size as u128);
                                
                                // Verificar correspondências
                                for (idx, hash) in matches {
                                    if !process_found_clone.load(Ordering::Relaxed) {
                                        let key = keys[idx];
                                        println!("\n{}", format!("!! ENCONTRADA CORRESPONDÊNCIA DE HASH EM WORKER SEQUENCIAL: chave = {:x}", key).green().bold());
                                        let _ = result_sender.send((key, hash.to_vec(), pubkeys_buffer[idx]));
                                        process_found_clone.store(true, Ordering::SeqCst);
                                    }
                                }
                                
                                // Atualizar a chave atual para estatísticas
                                stats_clone.set_current_key(current_key);
                            }
                        }
                    }
                });
            }
            
            // Thread principal terminou, sinalizar para thread de UI também encerrar
            if !process_found.load(Ordering::Relaxed) {
                process_app_state.search_active.store(false, Ordering::SeqCst);
            }
        });
        
        // Thread para atualização da UI em tempo real
        let ui_app_state = app_state.clone();
        let ui_found = found.clone();
        let ui_processed_keys = processed_keys.clone();
        let ui_stats = performance_stats.clone();
        
        s.spawn(move |_| {
            let mut last_ui_update = Instant::now();
            let mut last_key = 0u128;
            let mut last_save_time = Instant::now();
            let save_interval = Duration::from_millis(1000); // Salvar a cada 1 segundo
            
            while ui_app_state.search_active.load(Ordering::Relaxed) {
                // Dormir brevemente para não consumir CPU desnecessariamente
                std::thread::sleep(Duration::from_millis(50));
                
                let now = Instant::now();
                let elapsed = now.duration_since(last_ui_update);
                let elapsed_since_save = now.duration_since(last_save_time);
                
                // Atualizar UI apenas se passou tempo suficiente
                if elapsed.as_millis() >= 100 {
                    last_ui_update = now;
                    
                    // Atualizar dashboard
                    let snapshot = ui_stats.get_snapshot();
                    
                    // Renderizar o dashboard completo a cada atualização
                    clear_terminal();
                    println!("{}", dashboard.render());
                    
                    // Exibir a chave atual em cada atualização
                    println!("Chave atual: {:x}", snapshot.get_current_key());
                    
                    last_key = snapshot.get_current_key();
                }
                
                // Salvar progresso periodicamente
                if elapsed_since_save.as_millis() >= save_interval.as_millis() {
                    let result = save_progress(JSON_PROGRESS_FILE, ui_stats.get_current_key());
                    if result.is_err() {
                        eprintln!("Erro ao salvar progresso: {:?}", result.err());
                    }
                    last_save_time = now;
                }
                
                // Verificar se a busca encontrou resultado ou foi interrompida
                if ui_found.load(Ordering::Relaxed) {
                    break;
                }
            }
        });
        
        // Aguardar a conclusão de todos os threads
    }).unwrap();
    
    // Após a conclusão, obter snapshot final para estatísticas
    let final_stats = performance_stats.get_snapshot();
    
    // Imprimir resumo final
    println!("\n────────────────────────────────────────────────────────────────────────────────");
    if found_final.load(Ordering::Relaxed) {
        println!("█ BUSCA CONCLUÍDA COM SUCESSO!");
    } else {
        println!("█ BUSCA CONCLUÍDA");
    }
    println!("Total de chaves processadas: {}", final_stats.get_processed_keys());
    println!("Tempo total: {:.2}s", final_stats.get_elapsed_time().as_secs_f64());
    
    let rate = if final_stats.get_elapsed_time().as_secs_f64() > 0.0 {
        final_stats.get_processed_keys() as f64 / final_stats.get_elapsed_time().as_secs_f64()
    } else {
        0.0
    };
    println!("Taxa média: {:.2} Mkeys/s (SHA256+RIPEMD160)", rate / 1_000_000.0);
    
    if !found_final.load(Ordering::Relaxed) {
        println!("Chave não encontrada no range especificado.");
    }
    println!("────────────────────────────────────────────────────────────────────────────────");
} 