// turbo_search.rs - Implementação de busca de alta performance capaz de processar milhões de chaves/s
use crate::app_state::AppState;
use crate::batch_pubkey::{generate_pubkeys_batch, warmup_system};
use crate::batch_hash::{hash160_and_match, hash160_and_match_direct};
use crossbeam::channel::{bounded};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering, AtomicU64};
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufRead, BufReader};
use crossbeam::thread;
use rayon::prelude::*;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::hashes::Hash;
use bitcoin::PublicKey;
use bitcoin::Address;
use bitcoin::hashes::{sha256, ripemd160};
use bs58;

// Tamanho dos lotes para processamento - AUMENTADO para melhorar desempenho
const MEGA_BATCH_SIZE: usize = 1024 * 1024; // 1M chaves por mega-lote
const SUB_BATCH_SIZE: usize = 128 * 1024;   // 128K chaves por sub-lote
const CHANNEL_BUFFER: usize = 4;           // Buffer para maximizar throughput
const TURBO_BATCH_SIZE: usize = 262144;    // Aumentado de 65536 para 262144 (4x)

// Definir constante para o arquivo de progresso
pub const PROGRESS_FILE: &str = "zerohash_progress.txt";

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

/// Função pública auxiliar para salvar progresso, acessível por outros módulos
pub fn save_progress_helper(progress_path: &str, current_key: u128) {
    if progress_path.is_empty() {
        return;
    }
    
    if let Ok(file) = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(progress_path)
    {
        let mut writer = std::io::BufWriter::new(file);
        let _ = writeln!(writer, "{}", current_key);
    }
}

/// Carrega o progresso anterior de um arquivo.
pub fn load_progress(progress_path: &str) -> Result<u128, String> {
    match File::open(progress_path) {
        Ok(file) => {
            let mut reader = BufReader::new(file);
            let mut line = String::new();
            
            match reader.read_line(&mut line) {
                Ok(_) => {
                    match line.trim().parse::<u128>() {
                        Ok(value) => Ok(value),
                        Err(e) => Err(format!("Falha ao converter valor: {}", e))
                    }
                },
                Err(e) => Err(format!("Falha ao ler arquivo: {}", e))
            }
        },
        Err(e) => Err(format!("Falha ao abrir arquivo: {}", e))
    }
}

/// Salva o progresso atual da busca em um arquivo.
pub fn save_progress(progress_path: &str, current_key: u128) -> std::io::Result<()> {
    let mut file = File::create(progress_path)?;
    write!(file, "{}", current_key)?;
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

/// Implementação turbo da busca
pub fn turbo_search(app_state: Arc<AppState>) {
    // Aquecer o sistema antes de iniciar a busca
    warmup_system();
    
    // Obter os valores dos campos do AppState
    let num_threads = *app_state.num_threads.lock().unwrap();
    println!("Iniciando busca turbo com {0} threads", num_threads);
    
    // Determinar a faixa de chaves a buscar
    let range_start = if *app_state.resume.lock().unwrap() {
        let progress_file = app_state.progress_file.lock().unwrap().clone();
        match load_progress(&progress_file) {
            Ok(saved_key) => {
                println!("Retomando busca de {}", saved_key);
                saved_key
            },
            Err(e) => {
                println!("Não foi possível carregar progresso: {}", e);
                *app_state.range_start.lock().unwrap()
            }
        }
    } else {
        *app_state.range_start.lock().unwrap()
    };
    
    let range_end = *app_state.range_end.lock().unwrap();
    
    println!("Buscando de {0} até {1}", range_start, range_end);
    
    // Inicializar variáveis compartilhadas
    let found = AtomicBool::new(false);
    let processed_keys = AtomicU64::new(0);
    let last_report_time = Arc::new(std::sync::Mutex::new(Instant::now()));
    let last_save_time = Arc::new(std::sync::Mutex::new(Instant::now()));
    
    // Extrair o hash alvo uma vez antes de iniciar a busca
    let target_hash = {
        let hash_mutex = app_state.target_pubkey_hash.lock().unwrap();
        let mut hash_array = [0u8; 20];
        hash_array.copy_from_slice(&*hash_mutex);
        hash_array
    };
    
    // Criar canal para relatórios de resultados - aumentado buffer para reduzir contenção
    let (result_sender, result_receiver) = bounded::<(u128, Vec<u8>, [u8; 33])>(512);
    
    // Criar escopo de threads com crossbeam
    thread::scope(|s| {
        // Thread para processar e relatar resultados
        s.spawn(|_| {
            let mut results_file = {
                let results_path = app_state.results_file.lock().unwrap();
                if !results_path.is_empty() {
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&*results_path)
                        .ok()
                } else {
                    None
                }
            };
            
            while let Ok((key, hash, _pubkey)) = result_receiver.recv() {
                // Formatar e imprimir resultado
                let secp = Secp256k1::new();
                let mut key_bytes = [0u8; 32];
                key_bytes[16..].copy_from_slice(&key.to_be_bytes());
                
                if let Ok(secret_key) = SecretKey::from_slice(&key_bytes) {
                    let network = *app_state.network.lock().unwrap();
                    let pubkey = PublicKey::from_private_key(
                        &secp,
                        &bitcoin::PrivateKey::new(secret_key, network)
                    );
                    
                    let p2pkh = Address::p2pkh(&pubkey, network);
                    let p2wpkh = Address::p2wpkh(&pubkey, network).unwrap();
                    let p2sh_p2wpkh = Address::p2shwpkh(&pubkey, network).unwrap();
                    
                    let result = format!(
                        "Encontrado endereço correspondente!\nChave Privada: {}\nP2PKH: {}\nP2WPKH: {}\nP2SH-P2WPKH: {}\nHash160: {}\n",
                        hex::encode(key_bytes),
                        p2pkh,
                        p2wpkh,
                        p2sh_p2wpkh,
                        hex::encode(hash)
                    );
                    
                    println!("{}", result);
                    
                    // Salvar em arquivo se configurado
                    if let Some(ref mut file) = results_file {
                        let _ = writeln!(file, "{}", result);
                        let _ = file.flush();
                    }
                    
                    // Marcar que encontramos um resultado
                    found.store(true, Ordering::SeqCst);
                }
            }
        });
        
        // Thread para processamento principal
        s.spawn(|_| {
            // Dividir o trabalho em chunks para processamento em threads
            let chunks: Vec<(u128, u128)> = {
                // Otimização: Cálculo mais eficiente de chunks
                let total_range = range_end.saturating_sub(range_start) + 1;
                // Calculamos um tamanho de chunk baseado em múltiplos do tamanho do lote
                let chunk_size = (total_range / (num_threads as u128 * 2))
                    .max(TURBO_BATCH_SIZE as u128)
                    .min(total_range / 2); // Não queremos chunks muito grandes nem muito pequenos
                
                let mut chunks = Vec::new();
                let mut current = range_start;
                
                while current <= range_end {
                    let end = std::cmp::min(current + chunk_size - 1, range_end);
                    chunks.push((current, end));
                    current = end + 1;
                    
                    if current > range_end {
                        break;
                    }
                }
                
                chunks
            };
            
            println!("Dividindo trabalho em {} chunks", chunks.len());
            
            chunks.into_par_iter().for_each(|(chunk_start, chunk_end)| {
                if found.load(Ordering::Relaxed) { // Mudado para Relaxed para reduzir sobrecarga
                    return;
                }
                
                let mut current = chunk_start;
                let result_sender = result_sender.clone();
                
                // Pré-alocar buffers para reduzir alocações dentro do loop
                let mut pubkeys_buffer = Vec::with_capacity(TURBO_BATCH_SIZE);
                
                while current <= chunk_end && !found.load(Ordering::Relaxed) {
                    // Determinar tamanho do batch atual
                    let batch_end = std::cmp::min(current + TURBO_BATCH_SIZE as u128, chunk_end + 1);
                    let keys_in_batch = (batch_end - current) as usize;
                    
                    // Gerar lista de chaves privadas de forma mais eficiente
                    let mut keys = Vec::with_capacity(keys_in_batch);
                    for i in 0..keys_in_batch {
                        keys.push(current + i as u128);
                    }
                    
                    // Reutilizar o mesmo buffer para reduzir alocações
                    pubkeys_buffer.clear();
                    
                    // Gerar chaves públicas
                    generate_pubkeys_batch(&keys, &mut pubkeys_buffer);
                    
                    // Usar a versão direta que é mais eficiente para comparação exata
                    let matches = hash160_and_match_direct(&pubkeys_buffer, &target_hash);
                    
                    // Processar correspondências encontradas
                    for (idx, hash) in matches {
                        let key = keys[idx];
                        let _ = result_sender.send((key, hash.to_vec(), pubkeys_buffer[idx]));
                    }
                    
                    // Atualizar contadores - Usando fetch_add com Relaxed para menos contenção
                    processed_keys.fetch_add(keys_in_batch as u64, Ordering::Relaxed);
                    current = batch_end;
                    
                    // Relatório periódico de desempenho - Reduzindo frequência para menos sobrecarga
                    {
                        let now = Instant::now();
                        let mut should_report = false;
                        
                        {
                            let mut last_report = last_report_time.lock().unwrap();
                            if now.duration_since(*last_report) > Duration::from_millis(1500) {
                                *last_report = now;
                                should_report = true;
                            }
                        }
                        
                        if should_report {
                            let total = processed_keys.load(Ordering::Relaxed);
                            let elapsed = now.duration_since(Instant::now() - Duration::from_secs(5));
                            let rate = if elapsed.as_secs_f64() > 0.0 {
                                total as f64 / elapsed.as_secs_f64()
                            } else {
                                0.0
                            };
                            
                            println!("Progresso: {}/{} chaves ({:.2}%) a {:.0} k/s", 
                                     current - range_start, 
                                     range_end - range_start + 1,
                                     (current - range_start) as f64 / (range_end - range_start + 1) as f64 * 100.0,
                                     rate / 1000.0);
                        }
                    }
                    
                    // Salvar progresso a cada 2 minutos em vez de 1 para menos I/O
                    {
                        let now = Instant::now();
                        let mut should_save = false;
                        
                        {
                            let mut last_save = last_save_time.lock().unwrap();
                            if now.duration_since(*last_save) > Duration::from_secs(120) {
                                *last_save = now;
                                should_save = true;
                            }
                        }
                        
                        if should_save {
                            let progress_file = app_state.progress_file.lock().unwrap();
                            save_progress_helper(&progress_file, current);
                        }
                    }
                }
            });
            
            // Fechar canal de resultados quando terminar
            drop(result_sender);
        });
    }).unwrap();
    
    println!("Busca turbo concluída!");
} 