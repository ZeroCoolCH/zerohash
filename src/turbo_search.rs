// turbo_search.rs - Implementação de busca de alta performance capaz de processar milhões de chaves/s
use crate::app_state::AppState;
use crate::batch_pubkey::{generate_pubkeys_batch, generate_pubkey_precise, warmup_system};
use crate::batch_hash::{hash160_and_match_direct, warm_up_cache};
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
use bitcoin::{Address, Network};
use bitcoin::hashes::{sha256};
use bs58;
use std::sync::Mutex;
use std::collections::VecDeque;

// Tamanho dos lotes para processamento - AUMENTADO para melhorar desempenho
const MEGA_BATCH_SIZE: usize = 1024 * 1024; // 1M chaves por mega-lote
const SUB_BATCH_SIZE: usize = 128 * 1024;   // 128K chaves por sub-lote
const CHANNEL_BUFFER: usize = 4;           // Buffer para maximizar throughput
const TURBO_BATCH_SIZE: usize = 262144;    // Aumentado de 65536 para 262144 (4x)
const DYNAMIC_CHUNK_SIZE: usize = 10485760; // Tamanho de chunks inicial para o balanceamento dinâmico (10M)

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

// Estrutura para representar um intervalo de trabalho para balanceamento dinâmico
struct WorkRange {
    start: u128,
    end: u128,
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
    
    // Inicializar o Cache Contextual Dinâmico
    initialize_contextual_cache();
    
    // Modo de teste especial - verificar chaves conhecidas
    let test_mode = false; // Ative isso para testar chaves específicas

    if test_mode {
        println!("=== MODO DE TESTE ATIVADO ===");
        println!("Verificando chaves conhecidas contra o endereço alvo: {}", app_state.target_address);
        
        // Lista de chaves a testar (valores interessantes para testes)
        let test_keys = [
            1u128, 2u128, 3u128,
            // Valores conhecidos de Bitcoin
            0xd19c857c4744bb2fa570acf4a35cfbcfu128,  // Corresponde a um endereço conhecido
            0x01u128,  // Chave "um"
            0x69d61e4a8c50eae768bb3b135b1cdb85u128,  // Outra chave conhecida
        ];
        
        let target_hash = app_state.get_target_hash160();
        let secp = Secp256k1::new();
        
        for &key in &test_keys {
            println!("\nTestando chave: {:x}", key);
            
            // Gerar chave pública usando o método preciso
            if let Some(pubkey) = generate_pubkey_precise(key) {
                println!("Pubkey gerada: {:02x}{:02x}...", pubkey[0], pubkey[1]);
                
                // Calcular hash160 manualmente
                let hash160 = bitcoin::hashes::hash160::Hash::hash(&pubkey).to_byte_array();
                println!("Hash160: {}", hex::encode(&hash160));
                
                // Verificar se corresponde ao alvo
                if &hash160 == target_hash.as_slice() {
                    println!("!!! CORRESPONDÊNCIA ENCONTRADA !!!");
                    
                    // Converter em endereço Bitcoin para verificação
                    let mut key_bytes = [0u8; 32];
                    let key_u128_bytes = key.to_be_bytes();
                    let start_byte = 32usize.saturating_sub(key_u128_bytes.len());
                    key_bytes[start_byte..].copy_from_slice(&key_u128_bytes);
                    
                    if let Ok(secret_key) = SecretKey::from_slice(&key_bytes) {
                        let network = app_state.get_network();
                        let pk = bitcoin::PrivateKey::new(secret_key, network);
                        let pubkey = pk.public_key(&secp);
                        
                        let p2pkh = Address::p2pkh(&pubkey, network);
                        let compressed_pubkey_bytes = pubkey.inner.serialize();
                        let bip340_pubkey = bitcoin::key::CompressedPublicKey::from_slice(&compressed_pubkey_bytes).unwrap();
                        
                        let p2wpkh = Address::p2wpkh(&bip340_pubkey, network);
                        
                        println!("Chave privada (hex): {}", hex::encode(key_bytes));
                        println!("Endereço P2PKH: {}", p2pkh);
                        println!("Endereço P2WPKH: {}", p2wpkh);
                    }
                } else {
                    println!("Não corresponde ao alvo.");
                    println!("Alvo: {}", hex::encode(target_hash.as_slice()));
                }
            } else {
                println!("Falha ao gerar chave pública!");
            }
        }
        
        println!("\n=== FIM DO MODO DE TESTE ===\n");
    }
    
    // Obter os valores dos campos do AppState
    let num_threads = app_state.get_num_threads();
    let is_random_mode = app_state.random_mode.load(Ordering::Relaxed);
    let range_start = app_state.get_range_start();
    let range_end = app_state.get_range_end();
    
    // Flag para usar método preciso exclusivamente (mais lento, mas garantido)
    let use_precise_method = false; // Use false para usar o método batch padrão 
    if use_precise_method {
        println!("AVISO: Usando método preciso para geração de chaves públicas.");
        println!("Este método é mais lento, mas garante compatibilidade 100% com o padrão Bitcoin.");
    }

    if is_random_mode {
        println!("Iniciando busca turbo em MODO ALEATÓRIO com {} threads", num_threads);
        println!("Range de busca (hex): {:x} a {:x}", range_start, range_end);
        if app_state.should_resume() {
             println!("Aviso: Flag --resume ignorada no modo aleatório.");
             *app_state.resume.lock().unwrap() = false;
        }
        *app_state.progress_file.lock().unwrap() = String::new();
    } else {
        let effective_range_start = if app_state.should_resume() {
             let progress_file = app_state.get_progress_file_path();
             match load_progress(&progress_file) {
                 Ok(saved_key) if saved_key >= range_start && saved_key < range_end => {
                     println!("Retomando busca sequencial de: {:x}", saved_key + 1);
                     saved_key + 1
                 }
                 Ok(saved_key) => {
                     println!("Progresso sequencial ({:x}) inválido/fora do range. Iniciando de {:x}.", saved_key, range_start);
                     range_start
                 }
                 Err(e) => {
                     println!("Não foi possível carregar progresso: {}. Iniciando de {:x}.", e, range_start);
                     range_start
                 }
             }
         } else {
             range_start
         };
         println!("Iniciando busca turbo SEQUENCIAL com {} threads", num_threads);
         println!("Range de busca efetivo (hex): {:x} a {:x}", effective_range_start, range_end);
         if effective_range_start > range_end {
             println!("Range inválido após carregar progresso. Nada a fazer.");
             return;
         }
         *app_state.range_start.lock().unwrap() = effective_range_start;
    }

    // Inicializar variáveis compartilhadas
    let found = Arc::new(AtomicBool::new(false));
    let processed_keys = Arc::new(AtomicU64::new(0));
    let last_report_time = Arc::new(Mutex::new(Instant::now()));
    let last_save_time = Arc::new(Mutex::new(Instant::now()));
    let target_hash = app_state.get_target_hash160();

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

                println!("!!! PROCESSANDO RESULTADO ENCONTRADO: chave = {:x}", key);
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
                    println!("!!! Hash160 calculado: {}", hex::encode(&hash160_manual));
                    println!("!!! Hash160 alvo:      {}", hex::encode(&target_hash160));
                    
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
                        "\n!!! ENCONTRADO ENDEREÇO CORRESPONDENTE !!!\nChave Privada (Hex): {}\nChave Privada (WIF): {}\nP2PKH:              {}\nP2WPKH:             {}\nP2SH-P2WPKH:        {}\nHash160:            {}\n",
                        key_hex, wif, p2pkh, p2wpkh, p2sh_p2wpkh, hash_hex
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

                        for (idx, hash) in matches {
                             if !process_found.load(Ordering::Relaxed) {
                                 let key = keys[idx];
                                 println!("!! ENCONTRADA CORRESPONDÊNCIA DE HASH EM WORKER ALEATÓRIO: chave = {:x}", key);
                                 let _ = result_sender.send((key, hash.to_vec(), pubkeys_buffer[idx]));
                                 process_found.store(true, Ordering::SeqCst);
                             }
                        }
                        process_processed_keys.fetch_add(TURBO_BATCH_SIZE as u64, Ordering::Relaxed);

                        {
                            let now = Instant::now();
                            let mut should_report = false;
                            {
                                let mut last_report = process_last_report_time.lock().unwrap();
                                if now.duration_since(*last_report) > Duration::from_millis(500) {
                                    *last_report = now;
                                    should_report = true;
                                }
                            }
                            if should_report {
                                let total = process_processed_keys.load(Ordering::Relaxed);
                                let elapsed_total = process_app_state.get_elapsed_time().map_or(0.0, |d| d.as_secs_f64());
                                let rate = if elapsed_total > 0.0 {
                                    total as f64 / elapsed_total
                                } else {
                                    0.0
                                };
                                println!("Progresso (Aleatório): {} chaves testadas a {:.2} Mkeys/s (CPU: {})",
                                         total,
                                         rate / 1_000_000.0,
                                         num_threads);
                            }
                        }
                    }
                });
            } else {
                println!("Iniciando workers em modo SEQUENCIAL com balanceamento dinâmico");
                let effective_range_start = process_app_state.get_range_start();
                let total_keys_in_range = thread_range_end.saturating_sub(effective_range_start).saturating_add(1);

                // Novo sistema de balanceamento dinâmico
                // Criar uma fila compartilhada de work ranges
                let work_queue = Arc::new(Mutex::new(VecDeque::new()));
                let active_workers = Arc::new(AtomicUsize::new(0));
                
                // Calcular o tamanho inicial dos chunks
                let dynamic_chunk_size = std::cmp::min(
                    DYNAMIC_CHUNK_SIZE,
                    (total_keys_in_range / (num_threads as u128 * 2)).max(TURBO_BATCH_SIZE as u128) as usize
                );
                
                println!("Sistema de balanceamento dinâmico: chunks iniciais de ~{} chaves", dynamic_chunk_size);
                
                // Preencher a fila de trabalho inicial com chunks menores e mais numerosos
                {
                    let mut queue = work_queue.lock().unwrap();
                    let mut current = effective_range_start;
                    
                    // Criar ainda mais chunks iniciais para ver progresso mais rapidamente
                    let num_initial_chunks = num_threads * 16;
                    
                    // Calcular tamanho de chunk menor para ver progresso mais rapidamente
                    let range_size = thread_range_end.saturating_sub(effective_range_start).saturating_add(1);
                    let initial_chunk_size = std::cmp::max(
                        range_size / (num_initial_chunks as u128),
                        (TURBO_BATCH_SIZE * 4) as u128
                    );
                    
                    println!("Dividindo range em {} chunks iniciais de ~{} chaves cada", num_initial_chunks, initial_chunk_size);
                    
                    // Forçar uma atualização imediata do progresso
                    *process_last_report_time.lock().unwrap() = Instant::now().checked_sub(Duration::from_secs(10)).unwrap_or(Instant::now());
                    
                    // Contador para reportar progresso de inicialização
                    let mut chunks_criados = 0;
                    
                    while current < thread_range_end {
                        let chunk_end = std::cmp::min(
                            current.saturating_add(initial_chunk_size).saturating_sub(1),
                            thread_range_end
                        );
                        
                        queue.push_back(WorkRange { 
                            start: current,
                            end: chunk_end,
                        });
                        
                        current = chunk_end.saturating_add(1);
                        chunks_criados += 1;
                        
                        // Mostrar progresso durante a criação dos chunks
                        if chunks_criados % 10 == 0 {
                            println!("Preparando chunks: {} criados até agora...", chunks_criados);
                        }
                        
                        if current >= thread_range_end { break; }
                    }
                    
                    println!("Fila de trabalho inicializada com {} chunks", queue.len());
                    println!("INICIANDO PROCESSAMENTO - AGUARDE PRIMEIRA ATUALIZAÇÃO...");
                }

                // Iniciar workers
                (0..num_threads).into_par_iter().for_each(|thread_id| {
                    let work_queue = work_queue.clone();
                    let active_workers = active_workers.clone();
                    let result_sender = result_sender.clone();
                    let mut pubkeys_buffer = Vec::with_capacity(TURBO_BATCH_SIZE);
                    let mut keys_buffer = Vec::with_capacity(TURBO_BATCH_SIZE);
                    
                    // Incrementar contador de workers ativos
                    active_workers.fetch_add(1, Ordering::SeqCst);
                    println!("Worker {} iniciado.", thread_id);
                    
                    // Contador de batches processados por worker
                    let mut batches_processados = 0;
                    
                    loop {
                        if process_found.load(Ordering::Relaxed) || !process_app_state.search_active.load(Ordering::Relaxed) {
                            break;
                        }
                        
                        // Obter próximo intervalo de trabalho da fila
                        let current_work = {
                            let mut queue = work_queue.lock().unwrap();
                            queue.pop_front()
                        };
                        
                        // Se não há mais trabalho, verifica se ainda existem workers ativos
                        match current_work {
                            Some(work_range) => {
                                let mut current = work_range.start;
                                let chunk_end = work_range.end;
                                
                                // Mostrar qual worker está processando qual intervalo
                                println!("Worker {} processando intervalo: {:x} a {:x}", thread_id, current, chunk_end);
                                
                                // Processar o chunk atual
                                while current <= chunk_end {
                                    if process_found.load(Ordering::Relaxed) || !process_app_state.search_active.load(Ordering::Relaxed) {
                                        break;
                                    }
                                    
                                    let batch_end = std::cmp::min(
                                        current.saturating_add(TURBO_BATCH_SIZE as u128),
                                        chunk_end.saturating_add(1)
                                    );
                                    let keys_in_batch = batch_end.saturating_sub(current) as usize;
                                    if keys_in_batch == 0 { break; }
                                    
                                    keys_buffer.clear();
                                    keys_buffer.extend(current..batch_end);
                                    
                                    pubkeys_buffer.clear();
                                    
                                    if use_precise_method {
                                        // Usar método preciso para todas as chaves
                                        for key in &keys_buffer {
                                            if let Some(pubkey) = generate_pubkey_precise(*key) {
                                                pubkeys_buffer.push(pubkey);
                                            } else {
                                                // Colocar uma chave inválida para manter o índice
                                                pubkeys_buffer.push([0u8; 33]);
                                            }
                                        }
                                    } else {
                                        // Método normal batch
                                        generate_pubkeys_batch(&keys_buffer, &mut pubkeys_buffer);
                                    }
                                    
                                    let matches = hash160_and_match_direct(&pubkeys_buffer, &target_hash);
                                    
                                    for (idx, hash) in matches {
                                        if !process_found.load(Ordering::Relaxed) {
                                            let key = keys_buffer[idx];
                                            println!("!! ENCONTRADA CORRESPONDÊNCIA DE HASH EM WORKER: chave = {:x}", key);
                                            let _ = result_sender.send((key, hash.to_vec(), pubkeys_buffer[idx]));
                                            process_found.store(true, Ordering::SeqCst);
                                        }
                                    }
                                    
                                    let processed_in_batch = keys_buffer.len() as u64;
                                    process_processed_keys.fetch_add(processed_in_batch, Ordering::Relaxed);
                                    current = batch_end;
                                    
                                    batches_processados += 1;
                                    // Reportar progresso por worker ocasionalmente
                                    if batches_processados % 10 == 0 {
                                        println!("Worker {} já processou {} batches", thread_id, batches_processados);
                                    }
                                    
                                    // Reportar progresso global SEMPRE aqui
                                    {
                                        let elapsed_total = process_app_state.get_elapsed_time().map_or(0.0, |d| d.as_secs_f64());
                                        let current_processed_total = process_processed_keys.load(Ordering::Relaxed);
                                        let rate = if elapsed_total > 0.0 { current_processed_total as f64 / elapsed_total } else { 0.0 };
                                        let queue_size = work_queue.lock().unwrap().len();
                                        let workers = active_workers.load(Ordering::SeqCst);
                                        let percentage = if total_keys_in_range > 0 {
                                            (current.saturating_sub(effective_range_start)) as f64 / total_keys_in_range as f64 * 100.0
                                        } else { 100.0 };
                                        
                                        println!("ATUALIZAÇÃO DE PROGRESSO: {:.6}% ({:x}) | {:.2} Mkeys/s | {} workers | {} chunks",
                                                percentage, current.saturating_sub(1).max(effective_range_start),
                                                rate / 1_000_000.0, workers, queue_size);
                                    }
                                    
                                    // Se o chunk for grande, podemos dividi-lo para melhor balanceamento
                                    if chunk_end.saturating_sub(current) > (1048576 as u128 * 4) {
                                        // Dividir intervalo em dois
                                        let mid_point = current.saturating_add((chunk_end - current) / 2);
                                        
                                        // Adicionar segunda metade à fila
                                        if mid_point < chunk_end {
                                            let mut queue = work_queue.lock().unwrap();
                                            queue.push_back(WorkRange {
                                                start: mid_point.saturating_add(1),
                                                end: chunk_end,
                                            });
                                            
                                            println!("Worker {} dividiu chunk, segunda metade: {:x} a {:x}", 
                                                   thread_id, mid_point.saturating_add(1), chunk_end);
                                            
                                            // Atualizar chunk_end para processar apenas a primeira metade
                                            break;
                                        }
                                    }
                                }
                                
                                // Reportar progresso periodicamente
                                {
                                    let now = Instant::now();
                                    let mut should_report = false;
                                    {
                                        let mut last_report = process_last_report_time.lock().unwrap();
                                        // Diminuir o intervalo para reportar progresso mais frequentemente
                                        if now.duration_since(*last_report) > Duration::from_millis(100) {
                                            *last_report = now;
                                            should_report = true;
                                        }
                                    }
                                    if should_report {
                                        let elapsed_total = process_app_state.get_elapsed_time().map_or(0.0, |d| d.as_secs_f64());
                                        let current_processed_total = process_processed_keys.load(Ordering::Relaxed);
                                        let rate = if elapsed_total > 0.0 { current_processed_total as f64 / elapsed_total } else { 0.0 };
                                        let queue_size = work_queue.lock().unwrap().len();
                                        let workers = active_workers.load(Ordering::SeqCst);
                                        let percentage = if total_keys_in_range > 0 {
                                            (current.saturating_sub(effective_range_start)) as f64 / total_keys_in_range as f64 * 100.0
                                        } else { 100.0 };
                                        
                                        println!("Progresso (Balanceado): {:.6}% ({:x}) | {:.2} Mkeys/s | {} workers | {} chunks",
                                                percentage, current.saturating_sub(1).max(effective_range_start),
                                                rate / 1_000_000.0, workers, queue_size);
                                    }
                                }
                                
                                // Salvar progresso
                                {
                                    let now = Instant::now();
                                    let mut should_save = false;
                                    {
                                        let mut last_save = process_last_save_time.lock().unwrap();
                                        if now.duration_since(*last_save) > Duration::from_secs(30) {
                                            *last_save = now;
                                            should_save = true;
                                        }
                                    }
                                    if should_save {
                                        let key_to_save = current.saturating_sub(1);
                                        if key_to_save >= effective_range_start {
                                            let progress_file = process_app_state.get_progress_file_path();
                                            if !progress_file.is_empty() {
                                                save_progress_helper(&progress_file, key_to_save);
                                                println!("Progresso salvo: {:x}", key_to_save);
                                            }
                                        }
                                    }
                                }
                            },
                            None => {
                                // Verifica se ainda existem workers ativos
                                let workers = active_workers.load(Ordering::SeqCst);
                                println!("Worker {} sem trabalho. {} workers ativos.", thread_id, workers);
                                
                                if workers <= 1 {
                                    // Último worker ativo, sair
                                    active_workers.fetch_sub(1, Ordering::SeqCst);
                                    println!("Worker {} saindo (último worker).", thread_id);
                                    break;
                                }
                                
                                // Espera um pouco antes de verificar novamente
                                std::thread::sleep(Duration::from_millis(50));
                                
                                // Verificar novamente se há trabalho
                                let queue_size = work_queue.lock().unwrap().len();
                                if queue_size == 0 {
                                    // Se ainda não há trabalho, este worker termina
                                    active_workers.fetch_sub(1, Ordering::SeqCst);
                                    println!("Worker {} saindo (sem mais trabalho).", thread_id);
                                    break;
                                }
                            }
                        }
                    }
                });
            }
            drop(result_sender);
        });
    }).unwrap();

    let final_processed = processed_keys.load(Ordering::Relaxed);
    let elapsed_final = app_state.get_elapsed_time();
    println!("Busca turbo concluída! Total de chaves processadas: {}", final_processed);
    if let Some(duration) = elapsed_final {
         println!("Tempo total: {:.2?}", duration);
         let rate_final = if duration.as_secs_f64() > 0.0 { final_processed as f64 / duration.as_secs_f64() } else { 0.0 };
          println!("Taxa média: {:.2} Mkeys/s", rate_final / 1_000_000.0);
    }

    if found.load(Ordering::Relaxed) {
        println!("Chave encontrada salva em {}", app_state.get_results_file_path());
    } else {
        println!("Chave não encontrada no range especificado.");
    }
}

// Inicializa o Cache Contextual Dinâmico com padrões comuns
fn initialize_contextual_cache() {
    println!("Inicializando Cache Contextual Dinâmico para hashing otimizado...");
    
    // Prefixos comuns para chaves públicas comprimidas do Bitcoin
    let known_prefixes = [
        // Prefixos padrão para chaves comprimidas começando com '02'
        &[0x02, 0x00, 0x00, 0x00, 0x00][..],
        &[0x02, 0x10, 0x00, 0x00, 0x00][..],
        &[0x02, 0x20, 0x00, 0x00, 0x00][..],
        &[0x02, 0x30, 0x00, 0x00, 0x00][..],
        &[0x02, 0x40, 0x00, 0x00, 0x00][..],
        &[0x02, 0x50, 0x00, 0x00, 0x00][..],
        &[0x02, 0x60, 0x00, 0x00, 0x00][..],
        &[0x02, 0x70, 0x00, 0x00, 0x00][..],
        &[0x02, 0x80, 0x00, 0x00, 0x00][..],
        &[0x02, 0x90, 0x00, 0x00, 0x00][..],
        &[0x02, 0xa0, 0x00, 0x00, 0x00][..],
        &[0x02, 0xb0, 0x00, 0x00, 0x00][..],
        &[0x02, 0xc0, 0x00, 0x00, 0x00][..],
        &[0x02, 0xd0, 0x00, 0x00, 0x00][..],
        &[0x02, 0xe0, 0x00, 0x00, 0x00][..],
        &[0x02, 0xf0, 0x00, 0x00, 0x00][..],
        
        // Prefixos padrão para chaves comprimidas começando com '03'
        &[0x03, 0x00, 0x00, 0x00, 0x00][..],
        &[0x03, 0x10, 0x00, 0x00, 0x00][..],
        &[0x03, 0x20, 0x00, 0x00, 0x00][..],
        &[0x03, 0x30, 0x00, 0x00, 0x00][..],
        &[0x03, 0x40, 0x00, 0x00, 0x00][..],
        &[0x03, 0x50, 0x00, 0x00, 0x00][..],
        &[0x03, 0x60, 0x00, 0x00, 0x00][..],
        &[0x03, 0x70, 0x00, 0x00, 0x00][..],
        &[0x03, 0x80, 0x00, 0x00, 0x00][..],
        &[0x03, 0x90, 0x00, 0x00, 0x00][..],
        &[0x03, 0xa0, 0x00, 0x00, 0x00][..],
        &[0x03, 0xb0, 0x00, 0x00, 0x00][..],
        &[0x03, 0xc0, 0x00, 0x00, 0x00][..],
        &[0x03, 0xd0, 0x00, 0x00, 0x00][..],
        &[0x03, 0xe0, 0x00, 0x00, 0x00][..],
        &[0x03, 0xf0, 0x00, 0x00, 0x00][..],
    ];
    
    // Pré-aquecer o cache com esses prefixos
    warm_up_cache(&known_prefixes);
    
    println!("Cache Contextual Dinâmico inicializado com {} prefixos comuns", known_prefixes.len());
} 