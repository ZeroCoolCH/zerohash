// Declarar os módulos locais
mod app_state;
mod cli;
mod batch_hash;
mod batch_pubkey;
mod turbo_search;
mod stats;

// Usar tipos/funções dos módulos
use crate::app_state::AppState;
use crate::cli::Cli;
use crate::batch_hash::{supports_avx2, get_cache_manager};
use crate::turbo_search::{turbo_search};

use clap::Parser;
use std::{error::Error, sync::Arc, time::Instant};
use bs58;
use hex;
use rayon;
use std::sync::atomic::Ordering;
use ctrlc;
use std::fs::File;
use std::io::{BufReader, BufRead, Write};
use std::path::Path;
use std::process;
use rayon::ThreadPoolBuilder;
use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use parking_lot::RwLock;
use std::collections::HashMap;

// Constantes para arquivos de progresso
const PROGRESS_FILE: &str = "zerohash_progress.txt";
const JSON_PROGRESS_FILE: &str = "zerohash_progress.json";

// Estrutura para gerenciamento de progresso
#[derive(Serialize, Deserialize, Debug)]
struct ProgressEntry {
    address: String,
    range_start: String,  // Valor hex do início do range
    range_end: String,    // Valor hex do fim do range
    current_key: String,  // Valor hex da última chave processada
    timestamp: u64,       // Timestamp da última atualização
}

#[derive(Serialize, Deserialize, Debug)]
struct ProgressData {
    entries: Vec<ProgressEntry>,
}

fn save_progress_json(address: &str, range_start: u128, range_end: u128, current_key: u128) -> Result<(), String> {
    let mut progress_data = if Path::new(JSON_PROGRESS_FILE).exists() {
        match load_progress_data() {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Erro ao carregar arquivo de progresso existente: {}", e);
                ProgressData { entries: Vec::new() }
            }
        }
    } else {
        ProgressData { entries: Vec::new() }
    };
    
    // Verificar se já existe uma entrada para este endereço e range
    let mut found = false;
    for entry in &mut progress_data.entries {
        if entry.address == address &&
           entry.range_start == format!("{:x}", range_start) &&
           entry.range_end == format!("{:x}", range_end) {
            // Atualizar entrada existente
            entry.current_key = format!("{:x}", current_key);
            entry.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            found = true;
            break;
        }
    }
    
    // Se não encontrou entrada existente, criar nova
    if !found {
        progress_data.entries.push(ProgressEntry {
            address: address.to_string(),
            range_start: format!("{:x}", range_start),
            range_end: format!("{:x}", range_end),
            current_key: format!("{:x}", current_key),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
    }
    
    // Salvar arquivo JSON
    let serialized = match serde_json::to_string_pretty(&progress_data) {
        Ok(s) => s,
        Err(e) => return Err(format!("Erro ao serializar dados de progresso: {}", e)),
    };
    
    let mut file = match std::fs::File::create(JSON_PROGRESS_FILE) {
        Ok(f) => f,
        Err(e) => return Err(format!("Erro ao criar arquivo de progresso JSON: {}", e)),
    };
    
    if let Err(e) = file.write_all(serialized.as_bytes()) {
        return Err(format!("Erro ao escrever arquivo de progresso JSON: {}", e));
    }
    
    Ok(())
}

fn load_progress_data() -> Result<ProgressData, String> {
    let file = match std::fs::File::open(JSON_PROGRESS_FILE) {
        Ok(f) => f,
        Err(e) => return Err(format!("Erro ao abrir arquivo de progresso: {}", e)),
    };
    
    let reader = std::io::BufReader::new(file);
    match serde_json::from_reader(reader) {
        Ok(data) => Ok(data),
        Err(e) => Err(format!("Erro ao deserializar dados de progresso: {}", e)),
    }
}

fn load_specific_progress(address: &str, range_start: u128, range_end: u128) -> Result<u128, String> {
    let progress_data = load_progress_data()?;
    
    let range_start_hex = format!("{:x}", range_start);
    let range_end_hex = format!("{:x}", range_end);
    
    for entry in progress_data.entries {
        if entry.address == address && 
           entry.range_start == range_start_hex && 
           entry.range_end == range_end_hex {
            // Encontrou a entrada correspondente
            match u128::from_str_radix(&entry.current_key, 16) {
                Ok(key) => return Ok(key),
                Err(e) => return Err(format!("Erro ao converter current_key para u128: {}", e)),
            }
        }
    }
    
    Err(format!("Nenhum progresso encontrado para o endereço {} e range {:x}-{:x}", 
                address, range_start, range_end))
}

fn print_hardware_capabilities(verbose: bool) {
    if !verbose {
        return;
    }

    // Obter informações via CacheManager
    let cache_manager = get_cache_manager();
    let avx2_support = cache_manager.has_advanced_instruction_support();
    let recommended_threads = cache_manager.recommended_parallelism();

    println!("📊 Informações do Hardware:");
    println!("├─ Suporte AVX2: {}", if avx2_support { "✅ Sim" } else { "❌ Não" });
    println!("├─ Cache Hierárquico: ✅ Ativo (L1/L2/L3)");
    println!("├─ Buffer Pool Otimizado: ✅ Ativo");
    println!("├─ Pipeline de Processamento: ✅ Ativo");
    println!("├─ Núcleos físicos: {}", rayon::current_num_threads());
    println!("├─ Threads lógicos: {}", num_cpus::get());
    println!("└─ Threads recomendados: {}", recommended_threads);
    println!();
}

// Função para aquecer o cache com prefixos conhecidos
fn warmup_cache() {
    // Usar a nova interface CacheManager
    let cache_manager = get_cache_manager();
    
    println!("Inicializando cache de hashing...");
    
    // Pré-carregar prefixos comuns
    cache_manager.preload_common_prefixes();
    
    // Exibir informações sobre o suporte a instruções avançadas
    println!("Sistema inicializado com suporte a instruções avançadas: {}", 
             if cache_manager.has_advanced_instruction_support() { "Sim" } else { "Não" });
}

fn main() -> Result<(), Box<dyn Error>> {
    // Inicializar o sistema otimizado
    warmup_cache();
    
    // Exibir informações de capacidades do hardware se a flag de verbose estiver ativa
    if let Ok(args) = cli::parse_args() {
        print_hardware_capabilities(args.verbose);
    }

    // --- Parsear Argumentos CLI --- 
    let cli = Cli::parse();

    // --- Imprimir Banner ---
    println!("=============================");
    println!("       Zerohash v{}", env!("CARGO_PKG_VERSION"));
    println!("      By ZeroCoolCH");
    println!("=============================\n");

    // --- Validar e Processar Argumentos --- 
    let target_address = &cli.address;
    let range_start_hex_cli = &cli.range_start;
    let range_end_hex_cli = &cli.range_end;

    // Validar endereço e obter hash160
    let decoded_data = match bs58::decode(target_address).with_check(None).into_vec() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Erro ao decodificar endereço Base58Check: {}", e);
            std::process::exit(1);
        }
    };
    if decoded_data.len() != 21 {
        eprintln!("Erro: Comprimento inválido para endereço Base58Check P2PKH (esperado 21 bytes).");
        std::process::exit(1);
    }
    let version_byte = decoded_data[0];
    if version_byte != 0x00 {
        eprintln!(
            "Erro: Version byte inválido para endereço P2PKH mainnet (esperado 0x00, encontrado 0x{:02x}).",
            version_byte
        );
        std::process::exit(1);
    }
    
    // Obter o hash160 original do endereço
    let original_target_pubkey_hash: [u8; 20] = decoded_data[1..21]
        .try_into()
        .expect("Slice len garantido por check anterior");
    let target_pubkey_hash_hex = hex::encode(&original_target_pubkey_hash);
    
    // Parsear ranges como u128
    let range_start_cli = u128::from_str_radix(range_start_hex_cli, 16)
        .map_err(|e| format!("Falha ao parsear início do range hexadecimal da CLI: {}", e))?;
    let range_end = u128::from_str_radix(range_end_hex_cli, 16)
        .map_err(|e| format!("Falha ao parsear fim do range hexadecimal da CLI: {}", e))?;

    // --- Carregar Progresso (apenas se não for modo random) --- 
    let mut range_start = range_start_cli;
    let mut resumed = false;
    if !cli.random { // Só carregar/salvar progresso se NÃO for modo random
        // Verificar primeiro pelo arquivo JSON
        if Path::new(JSON_PROGRESS_FILE).exists() {
            println!("Verificando progresso específico para endereço {} e range {:x}-{:x} no arquivo JSON...", 
                     target_address, range_start_cli, range_end);
            
            match load_specific_progress(target_address, range_start_cli, range_end) {
                Ok(last_key_saved) => {
                    if last_key_saved >= range_start_cli && last_key_saved < range_end {
                        println!("Progresso JSON encontrado. Retomando de: {:x}", last_key_saved + 1);
                        range_start = last_key_saved + 1;
                        resumed = true;
                    } else {
                        println!("Progresso JSON ({:x}) inválido/fora do range. Ignorando.", last_key_saved);
                    }
                },
                Err(e) => {
                    println!("Não foi possível carregar progresso JSON específico: {}", e);
                    
                    // Tentar o arquivo de progresso antigo como fallback
                    if let Ok(file) = File::open(PROGRESS_FILE) {
                        let reader = BufReader::new(file);
                        if let Some(Ok(line)) = reader.lines().next() {
                            if let Ok(last_key_saved) = u128::from_str_radix(&line.trim(), 16) {
                                if last_key_saved >= range_start_cli && last_key_saved < range_end {
                                    println!("Progresso legado encontrado. Retomando de: {:x}", last_key_saved + 1);
                                    range_start = last_key_saved + 1;
                                    resumed = true;
                                } else {
                                    println!("Progresso legado ({:x}) inválido/fora do range. Ignorando.", last_key_saved);
                                }
                            } else {
                                println!("Erro ao parsear progresso legado, ignorando.");
                            }
                        } else {
                            println!("Arquivo de progresso legado vazio/ilegível, ignorando.");
                        }
                    } else {
                        println!("Nenhum progresso legado encontrado.");
                    }
                }
            }
        } else if let Ok(file) = File::open(PROGRESS_FILE) {
            // Arquivo JSON não existe, verificar o arquivo de progresso antigo
            println!("Arquivo de progresso JSON não encontrado, verificando progresso legado...");
            let reader = BufReader::new(file);
            if let Some(Ok(line)) = reader.lines().next() {
                if let Ok(last_key_saved) = u128::from_str_radix(&line.trim(), 16) {
                    if last_key_saved >= range_start_cli && last_key_saved < range_end {
                        println!("Progresso legado encontrado. Retomando de: {:x}", last_key_saved + 1);
                        range_start = last_key_saved + 1;
                        resumed = true;
                    } else {
                        println!("Progresso legado ({:x}) inválido/fora do range. Ignorando.", last_key_saved);
                    }
                } else {
                     println!("Erro ao parsear progresso legado, ignorando.");
                }
            } else {
                 println!("Arquivo de progresso legado vazio/ilegível, ignorando.");
            }
        } else {
            println!("Nenhum arquivo de progresso encontrado.");
        }
    } else {
        println!("Modo Aleatório Ativado: Progresso será ignorado e não será salvo.");
        // Garantir que range_start é o da CLI no modo aleatório
        range_start = range_start_cli;
        resumed = false; // Nunca retoma no modo aleatório
    }

    // Verificar range após carregar progresso
    if range_start > range_end {
        eprintln!(
            "Erro: O início do range efetivo ({:x}) é maior que o fim ({:x}). Nada a fazer.",
            range_start, range_end
        );
        std::process::exit(1);
    }
    // Calcular total de chaves como u128
    let total_keys_in_range: u128 = range_end.saturating_sub(range_start).saturating_add(1);

    // --- Configurar Rayon Threads --- 
    let actual_num_threads;
    if cli.threads > 0 {
        // Verificar se o pool global já está inicializado
        let thread_pool_res = rayon::ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global();
        
        // Se já estiver inicializado, apenas usar o número de threads especificado
        if let Err(ref e) = thread_pool_res {
            if e.to_string().contains("already been initialized") {
                println!("Pool de threads já inicializado. Usando configuração existente.");
                actual_num_threads = rayon::current_num_threads();
            } else {
                // Outro erro, retornar
                return Err(format!("Falha ao construir thread pool global: {}", e).into());
            }
        } else {
            actual_num_threads = cli.threads;
            println!("Pool de threads configurado com {} threads.", actual_num_threads);
        }
    } else {
        actual_num_threads = rayon::current_num_threads();
        println!(
            "Usando todos os núcleos disponíveis ({} núcleos lógicos).",
            actual_num_threads
        );
    }

    // Mostrar informações do sistema otimizado
    println!("\n=== OTIMIZAÇÕES AVANÇADAS ===");
    println!("Cache Hierárquico: ATIVADO");
    println!("- Sistema de cache L1/L2/L3 para estados SHA-256");
    println!("- Vetorização avançada com instruções SIMD");
    println!("- Buffer pool otimizado para redução de alocações");
    println!("\n=== RECURSOS ===");
    println!("Pipeline de Processamento: ATIVADO");
    println!("- Paralelismo de dados otimizado para baixa latência");
    println!("- Gerenciamento de progresso JSON robusto\n");

    // --- Inicialização do AppState --- 
    println!("Endereço Alvo: {}", target_address);
    println!("Hash da Chave Pública Alvo (Hash160): {}", target_pubkey_hash_hex);
    println!("Início do Intervalo (hex): {:x}{}", range_start, if resumed { " (Retomado)" } else { "" });
    println!("Fim do Intervalo (hex): {:x}", range_end);
    println!("Total de chaves no intervalo (apenas para informação no modo aleatório): {}", total_keys_in_range);
    
    let app_state = Arc::new(AppState::new(target_address));
    
    // Atualizar o hash160 do target
    {
        let mut target_hash = app_state.target_pubkey_hash.lock().unwrap();
        target_hash.copy_from_slice(&original_target_pubkey_hash);
    }
    
    // Configurar os campos adicionais do AppState
    app_state.update_config(
        range_start,
        range_end,
        actual_num_threads,
        resumed,
        PROGRESS_FILE,
        0, // zero_prefix_length, não estamos usando prefixos zero
        cli.random
    );
    
    // --- Configurar Handler Ctrl+C --- 
    let app_state_clone_for_ctrlc = app_state.clone();
    ctrlc::set_handler(move || {
        println!("\nCtrl+C recebido! Sinalizando parada elegante...");
        app_state_clone_for_ctrlc.search_active.store(false, Ordering::SeqCst);
    }).expect("Erro ao configurar o handler Ctrl+C");

    // --- Iniciar busca com o sistema otimizado ---
    app_state.search_active.store(true, Ordering::SeqCst);
    app_state.set_start_time(Instant::now());

    // Iniciar busca turbo otimizada
    turbo_search(app_state);
    
    Ok(())
}

