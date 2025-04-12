// Declarar os módulos locais
mod app_state;
mod cli;
mod batch_pubkey;
mod batch_hash;
mod turbo_search;

// Usar tipos/funções dos módulos
use crate::app_state::AppState;
use crate::cli::Cli;
use crate::turbo_search::turbo_search;

use clap::Parser;
use std::{error::Error, sync::Arc, time::Instant};
use bs58;
use hex;
use rayon;

// Referenciar constante do turbo_search
use crate::turbo_search::PROGRESS_FILE;

// Adicionar imports necessários
use std::sync::atomic::Ordering;
use ctrlc;
use std::fs::File;
use std::io::{BufReader, BufRead};

#[link(name = "hasher", kind = "static")]
extern "C" {
    fn calculate_hash160_batch_cpp(
        pubkeys_ptr: *const u8, 
        num_keys: usize,
        hashes_out_ptr: *mut u8
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    // --- Parsear Argumentos CLI --- 
    let cli = Cli::parse();

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
    let target_pubkey_hash: [u8; 20] = decoded_data[1..21]
        .try_into()
        .expect("Slice len garantido por check anterior");
    let target_pubkey_hash_hex = hex::encode(target_pubkey_hash);

    // Parsear ranges como u128
    let range_start_cli = u128::from_str_radix(range_start_hex_cli, 16)
        .map_err(|e| format!("Falha ao parsear início do range hexadecimal da CLI: {}", e))?;
    let range_end = u128::from_str_radix(range_end_hex_cli, 16)
        .map_err(|e| format!("Falha ao parsear fim do range hexadecimal da CLI: {}", e))?;

    // --- Carregar Progresso (apenas se não for modo random) --- 
    let mut range_start = range_start_cli;
    let mut resumed = false;
    if !cli.random { // Só carregar/salvar progresso se NÃO for modo random
        if let Ok(file) = File::open(PROGRESS_FILE) {
            let reader = BufReader::new(file);
            if let Some(Ok(line)) = reader.lines().next() {
                if let Ok(last_key_saved) = u128::from_str_radix(&line.trim(), 16) {
                    if last_key_saved >= range_start_cli && last_key_saved < range_end {
                        println!("Progresso sequencial encontrado. Retomando de: {:x}", last_key_saved + 1);
                        range_start = last_key_saved + 1;
                        resumed = true;
                    } else {
                        println!("Progresso sequencial ({:x}) inválido/fora do range. Ignorando.", last_key_saved);
                    }
                } else {
                     println!("Erro ao parsear progresso sequencial, ignorando.");
                }
            } else {
                 println!("Arquivo de progresso vazio/ilegível, ignorando.");
            }
        } else {
            println!("Nenhum progresso sequencial encontrado.");
        }
    } else {
        println!("Modo Aleatório Ativado: Progresso sequencial será ignorado e não será salvo.");
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
        rayon::ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()
            .map_err(|e| format!("Falha ao construir thread pool global: {}", e))?;
        actual_num_threads = cli.threads;
        println!("Usando {} threads.", actual_num_threads);
    } else {
        actual_num_threads = rayon::current_num_threads();
        println!(
            "Usando todos os núcleos disponíveis ({} núcleos lógicos).",
            actual_num_threads
        );
    }

    // ADICIONAR AQUI:
    println!("\n=== OTIMIZAÇÕES AVANÇADAS ===");
    println!("Cache Contextual Dinâmico: ATIVADO");
    println!("- Acelera o cálculo de hash160 usando estados intermediários de SHA-256");
    println!("- Adapta-se automaticamente a padrões nas chaves públicas");
    println!("- Compatível com o padrão Bitcoin 100%\n");

    // --- Inicialização do AppState --- 
    println!("Endereço Alvo: {}", target_address);
    println!("Hash da Chave Pública Alvo (Hash160): {}", target_pubkey_hash_hex);
    println!("Início do Intervalo (hex): {:x}{}", range_start, if resumed { " (Retomado)" } else { "" });
    println!("Fim do Intervalo (hex): {:x}", range_end);
    println!("Total de chaves no intervalo (apenas para informação no modo aleatório): {}", total_keys_in_range);
    
    let app_state = Arc::new(AppState::new(target_address));
    
    // Configurar os campos adicionais do AppState
    app_state.update_config(
        range_start,
        range_end,
        actual_num_threads,
        resumed,
        PROGRESS_FILE,
        1, // Zero prefix length padrão
        cli.random // <-- Passar a flag random aqui
    );
    
    // Atualizar o hash160 do target
    {
        let mut target_hash = app_state.target_pubkey_hash.lock().unwrap();
        target_hash.copy_from_slice(&target_pubkey_hash);
    }
    
    // --- Configurar Handler Ctrl+C --- 
    let app_state_clone_for_ctrlc = app_state.clone();
    ctrlc::set_handler(move || {
        println!("\nCtrl+C recebido! Sinalizando parada elegante...");
        app_state_clone_for_ctrlc.search_active.store(false, Ordering::SeqCst);
    }).expect("Erro ao configurar o handler Ctrl+C");

    // --- Iniciar busca com o modo turbo ---
    println!("=== INICIANDO BUSCA DE ALTA PERFORMANCE ===");
    app_state.search_active.store(true, Ordering::SeqCst);
    app_state.set_start_time(Instant::now());
    
    // Iniciar busca de alta performance
    turbo_search(app_state.clone());
    
    Ok(())
}
