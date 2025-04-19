// stats.rs - Sistema profissional de monitoramento de performance
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::fmt;
use std::collections::VecDeque;
use parking_lot::RwLock;
use colored::*;

// Tamanho do histórico de medições para cálculo de média móvel
const HISTORY_SIZE: usize = 5; // Reduzido para ser mais responsivo às mudanças

/// Estrutura para armazenar estatísticas de desempenho
#[derive(Clone)]
pub struct PerformanceStats {
    // Dados principais
    start_time: Arc<Mutex<Instant>>,
    current_key: Arc<Mutex<u128>>,
    total_keys: Arc<Mutex<u128>>,
    
    // Contadores
    processed_keys: Arc<AtomicU64>, // Mudado para AtomicU64 para melhor performance
    hashes_computed: Arc<AtomicU64>, // Mudado para AtomicU64 para melhor performance
    cache_hits: Arc<AtomicU64>,     // Mudado para AtomicU64 para melhor performance
    cache_misses: Arc<AtomicU64>,   // Mudado para AtomicU64 para melhor performance
    
    // Intervalos
    range_start: Arc<Mutex<u128>>,
    range_end: Arc<Mutex<u128>>,
    
    // História
    last_processed_keys: Arc<AtomicU64>, // Adicionar contador anterior para cálculo de taxa instantânea
    last_update_time: Arc<Mutex<Instant>>, // Último momento em que as estatísticas foram atualizadas
    recent_rates: Arc<Mutex<VecDeque<f64>>>, // Mudou para VecDeque para operações mais eficientes
}

/// Estrutura para capturar um snapshot das estatísticas para exibição
pub struct PerformanceSnapshot {
    pub elapsed_time: Duration,
    pub processed_keys: u64,
    pub hashes_computed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub current_key: u128,
    pub total_keys: u128,
    pub range_start: u128,
    pub range_end: u128,
    pub current_rate: f64,
    pub average_rate: f64,
    pub cache_hit_rate: f64,
    pub eta: Option<Duration>,
    pub progress_percent: f64,
}

impl PerformanceSnapshot {
    // Métodos públicos para acessar os campos
    pub fn get_elapsed_time(&self) -> &Duration {
        &self.elapsed_time
    }
    
    pub fn get_processed_keys(&self) -> u64 {
        self.processed_keys
    }
    
    pub fn get_hashes_computed(&self) -> u64 {
        self.hashes_computed
    }
    
    pub fn get_cache_hits(&self) -> u64 {
        self.cache_hits
    }
    
    pub fn get_cache_misses(&self) -> u64 {
        self.cache_misses
    }
    
    pub fn get_current_key(&self) -> u128 {
        self.current_key
    }
    
    pub fn get_total_keys(&self) -> u128 {
        self.total_keys
    }
    
    pub fn get_range_start(&self) -> u128 {
        self.range_start
    }
    
    pub fn get_range_end(&self) -> u128 {
        self.range_end
    }
    
    pub fn get_current_rate(&self) -> f64 {
        self.current_rate
    }
    
    pub fn get_average_rate(&self) -> f64 {
        self.average_rate
    }
    
    pub fn get_cache_hit_rate(&self) -> f64 {
        self.cache_hit_rate
    }
    
    pub fn get_eta(&self) -> Option<Duration> {
        self.eta
    }
    
    pub fn get_progress_percent(&self) -> f64 {
        self.progress_percent
    }
}

impl PerformanceStats {
    /// Cria uma nova instância de estatísticas de desempenho
    pub fn new(total_keys: u128, range_start: u128) -> Self {
        let now = Instant::now();
        Self {
            start_time: Arc::new(Mutex::new(now)),
            current_key: Arc::new(Mutex::new(range_start)),
            total_keys: Arc::new(Mutex::new(total_keys)),
            processed_keys: Arc::new(AtomicU64::new(0)),
            hashes_computed: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            range_start: Arc::new(Mutex::new(range_start)),
            range_end: Arc::new(Mutex::new(range_start.saturating_add(total_keys.saturating_sub(1)))),
            last_processed_keys: Arc::new(AtomicU64::new(0)),
            last_update_time: Arc::new(Mutex::new(now)),
            recent_rates: Arc::new(Mutex::new(VecDeque::with_capacity(HISTORY_SIZE))),
        }
    }
    
    /// Reinicia as estatísticas
    pub fn reset(&self) {
        let now = Instant::now();
        *self.start_time.lock().unwrap() = now;
        *self.last_update_time.lock().unwrap() = now;
        self.processed_keys.store(0, Ordering::Relaxed);
        self.hashes_computed.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.last_processed_keys.store(0, Ordering::Relaxed);
        self.recent_rates.lock().unwrap().clear();
    }
    
    /// Adiciona keys processadas ao contador
    pub fn add_processed_keys(&self, count: u64) {
        self.processed_keys.fetch_add(count, Ordering::Relaxed);
    }
    
    /// Adiciona hashes computados ao contador
    pub fn add_hashes_computed(&self, count: u64) {
        self.hashes_computed.fetch_add(count, Ordering::Relaxed);
    }
    
    /// Adiciona hits de cache ao contador
    pub fn add_cache_hits(&self, count: u64) {
        self.cache_hits.fetch_add(count, Ordering::Relaxed);
    }
    
    /// Adiciona misses de cache ao contador
    pub fn add_cache_misses(&self, count: u64) {
        self.cache_misses.fetch_add(count, Ordering::Relaxed);
    }
    
    /// Atualiza a chave atual sendo processada
    pub fn update_current_key(&self, key: u128) {
        let mut current = self.current_key.lock().unwrap();
        *current = key;
    }
    
    /// Obtém um snapshot das estatísticas atuais
    pub fn get_snapshot(&self) -> PerformanceSnapshot {
        let now = Instant::now();
        let start_time = self.start_time.lock().unwrap().clone();
        let elapsed = now.duration_since(start_time);
        
        // Obter valores atômicos sem bloqueio
        let processed_keys = self.processed_keys.load(Ordering::Relaxed);
        let hashes_computed = self.hashes_computed.load(Ordering::Relaxed);
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);
        
        // Obter valores com bloqueio
        let current_key = *self.current_key.lock().unwrap();
        let total_keys = *self.total_keys.lock().unwrap();
        let range_start = *self.range_start.lock().unwrap();
        let range_end = *self.range_end.lock().unwrap();
        
        // Calcular taxa instantânea baseada no intervalo desde a última atualização
        let mut last_update_time = self.last_update_time.lock().unwrap();
        let last_update_elapsed = now.duration_since(*last_update_time);
        let last_count = self.last_processed_keys.load(Ordering::Relaxed);
        
        // Apenas atualizar se passou um tempo mínimo (50ms) para evitar flutuações extremas
        let current_rate = if last_update_elapsed.as_millis() >= 50 {
            // Calcular incremento desde a última atualização
            let increment = processed_keys.saturating_sub(last_count);
            let rate = if last_update_elapsed.as_secs_f64() > 0.0 {
                increment as f64 / last_update_elapsed.as_secs_f64()
            } else {
                0.0
            };
            
            // Registrar valores atuais para a próxima atualização
            *last_update_time = now;
            self.last_processed_keys.store(processed_keys, Ordering::Relaxed);
            
            // Atualizar histórico de taxas para média móvel
            let mut recent_rates = self.recent_rates.lock().unwrap();
            recent_rates.push_back(rate);
            if recent_rates.len() > HISTORY_SIZE {
                recent_rates.pop_front();
            }
            
            rate
        } else {
            // Se não passou tempo suficiente, usar a última taxa calculada
            if let Some(last_rate) = self.recent_rates.lock().unwrap().back() {
                *last_rate
            } else {
                // Se não temos nenhuma taxa anterior, calcular com base no tempo total
                if elapsed.as_secs_f64() > 0.0 {
                    processed_keys as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                }
            }
        };
        
        // Calcular taxa média usando média móvel
        let average_rate = {
            let recent_rates = self.recent_rates.lock().unwrap();
            if recent_rates.is_empty() {
                // Se não temos médias recentes, calcular com base no tempo total
                if elapsed.as_secs_f64() > 0.0 {
                    processed_keys as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                }
            } else {
                // Usar média móvel das taxas recentes
                recent_rates.iter().sum::<f64>() / recent_rates.len() as f64
            }
        };
        
        // Calcular taxa de acertos de cache
        let cache_hit_rate = if cache_hits + cache_misses > 0 {
            cache_hits as f64 / (cache_hits + cache_misses) as f64
        } else {
            0.0
        };
        
        // Calcular progresso
        let range_size = range_end.saturating_sub(range_start).saturating_add(1);
        let keys_remaining = if current_key > range_start {
            range_end.saturating_sub(current_key).saturating_add(1)
        } else {
            range_size
        };
        
        let progress_percent = if range_size > 0 {
            let processed_range = current_key.saturating_sub(range_start);
            processed_range as f64 / range_size as f64 * 100.0
        } else {
            0.0
        };
        
        // Calcular ETA
        let eta = if average_rate > 0.0 && keys_remaining > 0 {
            let seconds_remaining = keys_remaining as f64 / average_rate;
            // Verificar se o valor está dentro de um intervalo razoável para evitar pânico
            if seconds_remaining.is_finite() && seconds_remaining >= 0.0 && seconds_remaining <= 1e9 {
                Some(Duration::from_secs_f64(seconds_remaining))
            } else {
                None
            }
        } else {
            None
        };
        
        PerformanceSnapshot {
            elapsed_time: elapsed,
            processed_keys,
            hashes_computed,
            cache_hits,
            cache_misses,
            current_key,
            total_keys,
            range_start,
            range_end,
            current_rate,
            average_rate,
            cache_hit_rate,
            eta,
            progress_percent,
        }
    }

    /// Define a chave atual
    pub fn set_current_key(&self, key: u128) {
        let mut current = self.current_key.lock().unwrap();
        *current = key;
    }

    /// Obtém a chave atual
    pub fn get_current_key(&self) -> u128 {
        let current = self.current_key.lock().unwrap();
        *current
    }
}

/// Formata um grande número com separadores para facilitar a leitura
pub fn format_large_number(num: u64) -> String {
    let num_str = num.to_string();
    let mut result = String::new();
    let len = num_str.len();
    
    for (i, c) in num_str.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push('.');
        }
        result.push(c);
    }
    
    result
}

/// Formata um valor hexadecimal com tamanho específico
pub fn format_hex(value: u128, min_width: usize) -> String {
    let hex = format!("{:x}", value);
    if hex.len() >= min_width {
        hex
    } else {
        format!("{:0>width$}", hex, width = min_width)
    }
}

/// Formata uma duração para exibição amigável
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    
    if hours > 0 {
        format!("{}h {:02}m {:02}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {:02}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Limpa o terminal
pub fn clear_terminal() {
    print!("\x1B[2J\x1B[1;1H");
}

/// Estrutura para renderizar uma barra de progresso
pub struct ProgressBar {
    width: usize,
    percent: f64,
}

impl ProgressBar {
    pub fn new(width: usize, percent: f64) -> Self {
        Self {
            width,
            percent: percent.max(0.0).min(100.0),
        }
    }
    
    pub fn render(&self) -> String {
        let filled_width = ((self.width as f64) * self.percent / 100.0).round() as usize;
        let empty_width = self.width.saturating_sub(filled_width);
        
        let filled = "█".repeat(filled_width);
        let empty = "░".repeat(empty_width);
        
        format!("[{}{}] {:.2}%", filled.green(), empty, self.percent)
    }
}

/// Dashboard para exibir estatísticas de desempenho de forma amigável
#[derive(Clone)]
pub struct Dashboard {
    stats: PerformanceStats,
    last_update: Instant,
    update_interval: Duration,
}

impl Dashboard {
    pub fn new(stats: PerformanceStats) -> Self {
        Self {
            stats,
            last_update: Instant::now(),
            update_interval: Duration::from_millis(100),
        }
    }
    
    pub fn should_update(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_update) >= self.update_interval {
            self.last_update = now;
            true
        } else {
            false
        }
    }
    
    pub fn render(&self) -> String {
        let snapshot = self.stats.get_snapshot();
        
        let progress_bar = ProgressBar::new(50, snapshot.progress_percent);
        
        let mut output = String::new();
        
        // Cabeçalho
        output.push_str(&format!("{}\n", "■ ZEROHASH FINDER".bold().bright_green()));
        output.push_str(&format!("{}\n\n", "Search Professional Edition".bright_blue()));
        
        // Informações gerais
        output.push_str(&format!("{}: {}\n", "Tempo Decorrido".bold(), format_duration(snapshot.elapsed_time)));
        
        if let Some(eta) = snapshot.eta {
            output.push_str(&format!("{}: {} (estimado)\n", "Tempo Restante".bold(), format_duration(eta)));
        } else {
            output.push_str(&format!("{}: Calculando...\n", "Tempo Restante".bold()));
        }
        
        // Barra de progresso
        output.push_str(&format!("\n{}\n\n", progress_bar.render()));
        
        // Estatísticas de processamento
        output.push_str(&format!("{}: {} ({:.2} milhões)\n", 
            "Chaves Processadas".bold(), 
            format_large_number(snapshot.processed_keys),
            snapshot.processed_keys as f64 / 1_000_000.0));
        
        // Exibir taxas em MKeys/s para maior clareza
        let current_mkeys = snapshot.current_rate / 1_000_000.0;
        let current_rate_formatted = if current_mkeys >= 0.01 {
            format!("{:.2} MKeys/s", current_mkeys)
        } else {
            format!("{} Keys/s", format_large_number(snapshot.current_rate as u64))
        };
        
        let avg_mkeys = snapshot.average_rate / 1_000_000.0;
        let avg_rate_formatted = if avg_mkeys >= 0.01 {
            format!("{:.2} MKeys/s", avg_mkeys)
        } else {
            format!("{} Keys/s", format_large_number(snapshot.average_rate as u64))
        };
        
        output.push_str(&format!("{}: {}\n", "Taxa Atual".bold(), current_rate_formatted));
        output.push_str(&format!("{}: {}\n", "Taxa Média".bold(), avg_rate_formatted));
        
        // Status do Cache
        output.push_str(&format!("\n{}\n", "■ CACHE STATUS".bold().cyan()));
        output.push_str(&format!("{}: {:.1}% ({} hits, {} misses)\n", 
            "Hit Rate".bold(), 
            snapshot.cache_hit_rate * 100.0,
            format_large_number(snapshot.cache_hits),
            format_large_number(snapshot.cache_misses)));
        
        // Informações do Range
        output.push_str(&format!("\n{}\n", "■ RANGE INFORMATION".bold().yellow()));
        output.push_str(&format!("{}: 0x{}\n", "Chave Atual".bold(), format_hex(snapshot.current_key, 8)));
        output.push_str(&format!("{}: 0x{}\n", "Início do Range".bold(), format_hex(snapshot.range_start, 8)));
        output.push_str(&format!("{}: 0x{}\n", "Fim do Range".bold(), format_hex(snapshot.range_end, 8)));
        output.push_str(&format!("{}: {} ({:.2}%)\n", 
            "Progresso".bold(), 
            format_large_number(snapshot.processed_keys),
            snapshot.progress_percent));
        
        // Computação para processamento mais avançado
        if snapshot.hashes_computed > 0 {
            output.push_str(&format!("\n{}\n", "■ ADVANCED STATS".bold().magenta()));
            let hash_per_key = if snapshot.processed_keys > 0 {
                snapshot.hashes_computed as f64 / snapshot.processed_keys as f64
            } else {
                0.0
            };
            output.push_str(&format!("{}: {:.2} hash/key\n", "Eficiência de Hash".bold(), hash_per_key));
            output.push_str(&format!("{}: {} ({:.2} milhões)\n", 
                "Hashes Computados".bold(), 
                format_large_number(snapshot.hashes_computed),
                snapshot.hashes_computed as f64 / 1_000_000.0));
        }
        
        // Rodapé
        output.push_str(&format!("\n{}\n", "─".repeat(80)));
        output.push_str(&format!("{} {}\n", 
            "INFO:".bold().bright_blue(), 
            "Pressione Ctrl+C para interromper a busca. O progresso será salvo automaticamente."));
        
        output
    }
}

impl fmt::Display for Dashboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
} 