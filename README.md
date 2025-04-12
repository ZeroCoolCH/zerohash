# ZeroHash Finder

Um buscador de chaves privadas Bitcoin de alta performance escrito em Rust, focado em velocidade e otimização.

[![Build Status](https://github.com/ZeroCoolCH/zerohash/actions/workflows/rust.yml/badge.svg)](https://github.com/ZeroCoolCH/zerohash/actions/workflows/rust.yml)

## Descrição

O ZeroHash Finder é uma ferramenta projetada para procurar chaves privadas Bitcoin dentro de ranges específicos ou de forma aleatória em um range. Ele utiliza processamento paralelo massivo (Rayon), interface C++ otimizada (FFI) para hashing, e técnicas avançadas de cache para maximizar a taxa de verificação de chaves por segundo.

## Recursos

- **Busca Sequencial:** Verifica todas as chaves privadas dentro de um range hexadecimal especificado (`--range-start` a `--range-end`).
- **Busca Aleatória:** Verifica chaves privadas selecionadas aleatoriamente *dentro* do range especificado (`--range-start` a `--range-end`) usando a flag `--random`. Ideal para explorar grandes ranges probabilisticamente.
- **Multi-threading:** Utiliza a crate Rayon para escalar o processamento em todos os núcleos de CPU disponíveis ou em um número específico de threads (`--threads`).
- **Hashing Otimizado:**
    - Implementa a geração de chaves públicas e o cálculo HASH160 (SHA256 + RIPEMD160) em lotes.
    - **Cache Contextual Dinâmico:** Acelera o cálculo de HASH160 reutilizando estados intermediários de SHA256 para prefixos de chaves públicas comuns ou frequentemente encontrados, adaptando-se aos padrões de dados (mais eficaz no modo sequencial).
    - **Interface C++ (FFI):** Delega partes críticas do cálculo de hash (manipulação de estado SHA256, RIPEMD160) para código C++ potencialmente otimizado (`src/hasher.cpp`), linkado estaticamente.
- **Retomada de Progresso:** No modo sequencial, salva a última chave processada em `zerohash_progress.txt` e retoma automaticamente a partir desse ponto se a busca for interrompida e reiniciada com o mesmo range. (Não aplicável ao modo aleatório).
- **Saída Detalhada:** Exibe o endereço P2PKH, P2WPKH, P2SH-P2WPKH, a chave privada em WIF e hexadecimal, e o hash160 quando uma correspondência é encontrada. Os resultados também são salvos em `results.txt`.
- **Parada Elegante:** Responde ao sinal Ctrl+C para interromper a busca de forma limpa.

## Estrutura do Código

O projeto é organizado nos seguintes módulos principais em `src/`:

- `main.rs`: Ponto de entrada, parseamento de argumentos CLI, inicialização, orquestração da busca.
- `cli.rs`: Definição da interface de linha de comando usando `clap`.
- `app_state.rs`: Definição da struct `AppState` que mantém o estado global compartilhado entre as threads (configurações, flags atômicas, mutexes).
- `turbo_search.rs`: Contém a lógica principal da busca, gerenciamento de threads (usando `crossbeam` para escopo e `rayon` para paralelismo), e a implementação dos modos sequencial e aleatório.
- `batch_pubkey.rs`: Geração otimizada de chaves públicas Bitcoin em lote a partir de chaves privadas (`u128`).
- `batch_hash.rs`: Implementação do hashing HASH160 em lote, incluindo a lógica do Cache Contextual Dinâmico e a interface (FFI) para as funções C++.
- `hasher.cpp`: Código C++ que implementa as funções de hashing de baixo nível (SHA256, RIPEMD160, manipulação de estado) chamadas via FFI.

## Instalação

### Requisitos

- **Rust:** Toolchain estável ou nightly (ver `rust-toolchain.toml` se presente). Instalável via [rustup](https://rustup.rs/).
- **Compilador C++:** Necessário para compilar `hasher.cpp` (ex: `gcc`, `clang`, MSVC Build Tools).
- **OpenSSL:** Biblioteca de desenvolvimento (ex: `libssl-dev` no Debian/Ubuntu, `openssl-devel` no Fedora).
- **Git:** Para clonar o repositório.
- **pkg-config:** Ferramenta para auxiliar na localização de bibliotecas.

### Passos (Exemplo Linux)

1.  **Instalar Dependências (Exemplo Debian/Ubuntu):**
    ```bash
    sudo apt update
    sudo apt install build-essential libssl-dev pkg-config git curl
    ```
    *(Adapte para sua distribuição: ex. `dnf install gcc gcc-c++ openssl-devel pkgconfig git curl` no Fedora)*

2.  **Instalar Rust:**
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source "$HOME/.cargo/env"
    ```

3.  **Clonar Repositório:**
    ```bash
    git clone https://github.com/ZeroCoolCH/zerohash.git
    cd zerohash
    ```

4.  **Compilar (Modo Release Otimizado):**
    *É altamente recomendável compilar com `target-cpu=native` para obter o máximo desempenho no seu hardware específico.*
    ```bash
    RUSTFLAGS="-C target-cpu=native" cargo build --release
    ```
    *(No Windows, use `set RUSTFLAGS=-C target-cpu=native` antes do comando `cargo build`).*

5.  **Executável:** O binário estará em `./target/release/zerohash_finder`.

## Uso

**Sintaxe:**

```bash
./target/release/zerohash_finder --address <ENDEREÇO_ALVO> --range-start <HEX_INICIO> --range-end <HEX_FIM> [OPÇÕES]
```

**Argumentos Obrigatórios:**

- `--address <ENDEREÇO_ALVO>`: O endereço Bitcoin P2PKH (começando com '1') que você está procurando.
- `--range-start <HEX_INICIO>`: O início do range de chaves privadas (em hexadecimal, sem `0x`) a ser pesquisado.
- `--range-end <HEX_FIM>`: O fim do range de chaves privadas (em hexadecimal, sem `0x`) a ser pesquisado.

**Opções:**

- `--random`: Ativa o modo de busca aleatória dentro do range especificado. Sem esta flag, a busca é sequencial.
- `--threads <NUMERO>`: Define o número de threads a serem usadas. Se omitido ou 0, usa todos os núcleos lógicos disponíveis.

**Exemplos:**

```bash
# Busca sequencial em um range pequeno com 8 threads
./target/release/zerohash_finder --address 1BitcoinEaterAddressDontSendf59kuE \
                               --range-start 10000000 \
                               --range-end   1000FFFF \
                               --threads 8

# Busca aleatória em um range muito grande usando todos os núcleos
./target/release/zerohash_finder --address 1CQFwcjw1dwhtNPVaQwxe6f9NnqfA1hGMN \
                               --range-start 20000000000000000 \
                               --range-end   3ffffffffffffffff \
                               --random
```

**Saída:**

- O programa exibirá o progresso (taxa de chaves por segundo e/ou percentual concluído).
- Se uma chave for encontrada, os detalhes completos (Hex, WIF, Endereços, Hash) serão impressos no console e salvos em `results.txt`.
- Ao final, exibirá um resumo com o total de chaves processadas, tempo total e taxa média.
- Pressione `Ctrl+C` a qualquer momento para parar a busca.

## Performance

- A performance depende muito do hardware (CPU, cache, velocidade da memória) e do modo de busca.
- O **modo sequencial** tende a ser mais rápido (potencialmente dezenas de Mkeys/s) devido à alta eficiência do Cache Contextual Dinâmico.
- O **modo aleatório** geralmente terá uma taxa menor (na casa de 0.1 a alguns Mkeys/s) pois a geração aleatória e a menor eficiência do cache introduzem overhead.
- Compilar com `RUSTFLAGS="-C target-cpu=native"` é crucial para atingir o pico de performance.

## Aviso Legal

Esta ferramenta é fornecida **estritamente** para fins educacionais e de pesquisa sobre criptografia, performance de computação e programação em Rust/C++.

**NÃO USE ESTA FERRAMENTA PARA TENTAR ACESSAR CARTEIRAS ALHEIAS.**

- O espaço de chaves privadas do Bitcoin é astronomicamente grande (2^256).
- Encontrar uma chave privada específica em uso por força bruta ou busca aleatória é **computacionalmente inviável** com a tecnologia atual ou futura previsível.
- Qualquer chave encontrada por esta ferramenta em ranges pequenos será quase certamente uma chave que nunca foi usada e não possui fundos.

O autor não se responsabiliza por qualquer uso indevido desta ferramenta. Use por sua conta e risco e com responsabilidade.