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
    - **Interface C++ (FFI):** Delega partes críticas do cálculo de hash (manipulação de estado SHA256, RIPEMD160) para código C++ otimizado (`src/hasher.cpp`), linkado estaticamente com suporte automático a instruções AVX/AVX2/AVX512.
- **Balanceamento de Carga Dinâmico:** Implementa um sistema de divisão dinâmica de trabalho entre threads, permitindo que workers mais rápidos ajudem os mais lentos, melhorando significativamente a utilização de CPU.
- **Detecção Automática de Arquitetura:** Identifica automaticamente as instruções suportadas pela CPU e habilita otimizações específicas em tempo de compilação.
- **Retomada de Progresso:** No modo sequencial, salva a última chave processada a cada 5 segundos em `zerohash_progress.txt` e retoma automaticamente a partir desse ponto seguinte se a busca for interrompida e reiniciada com o mesmo range. O sistema verifica automaticamente se o arquivo existe e usa seu conteúdo para recomeçar do ponto onde parou. (Não aplicável ao modo aleatório, que inicia sempre do começo).
  - **Sistema de Progresso JSON:** Um sistema avançado foi implementado para salvar o progresso em formato JSON (`zerohash_progress.json`), permitindo manter múltiplos estados de progresso para diferentes combinações de endereços e ranges. Isso significa que você pode:
    - Testar múltiplos ranges para o mesmo endereço e retomar cada um de onde parou
    - Alternar entre diferentes endereços sem perder o progresso de nenhum
    - Manter um histórico completo de todas as buscas com timestamps da última execução
  - O sistema de progresso JSON é robusto e mantém compatibilidade com o formato antigo para garantir que buscas anteriores possam ser retomadas.
- **Saída Detalhada:** Exibe o endereço P2PKH, P2WPKH, P2SH-P2WPKH, a chave privada em WIF e hexadecimal, e o hash160 quando uma correspondência é encontrada. Os resultados também são salvos em `found_keys.txt`.
- **Suporte a Tipos Modernos de Endereços:** Total compatibilidade com P2WPKH (endereços bech32) e P2SH-P2WPKH, além dos tradicionais P2PKH.
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
- `build.rs`: Script de build que configura a compilação do código C++ e detecta recursos da CPU.

## Instalação

### Requisitos

- **Rust:** Toolchain estável (1.70+). Instalável via [rustup](https://rustup.rs/).
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
    ```bash
    cargo build --release
    ```
    *O script build.rs detectará automaticamente as instruções suportadas pela sua CPU e habilitará otimizações adequadas.*

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
  - No modo aleatório, o arquivo de progresso é desativado, e cada execução começa do zero.
  - Modo ideal para explorar ranges grandes de forma probabilística.
- `--threads <NUMERO>`: Define o número de threads a serem usadas. Se omitido ou 0, usa todos os núcleos lógicos disponíveis.

**Modos de Execução:**

- **Modo Sequencial (padrão)**: 
  - Examina cada chave do range de forma ordenada e completa
  - Salva o progresso periodicamente em `zerohash_progress.txt`
  - Retoma automaticamente do último ponto salvo se reiniciado
  - Ideal para ranges pequenos ou médios que precisam ser verificados completamente
  
- **Modo Aleatório** (com flag `--random`):
  - Seleciona chaves aleatoriamente dentro do range especificado
  - Não salva progresso (cada execução é independente)
  - Ideal para explorar grandes espaços de busca onde verificação completa seria inviável
  - Útil para demonstrações ou para testar a sorte

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
                               
# Busca sequencial em range específico (exemplo de teste)
./target/release/zerohash_finder --address 1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm \
                               --range-start 10000 \
                               --range-end   20000
```

**Saída:**

- O programa exibirá o progresso com taxa de processamento, percentual concluído, número de workers ativos e chunks restantes.
- Se uma chave for encontrada, os detalhes completos (Hex, WIF, Endereços, Hash) serão impressos no console e salvos em `found_keys.txt`.
- Ao final, exibirá um resumo com o total de chaves processadas, tempo total e taxa média.
- Pressione `Ctrl+C` a qualquer momento para parar a busca.

## Dicas e Solução de Problemas

### Sistema de Progresso

- **Arquivo de Progresso**: O programa salva o progresso a cada 5 segundos no arquivo `zerohash_progress.txt` no diretório de execução.
- **Formato**: O arquivo contém um único valor hexadecimal sem prefixo, representando a última chave processada.
- **Reinício**: Quando você reinicia o programa com o mesmo intervalo, ele verifica automaticamente o arquivo de progresso e continua de onde parou.
- **Tempo Mínimo de Execução**: O programa precisa executar por pelo menos 5-10 segundos para que o progresso seja salvo.
- **Verificação do Progresso**: Você pode verificar o progresso atual usando: `cat zerohash_progress.txt`
- **Modo Aleatório**: No modo aleatório (`--random`), o sistema de progresso é desativado intencionalmente.

### Outras Dicas

- **Performance Ótima**:
  - Use o modo Release: `cargo run --release -- [ARGUMENTOS]` ou o binário compilado em release
  - Em CPUs modernas, um valor adequado para `--threads` é geralmente o número de núcleos físicos + 1
  
- **Testes**:
  - Para testar se o sistema está funcionando corretamente, use um range pequeno com um endereço de teste conhecido como:
    ```
    --address 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ --range-start bebb3940cd0fc1000 --range-end bebb3940cd0fc5000
    ```

- **Problemas Comuns**:
  - **Arquivo de progresso não é criado**: Certifique-se de que o programa executa por pelo menos 5-10 segundos
  - **Performance baixa**: Verifique se está executando a build de release e não a de debug
  - **Erros de permissão**: Certifique-se de que você tem permissões de escrita no diretório atual

## Performance

- A performance do programa foi otimizada com diversas técnicas:
  - **Balanceamento de Carga Dinâmico:** Distribui automaticamente o trabalho entre as threads, evitando que algumas fiquem ociosas enquanto outras estão sobrecarregadas.
  - **Cache Contextual Dinâmico:** Melhora significativamente a performance reutilizando estados intermediários de hashing.
  - **Otimizações por Arquitetura:** Suporte automaticamente detectado para AVX/AVX2/AVX512.
  - **Interface C++:** Operações críticas de hash delegadas para código C++ otimizado.
  
- Em hardware moderno (CPU recente com múltiplos núcleos):
  - **Modo sequencial**: Pode atingir de 100 mil a vários milhões de chaves por segundo, dependendo do hardware.
  - **Modo aleatório**: Geralmente alcança taxa menor devido à geração aleatória e menor eficiência do cache.

## Exemplos de Resultados

O ZeroHash Finder já foi capaz de encontrar as seguintes chaves de teste:

- **Endereço:** 1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm
  - **Chave Privada (Hex):** 000000000000000000000000000000000000000000000000000000000001764f
  - **WIF:** KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFiHkRsp99uC

- **Endereço:** 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ
  - **Chave Privada (Hex):** 0000000000000000000000000000000000000000000000bebb3940cd0fc1491
  - **WIF:** KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qd7sDG4F2sdMtzNe8y2U

## Aviso Legal

Esta ferramenta é fornecida **estritamente** para fins educacionais e de pesquisa sobre criptografia, performance de computação e programação em Rust/C++.

**NÃO USE ESTA FERRAMENTA PARA TENTAR ACESSAR CARTEIRAS ALHEIAS.**

- O espaço de chaves privadas do Bitcoin é astronomicamente grande (2^256).
- Encontrar uma chave privada específica em uso por força bruta ou busca aleatória é **computacionalmente inviável** com a tecnologia atual ou futura previsível.
- Qualquer chave encontrada por esta ferramenta em ranges pequenos será quase certamente uma chave que nunca foi usada e não possui fundos.

O autor não se responsabiliza por qualquer uso indevido desta ferramenta. Use por sua conta e risco e com responsabilidade.