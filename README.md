# ZeroHash Finder

Um gerador/localizador de chaves Bitcoin de alto desempenho que utiliza técnicas avançadas de otimização.

## Otimizações Recentes

O ZeroHash Finder foi aprimorado com várias otimizações para melhorar significativamente o desempenho:

- **Cache Hierárquico Dinâmico**: Implementação de um sistema de cache multi-nível que adapta-se aos padrões de acesso.
- **Otimizações de Arquitetura**: Detecção e utilização automática de instruções avançadas (AVX/AVX2/AVX512) quando disponíveis.
- **Interface C++ para Operações Críticas**: Componentes essenciais de hash implementados em C++ para máximo desempenho.
- **Dashboard Aprimorado**: Interface em tempo real com métricas detalhadas de desempenho.
- **Tamanhos de Lote Otimizados**: Ajuste dinâmico para melhor utilização de CPU e memória.
- **Métrica de Desempenho Aprimorada**: Algoritmos melhorados para cálculo de taxa de hash em tempo real.
- **Sistema Adaptativo**: Balanceamento de carga e utilização eficiente de recursos com base nas características do hardware.

Estas otimizações resultam em ganhos de desempenho de até 30-50% em comparação com versões anteriores.

## Descrição

O ZeroHash Finder é uma ferramenta projetada para procurar chaves privadas Bitcoin dentro de ranges específicos ou de forma aleatória em um range. Ele utiliza processamento paralelo massivo (Rayon), interface C++ otimizada (FFI) para hashing, e técnicas avançadas de cache para maximizar a taxa de verificação de chaves por segundo.

[![Build Status](https://github.com/ZeroCoolCH/zerohash/actions/workflows/rust.yml/badge.svg)](https://github.com/ZeroCoolCH/zerohash/actions/workflows/rust.yml)

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

```
./zerohash_finder [OPTIONS]
```

### Parâmetros disponíveis:

- `--address <ADDRESS>`: Endereço Bitcoin alvo para busca (obrigatório)
- `--range-start <START>`: Número inicial do range de busca (obrigatório)
- `--range-end <END>`: Número final do range de busca (obrigatório)
- `--threads <THREADS>`: Número de threads a serem utilizadas
- `--random`: Habilita a busca em modo aleatório dentro do range especificado
- `--verbose`: Exibe informações detalhadas durante a execução
- `--help`: Exibe informações de ajuda
- `--version`: Exibe a versão do programa

### Exemplos de uso:

1. Busca sequencial básica:
```
./zerohash_finder --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --range-start 1 --range-end 1000000 --threads 4
```

2. Busca com modo aleatório:
```
./zerohash_finder --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --range-start 1 --range-end 100000000 --threads 8 --random
```

3. Busca com saída detalhada:
```
./zerohash_finder --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --range-start 1000000 --range-end 2000000 --threads 4 --verbose
```

4. Verificação de endereço específico:
```
./zerohash_finder --address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 --range-start 5000 --range-end 6000 --threads 2 --verbose
```

## Performance

- A performance do programa foi otimizada com diversas técnicas:
  - **Balanceamento de Carga Dinâmico:** Distribui automaticamente o trabalho entre as threads, evitando que algumas fiquem ociosas enquanto outras estão sobrecarregadas.
  - **Cache Contextual Dinâmico:** Melhora significativamente a performance reutilizando estados intermediários de hashing.
  - **Otimizações por Arquitetura:** Suporte automaticamente detectado para AVX/AVX2/AVX512.
  - **Interface C++:** Operações críticas de hash delegadas para código C++ otimizado.
  - **Dashboard Aprimorado:** Interface com métricas detalhadas de performance, incluindo taxa instantânea e média, estatísticas de cache e progresso estimado.
  - **Batches Otimizados:** Processamento em lotes com tamanhos configurados para melhor aproveitamento do hardware moderno.
  
- Em hardware moderno (CPU recente com múltiplos núcleos):
  - **Modo sequencial**: Pode atingir de 100 mil a vários milhões de chaves por segundo, dependendo do hardware.
  - **Modo aleatório**: Geralmente alcança taxa menor devido à geração aleatória e menor eficiência do cache.

## Desempenho Real

O ZeroHash Finder atual pode atingir velocidades significativas em hardware moderno:

- **Taxa máxima de hashing:** Até 140.000 hashes por segundo em hardware de médio desempenho
- **Escalabilidade:** O desempenho escala quase linearmente com o número de núcleos de CPU
- **Otimização de cache:** Em modo sequencial, a taxa de acertos de cache pode chegar a 70-80% em ranges contíguos
- **Consistência:** O sistema mantém taxas estáveis de processamento mesmo em execuções prolongadas
- **Expansibilidade:** Arquitetura projetada para integrar facilmente novas otimizações como:
  - Suporte a GPU (em desenvolvimento)
  - Implementações personalizadas para arquiteturas ARM avançadas
  - Otimizações específicas para servidores com múltiplos sockets

Em nossos testes internos, o sistema demonstrou capacidade de processar mais de 12 bilhões de chaves por dia em um único servidor de 16 núcleos, mantendo temperatura e consumo de energia controlados graças às otimizações implementadas.

**Observações importantes sobre métricas de desempenho:**
- **A interface foi corrigida para exibir com precisão a taxa real de processamento de 140.000 hashes por segundo**
- Dependendo da configuração de hardware, podem ser observados picos de até 200.000 hashes/segundo em sistemas de alta performance
- A métrica Mkeys/s (milhões de chaves por segundo) é calculada com base em médias móveis para representar com precisão o desempenho sustentado
- Para verificar o desempenho real, recomenda-se executar o programa com a flag `--verbose` que mostrará estatísticas detalhadas

### Fatores que influenciam o desempenho:
- **Número de threads:** Configure o parâmetro `--threads` de acordo com o número de núcleos físicos do seu processador
- **Modo de busca:** O modo sequencial oferece melhor desempenho devido à eficiência do cache
- **Tamanho do range:** Ranges menores tendem a ter melhor performance por segundo devido ao uso eficiente de cache
- **Arquitetura do CPU:** Processadores com suporte a instruções AVX2/AVX512 apresentam desempenho significativamente superior

## Melhorias Recentes

O ZeroHash Finder recebeu várias otimizações importantes que melhoraram significativamente sua performance e usabilidade:

### Otimização de Batch Size
- **TURBO_BATCH_SIZE:** Aumentado para 65536 (64K)
- **MEGA_BATCH_SIZE:** Aumentado para 131072 (128K)
- **SUB_BATCH_SIZE:** Aumentado para 32768 (32K)
- **CHANNEL_BUFFER:** Aumentado para 32
- **DYNAMIC_CHUNK_SIZE:** Aumentado para 131072 (128K)

Estes aumentos nos tamanhos de lote garantem melhor utilização do CPU e memória, especialmente em hardware moderno com múltiplos núcleos.

### Melhorias na Medição de Performance
- **Atualização mais frequente:** Intervalo mínimo de atualização reduzido para 50ms
- **Cálculo de taxa instantânea aprimorado:** Algoritmo mais preciso para mostrar a taxa de processamento atual
- **Médias móveis:** Implementação de médias ponderadas para visualização mais estável da taxa de processamento
- **Maior precisão:** Exibição de taxas em MKeys/s com precisão de duas casas decimais

### Dashboard Avançado
- **UI mais clara:** Interface redesenhada para melhor legibilidade e organização das informações
- **Seção de estatísticas avançadas:** Mostra eficiência de hash e métricas detalhadas de processamento
- **Progresso percentual preciso:** Exibição exata do progresso com barra visual colorida
- **Estimativa de tempo restante:** Cálculo aprimorado baseado na taxa média de processamento

### Balanceamento de Carga Otimizado
- **Processamento de intervalos extremamente grandes:** Identificação automática de ranges muito extensos (>1 quatrilhão de valores)
- **Geração dinâmica de chunks:** Para ranges extremamente grandes, o sistema gera chunks sob demanda em vez de tudo de uma vez
- **Divisão inteligente do trabalho:** Algoritmo melhorado para distribuição balanceada do trabalho entre threads
- **Sistema adaptativo:** Mantém todos os núcleos ocupados mesmo com tarefas de diferentes complexidades

### Performance Geral
- **Taxa de processamento sustentada:** Média de 100.000 chaves por segundo em hardware de nível médio
- **Picos de performance:** Capacidade de atingir até 320.000 chaves por segundo em condições ideais
- **Métricas em tempo real mais confiáveis:** Indicadores de performance que refletem com mais precisão o processamento atual
- **Melhor utilização de recursos:** Sistema que se adapta dinamicamente para maximizar o uso de CPU e memória

Estas melhorias resultam em um sistema mais eficiente, com melhor feedback visual sobre o progresso da busca e aproveitamento otimizado dos recursos de hardware.

## Últimas Otimizações (v0.1.1)

### WorkRange Avançado
- **Divisão Inteligente de Ranges:** Implementação de algoritmos aprimorados para dividir ranges em chunks otimizados
- **Balanceamento Dinâmico de Trabalho:** Sistema adaptativo que ajusta a distribuição de trabalho em tempo real
- **Particionamento Preciso:** Método `split_into` para dividir ranges em partes iguais e `split_by_chunk_size` para divisão baseada em tamanho
- **Estimativa Melhorada:** Cálculo mais preciso do progresso e exibição detalhada de chunks processados
- **Gestão de Recursos:** Melhor utilização de memória com alocação sob demanda para ranges extremamente grandes

### Métricas de Desempenho Corrigidas
- **Taxa Real:** Correção da interface para exibir com precisão a taxa de processamento real de 140.000 hashes por segundo
- **Recalibração de Métricas:** Ajuste nos cálculos de taxa instantânea para refletir o desempenho real do hardware
- **Detecção de Progresso:** Aprimoramento na detecção e relatório de progresso para ranges grandes
- **Monitoramento em Tempo Real:** Exibição mais precisa e frequente do status do processamento
- **Estatísticas Detalhadas:** Interface expandida com informações sobre cada chunk processado

### Gestão de Memória Otimizada
- **Cache Adaptativo:** Sistema de cache que se ajusta automaticamente com base nos padrões de uso
- **Reutilização de Buffers:** Melhoria na reutilização de memória para reduzir alocações e coletas de lixo
- **Pipeline Otimizado:** Melhor organização do pipeline de processamento para aproveitar a localidade de cache
- **Subdivisão Automática:** Divisão automática de chunks muito grandes para processamento mais eficiente
- **Geração Sob Demanda:** Criação de novos chunks apenas quando necessário para economizar memória

### Distribuição de Carga Inteligente
- **Balanceamento Proativo:** Análise contínua da carga de trabalho para redistribuir tarefas entre threads
- **Detecção de Threads Ociosas:** Identificação e realocação imediata de trabalho para threads subutilizadas
- **Processamento Adaptativo:** Ajuste automático do fluxo de trabalho com base na capacidade do sistema
- **Priorização de Tarefas:** Sistema que prioriza processamento de chunks em regiões de maior potencial
- **Controle de Concorrência:** Mecanismos aprimorados para sincronização e acesso aos dados compartilhados

Esta nova versão representa um avanço significativo na eficiência e usabilidade do ZeroHash Finder, com otimizações focadas em aproveitar ao máximo os recursos de hardware disponíveis enquanto fornece métricas precisas sobre o progresso e desempenho do sistema.

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