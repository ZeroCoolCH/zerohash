# ZeroHash Finder

Um buscador de chaves privadas Bitcoin de alta performance escrito em Rust.

## Descrição

O ZeroHash Finder é uma ferramenta otimizada para procurar chaves privadas Bitcoin dentro de ranges específicos. Ele utiliza processamento paralelo e otimizações de baixo nível para atingir velocidades de verificação de milhões de chaves por segundo.

## Recursos

- Busca sequencial completa em ranges de chaves especificados
- Modo aleatório para buscas probabilísticas
- Suporte a multi-threading para aproveitar todos os núcleos do CPU
- Geração eficiente de chaves públicas e hashes Bitcoin
- Salvamento de progresso para retomar buscas interrompidas
- Saída de resultados detalhada quando uma chave é encontrada

## Instalação

### Requisitos de Sistema

- [Rust](https://www.rust-lang.org/) (versão 1.56.0 ou superior)
- [OpenSSL](https://www.openssl.org/) (versão 1.1.0 ou superior)
- [Git](https://git-scm.com/) (opcional, para clonar o repositório)
- Compilador C/C++ (para compilar dependências nativas)

### Instalação no Linux

1. Instale as dependências necessárias:

   **Ubuntu/Debian:**
   ```bash
   sudo apt update
   sudo apt install build-essential pkg-config libssl-dev curl
   ```

   **Fedora:**
   ```bash
   sudo dnf install gcc gcc-c++ openssl-devel pkgconfig curl
   ```

   **Arch Linux:**
   ```bash
   sudo pacman -S base-devel openssl pkgconf curl
   ```

2. Instale o Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

3. Clone o repositório:
   ```bash
   git clone https://github.com/ZeroCoolCH/zerohash.git
   cd zerohash
   ```

4. Compile o projeto:
   ```bash
   cargo build --release
   ```

5. O executável estará disponível em `./target/release/zerohash_finder`

### Instalação no Windows

1. Instale o [Rust](https://www.rust-lang.org/tools/install) usando o instalador oficial

2. Instale o [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) com o componente "Ferramentas de Compilação C++"

3. Instale o [OpenSSL para Windows](https://slproweb.com/products/Win32OpenSSL.html) (versão completa, não a "Light")

4. Configure as variáveis de ambiente:
   ```
   SET OPENSSL_DIR=C:\Program Files\OpenSSL-Win64
   ```

5. Clone o repositório:
   ```
   git clone https://github.com/ZeroCoolCH/zerohash.git
   cd zerohash
   ```

6. Compile o projeto:
   ```
   cargo build --release
   ```

7. O executável estará disponível em `.\target\release\zerohash_finder.exe`

### Instalação no macOS

1. Instale o [Homebrew](https://brew.sh/):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. Instale as dependências:
   ```bash
   brew install openssl pkg-config
   ```

3. Instale o Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

4. Configure as variáveis de ambiente para OpenSSL:
   ```bash
   export OPENSSL_DIR=$(brew --prefix openssl)
   ```

5. Clone o repositório:
   ```bash
   git clone https://github.com/ZeroCoolCH/zerohash.git
   cd zerohash
   ```

6. Compile o projeto:
   ```bash
   cargo build --release
   ```

7. O executável estará disponível em `./target/release/zerohash_finder`

### Compilação Otimizada

Para melhor desempenho, use a seguinte opção de compilação:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

No Windows:
```
set RUSTFLAGS=-C target-cpu=native
cargo build --release
```

### Solução de Problemas

#### Erro de Linker no OpenSSL
Se você encontrar erros relacionados ao OpenSSL durante a compilação, certifique-se de que:

1. O OpenSSL está corretamente instalado
2. As variáveis de ambiente estão configuradas corretamente:
   ```bash
   export OPENSSL_DIR=/caminho/para/openssl
   export OPENSSL_INCLUDE_DIR=/caminho/para/openssl/include
   export OPENSSL_LIB_DIR=/caminho/para/openssl/lib
   ```

#### Erro de "crate not found"
Se o cargo não conseguir encontrar determinadas crates, tente atualizar o registro:
```bash
cargo update
```

## Uso

```
./zerohash_finder --address <ENDEREÇO_BITCOIN> --range-start <HEX_INICIO> --range-end <HEX_FIM> [--random]
```

Exemplos:

```
# Busca sequencial em um range específico
./zerohash_finder --address 1Pie8JkxBT6MGPz9Nvi3fsPkr2D8q3GBc1 --range-start 1000 --range-end 1fff

# Busca aleatória em um range amplo
./zerohash_finder --address 19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG --range-start 1000000000 --range-end 1fffffffff --random
```

## Performance

Em hardware moderno, o ZeroHash Finder pode atingir velocidades de verificação de 10-20 milhões de chaves por segundo.

## Aviso Legal

Esta ferramenta é fornecida apenas para fins educacionais e de pesquisa. As chances de encontrar uma chave privada em uso são praticamente nulas devido ao tamanho do espaço de chaves Bitcoin.