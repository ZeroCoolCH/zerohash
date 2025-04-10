#!/bin/bash

echo "=== ZeroHash Finder - Verificação de Ambiente ==="
echo "Este script verifica seu ambiente para problemas comuns de compilação."
echo ""

# Verificar se há Cargo.toml conflitante
echo "=== Verificando Cargo.toml conflitante ==="
HOME_CARGO_TOML="$HOME/Cargo.toml"
if [ -f "$HOME_CARGO_TOML" ]; then
    echo "PROBLEMA DETECTADO: Existe um Cargo.toml no diretório principal do usuário:"
    echo "$HOME_CARGO_TOML"
    echo ""
    echo "Este arquivo pode interferir na compilação. Conteúdo do arquivo:"
    cat "$HOME_CARGO_TOML"
    echo ""
    
    read -p "Deseja renomear este arquivo para $HOME_CARGO_TOML.bak? (s/n): " resp
    if [ "$resp" = "s" ]; then
        mv "$HOME_CARGO_TOML" "$HOME_CARGO_TOML.bak"
        echo "Arquivo renomeado para $HOME_CARGO_TOML.bak"
    else
        echo "Arquivo não modificado. A compilação pode falhar."
    fi
else
    echo "OK: Nenhum arquivo Cargo.toml conflitante encontrado."
fi
echo ""

# Verificar dependências
echo "=== Verificando dependências necessárias ==="
DEPS_OK=true

# Verificar Rust
if command -v rustc >/dev/null 2>&1; then
    RUST_VERSION=$(rustc --version | cut -d' ' -f2)
    echo "OK: Rust encontrado (versão $RUST_VERSION)"
else
    echo "PROBLEMA: Rust não encontrado. Por favor, instale o Rust."
    DEPS_OK=false
fi

# Verificar Cargo
if command -v cargo >/dev/null 2>&1; then
    CARGO_VERSION=$(cargo --version | cut -d' ' -f2)
    echo "OK: Cargo encontrado (versão $CARGO_VERSION)"
else
    echo "PROBLEMA: Cargo não encontrado. Por favor, instale o Cargo."
    DEPS_OK=false
fi

# Verificar OpenSSL
if pkg-config --exists openssl 2>/dev/null; then
    OPENSSL_VERSION=$(pkg-config --modversion openssl)
    echo "OK: OpenSSL encontrado (versão $OPENSSL_VERSION)"
else
    echo "AVISO: Não foi possível verificar a versão do OpenSSL com pkg-config."
    echo "Verifique se o OpenSSL e seu pacote de desenvolvimento estão instalados."
fi

# Verificar compilador C/C++
if command -v g++ >/dev/null 2>&1; then
    GCC_VERSION=$(g++ --version | head -n1 | cut -d' ' -f3)
    echo "OK: Compilador C++ (g++) encontrado (versão $GCC_VERSION)"
else
    echo "PROBLEMA: Compilador C++ (g++) não encontrado. Por favor, instale o GCC."
    DEPS_OK=false
fi

echo ""
if [ "$DEPS_OK" = true ]; then
    echo "=== Todas as dependências principais estão disponíveis ==="
    echo "Você pode compilar o ZeroHash Finder usando:"
    echo "cargo build --release"
else
    echo "=== Algumas dependências estão faltando ==="
    echo "Por favor, instale as dependências mencionadas acima antes de compilar."
fi 