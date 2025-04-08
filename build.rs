extern crate cc;
use std::env;
use std::path::Path;

fn main() {
    println!("--- Executando build.rs ---");
    let project_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let cpp_file_path = format!("{}/src/hasher.cpp", project_dir);
    println!("Tentando compilar: {}", cpp_file_path);

    let mut builder = cc::Build::new();
    
    // Otimizações específicas para compilação
    builder
        .cpp(true)                // Compilar como C++
        .opt_level(3)             // Nível de otimização máximo
        .file(&cpp_file_path)     // Arquivo fonte em C++
        .flag("-march=native")    // Otimizar para CPU específica
        .flag("-mtune=native")    // Ajustar para CPU específica
        .flag("-O3")              // Otimização agressiva
        .flag("-ffast-math")      // Otimizações de ponto flutuante
        .flag("-funroll-loops");  // Desenrolar loops para mais desempenho
    
    // Adicionar suporte a AVX2 se disponível
    #[cfg(target_arch = "x86_64")]
    {
        builder.flag("-mavx2");
    }
    
    // Verificar se o sistema tem OpenSSL instalado
    if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
        let include_dir = Path::new(&openssl_dir).join("include");
        builder.include(include_dir);
    }
    
    // Adicionar diretórios de inclusão para OpenSSL
    // Se não estiver no caminho padrão, o usuário precisará definir OPENSSL_DIR
    #[cfg(target_os = "linux")]
    {
        builder.include("/usr/include");
        builder.include("/usr/local/include");
    }
    
    #[cfg(target_os = "macos")]
    {
        builder.include("/usr/local/opt/openssl/include");
        builder.include("/opt/homebrew/opt/openssl/include");
    }
    
    #[cfg(target_os = "windows")]
    {
        builder.include("C:/OpenSSL-Win64/include");
    }
    
    // Compilar a biblioteca
    builder.compile("hasher");
    
    // Adicionar diretórios para vinculação com OpenSSL
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }
    
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-search=native=/usr/local/opt/openssl/lib");
        println!("cargo:rustc-link-search=native=/opt/homebrew/opt/openssl/lib");
    }
    
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-search=native=C:/OpenSSL-Win64/lib");
    }
    
    // Vincular à biblioteca OpenSSL
    println!("cargo:rustc-link-lib=dylib=ssl");
    println!("cargo:rustc-link-lib=dylib=crypto");
    
    // Vincular estaticamente se disponível
    if cfg!(feature = "static-openssl") {
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
    }
    
    // Recompilar se os arquivos forem modificados
    println!("cargo:rerun-if-changed=src/hasher.cpp");
    println!("cargo:rerun-if-changed=build.rs");
    println!("--- Fim build.rs ---");
} 