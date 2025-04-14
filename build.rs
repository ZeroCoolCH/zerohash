extern crate cc;
use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("--- Executando build.rs ---");
    let project_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let cpp_file_path = format!("{}/src/hasher.cpp", project_dir);
    println!("Tentando compilar: {}", cpp_file_path);

    // Verificar se o OpenSSL está disponível
    let openssl_available = check_openssl_available();
    if !openssl_available {
        println!("cargo:warning=OpenSSL não encontrado. Verifique se o OpenSSL está instalado corretamente.");
        println!("cargo:warning=Em sistemas Debian/Ubuntu: sudo apt-get install libssl-dev");
        println!("cargo:warning=Em sistemas RedHat/Fedora: sudo dnf install openssl-devel");
        println!("cargo:warning=Em sistemas macOS: brew install openssl");
        println!("cargo:warning=Em sistemas Windows: Instale através de https://slproweb.com/products/Win32OpenSSL.html");
        panic!("OpenSSL não encontrado. Consulte as mensagens acima para instruções de instalação.");
    }

    let mut builder = cc::Build::new();
    
    // Otimizações básicas
    builder
        .cpp(true)                // Compilar como C++
        .opt_level(3)             // Nível de otimização máximo
        .file(&cpp_file_path)     // Arquivo fonte em C++
        .flag("-O3")              // Otimização agressiva
        .flag("-ffast-math")      // Otimizações de ponto flutuante
        .flag("-funroll-loops");  // Desenrolar loops para mais desempenho
    
    // Detecção automática de arquitetura x86_64
    #[cfg(target_arch = "x86_64")]
    {
        // Detectar suporte a AVX, AVX2, AVX512
        let cpu_features = detect_cpu_features();
        println!("CPU features detectadas: {}", cpu_features);
        
        // Arquitetura base
        builder.flag("-march=native").flag("-mtune=native");
        
        // AVX/AVX2/AVX512
        if cpu_features.contains("avx512") {
            println!("cargo:warning=Habilitando otimizações AVX512");
            builder.flag("-mavx512f").flag("-mavx512vl").flag("-mavx512bw").flag("-mavx512dq");
        } else if cpu_features.contains("avx2") {
            println!("cargo:warning=Habilitando otimizações AVX2");
            builder.flag("-mavx2").flag("-mfma");
        } else if cpu_features.contains("avx") {
            println!("cargo:warning=Habilitando otimizações AVX");
            builder.flag("-mavx");
        } else {
            println!("cargo:warning=Utilizando SSE4.2 como fallback");
            builder.flag("-msse4.2");
        }
    }
    
    // Otimizações específicas para ARM
    #[cfg(target_arch = "aarch64")]
    {
        println!("cargo:warning=Compilando para ARM64 com otimizações NEON");
        builder.flag("-march=native");
        
        // Habilitar instruções NEON/SIMD específicas para ARM
        #[cfg(target_os = "macos")]
        {
            builder.flag("-mcpu=apple-a14"); // Bom para Apple Silicon
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            builder.flag("-mcpu=native");
        }
    }
    
    // Verificar e configurar OpenSSL
    configure_openssl(&mut builder);
    
    // Compilar a biblioteca
    builder.compile("hasher");
    
    // Configuração para vinculação da biblioteca
    link_openssl_libraries();
    
    // Recompilar se os arquivos forem modificados
    println!("cargo:rerun-if-changed=src/hasher.cpp");
    println!("cargo:rerun-if-changed=build.rs");
    println!("--- Fim build.rs ---");
}

// Verificar se o OpenSSL está disponível no sistema
fn check_openssl_available() -> bool {
    // Verificar variável de ambiente OPENSSL_DIR
    if env::var("OPENSSL_DIR").is_ok() {
        return true;
    }
    
    // Verificar se pkg-config consegue encontrar o OpenSSL
    if let Ok(output) = Command::new("pkg-config").args(["--modversion", "openssl"]).output() {
        if output.status.success() {
            return true;
        }
    }
    
    // Verificar caminhos comuns
    let common_paths = if cfg!(target_os = "windows") {
        vec!["C:/OpenSSL-Win64", "C:/OpenSSL-Win32"]
    } else if cfg!(target_os = "macos") {
        vec!["/usr/local/opt/openssl", "/opt/homebrew/opt/openssl"]
    } else {
        vec!["/usr/include/openssl", "/usr/local/include/openssl"]
    };
    
    for path in common_paths {
        if Path::new(path).exists() {
            return true;
        }
    }
    
    false
}

// Detectar recursos de CPU disponíveis
fn detect_cpu_features() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        if let Ok(output) = Command::new("cat").arg("/proc/cpuinfo").output() {
            if output.status.success() {
                let cpuinfo = String::from_utf8_lossy(&output.stdout);
                let mut features = Vec::new();
                
                if cpuinfo.contains("avx512") {
                    features.push("avx512");
                }
                if cpuinfo.contains(" avx2 ") {
                    features.push("avx2");
                }
                if cpuinfo.contains(" avx ") {
                    features.push("avx");
                }
                if cpuinfo.contains(" sse4_2 ") {
                    features.push("sse4.2");
                }
                
                return features.join(",");
            }
        }
        
        // Fallback para Linux/macOS usando lscpu
        if let Ok(output) = Command::new("lscpu").output() {
            if output.status.success() {
                let lscpu_output = String::from_utf8_lossy(&output.stdout);
                let mut features = Vec::new();
                
                if lscpu_output.contains("avx512") {
                    features.push("avx512");
                }
                if lscpu_output.contains(" avx2 ") {
                    features.push("avx2");
                }
                if lscpu_output.contains(" avx ") {
                    features.push("avx");
                }
                if lscpu_output.contains(" sse4_2 ") {
                    features.push("sse4.2");
                }
                
                return features.join(",");
            }
        }
    }
    
    // Se não conseguir detectar, assumir recursos básicos
    "sse4.2".to_string()
}

// Configurar OpenSSL para o builder
fn configure_openssl(builder: &mut cc::Build) {
    // Verificar se o sistema tem OpenSSL instalado
    if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
        let include_dir = Path::new(&openssl_dir).join("include");
        builder.include(include_dir);
        println!("cargo:warning=Usando OpenSSL de OPENSSL_DIR: {}", openssl_dir);
        return;
    }
    
    // Tentar usar pkg-config para encontrar o OpenSSL
    if let Ok(output) = Command::new("pkg-config").args(["--cflags", "openssl"]).output() {
        if output.status.success() {
            let flags = String::from_utf8_lossy(&output.stdout);
            for flag in flags.split_whitespace() {
                if flag.starts_with("-I") {
                    let path = &flag[2..]; // Remover o -I
                    builder.include(path);
                    println!("cargo:warning=Encontrado OpenSSL via pkg-config: {}", path);
                    return;
                }
            }
        }
    }
    
    // Adicionar diretórios de inclusão para OpenSSL em caminhos comuns
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
}

// Configurar vinculação das bibliotecas OpenSSL
fn link_openssl_libraries() {
    // Adicionar diretórios para vinculação com OpenSSL
    if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
        let lib_dir = Path::new(&openssl_dir).join("lib");
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    } else if let Ok(output) = Command::new("pkg-config").args(["--libs", "openssl"]).output() {
        if output.status.success() {
            let flags = String::from_utf8_lossy(&output.stdout);
            for flag in flags.split_whitespace() {
                if flag.starts_with("-L") {
                    let path = &flag[2..]; // Remover o -L
                    println!("cargo:rustc-link-search=native={}", path);
                }
            }
        } else {
            // Caminhos específicos do sistema operacional
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
        }
    }
    
    // Vincular à biblioteca OpenSSL
    println!("cargo:rustc-link-lib=dylib=ssl");
    println!("cargo:rustc-link-lib=dylib=crypto");
} 