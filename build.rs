extern crate cc;

fn main() {
    println!("--- Executando build.rs ---");
    let project_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let cpp_file_path = format!("{}/src/hasher.cpp", project_dir);
    println!("Tentando compilar: {}", cpp_file_path);

    let mut build = cc::Build::new();
    build.file(&cpp_file_path) // Usar referência ao path
        .cpp(true)
        .opt_level(3)
        // .flag("-march=native") 
        .warnings(true); // Habilitar warnings do compilador C++
    
    // Tentar compilar e verificar resultado
    let result = build.try_compile("hasher");

    match result {
        Ok(_) => println!("Compilação C++ (try_compile) OK."),
        Err(ref e) => println!("Erro na compilação C++ (try_compile): {:?}", e),
    }

    // Informa ao Cargo para linkar com as bibliotecas OpenSSL do sistema
    println!("cargo:rustc-link-lib=dylib=ssl");
    println!("cargo:rustc-link-lib=dylib=crypto");

    // Diz ao Cargo para recompilar se o hasher.cpp mudar
    println!("cargo:rerun-if-changed=src/hasher.cpp");
    println!("--- Fim build.rs ---");

    // Se try_compile falhou, faz o build.compile() falhar também para parar o processo
    if result.is_err() {
         panic!("Falha ao compilar hasher.cpp: {:?}", result.err().expect("Erro esperado aqui"));
    }
} 