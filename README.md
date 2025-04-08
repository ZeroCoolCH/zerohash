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

## Compilação

Requer Rust e as dependências OpenSSL. Para compilar:

```
cargo build --release
```

Para compilação otimizada:

```
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Performance

Em hardware moderno, o ZeroHash Finder pode atingir velocidades de verificação de 10-20 milhões de chaves por segundo.

## Aviso Legal

Esta ferramenta é fornecida apenas para fins educacionais e de pesquisa. As chances de encontrar uma chave privada em uso são praticamente nulas devido ao tamanho do espaço de chaves Bitcoin.