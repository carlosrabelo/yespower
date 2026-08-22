# yespower

Biblioteca Rust que calcula o hash de proof-of-work yespower para cargas de trabalho relacionadas a blockchain e mineração.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

## Destaques

- Calcula hashes yespower 0.5 e 1.0 a partir de um input de bytes e um conjunto de parâmetros
- Suporta strings de personalização opcionais para variantes específicas de cadeia
- Porta o algoritmo de referência da Openwall (`yespower-ref.c`), priorizando correção em vez de velocidade máxima
- Expõe uma API idiomática pequena (`yespower`, `Params`, `Version`, `Error`)
- Valida parâmetros da mesma forma que a referência C upstream
- Inclui testes golden contra os vetores Openwall em `TESTS-OK`
- Mantém unit tests junto ao código privado e integration tests sobre a API pública
- Compila e verifica com targets `make` padrão

## Visão Geral

yespower é uma função de proof-of-work amigável a CPU e hostil a GPU, derivada do yescrypt. Em geral, o chamador hasheia inputs de tentativa (como headers de bloco) e compara o resultado de 256 bits com um alvo de dificuldade.

Este crate é uma reimplementação em Rust das fontes de referência da Openwall. Serve para testes de compatibilidade e uso leve; não é um backend de mineração otimizado com SIMD.

scrypt foi projetado por Colin Percival. yescrypt e yespower foram projetados por Solar Designer (Alexander Peslyak). Projeto upstream: <https://www.openwall.com/yespower/>.

## Pré-requisitos

- **Rust 1.73+** (stable) com Cargo — [instale via rustup](https://rustup.rs/)
- **rustfmt** e **clippy** — necessários para `make quality` (`rustup component add rustfmt clippy`)

## Instalação

### Compilar a partir do código-fonte

```bash
git clone https://github.com/carlosrabelo/yespower.git
cd yespower
make build
```

### Como dependência Cargo

```toml
[dependencies]
yespower = { git = "https://github.com/carlosrabelo/yespower.git" }
```

## Uso

### Hashear um input do tamanho de um bloco

```rust
use yespower::{yespower, Params, Version};

let src = [0u8; 80]; // e.g. block header
let params = Params {
    version: Version::V1_0,
    n: 2048,
    r: 32,
    pers: None,
};
let hash = yespower(&src, &params).expect("valid params");
assert_eq!(hash.len(), 32);
```

### Usar yespower 0.5 com personalização

```rust
use yespower::{yespower, Params, Version};

let header = [0u8; 80];
let params = Params {
    version: Version::V0_5,
    n: 2048,
    r: 8,
    pers: Some(b"Client Key"),
};
let hash = yespower(&header, &params).expect("valid params");
```

### Restrições de parâmetros

Parâmetros inválidos retornam `Err(Error::InvalidParams)`:

| Campo | Restrição |
|-------|-----------|
| `n`   | Potência de dois em `1024..=512 * 1024` |
| `r`   | Inteiro em `8..=32` |

O custo de memória é cerca de `128 * N * r` bytes no buffer principal (mais espaço scratch das S-boxes).

### Conjuntos de parâmetros sugeridos

| Memory | N    | r  |
|--------|------|----|
| 1 MiB  | 1024 | 8  |
| 2 MiB  | 2048 | 8  |
| 4 MiB  | 1024 | 32 |
| 8 MiB  | 2048 | 32 |
| 16 MiB | 4096 | 32 |

## Estrutura do Projeto

```
src/lib.rs           # API pública (yespower, Params, Version, Error)
src/yespower/        # Algoritmo de referência + unit tests
src/sha256/          # Helpers criptográficos + unit tests
tests/               # Integration tests (somente API pública)
tests/common/        # Helpers compartilhados dos integration tests
tests/golden.rs      # Vetores Openwall TESTS-OK
tests/params.rs      # Validação de parâmetros
tests/properties.rs  # Determinismo / avalanche / semântica de versão
tests/pow.rs         # Checagens PoW (nonce / target)
TESTS-OK             # Vetores golden upstream (lidos por tests/golden.rs)
.make/               # Scripts de build, test e quality
Makefile             # Ponto de entrada do desenvolvedor
Cargo.toml           # Manifesto do crate
```

## Desenvolvimento

```bash
make build      # Compila a library em release
make test       # Unit tests (src) + integration tests (tests/)
make quality    # Verifica formatação e clippy
make clean      # Remove artefatos de build do Cargo
```

## Licença

Este projeto está licenciado sob a GNU General Public License v3.0 only — veja [LICENSE](LICENSE) para detalhes.
