# Rust Analyzer e Testes no VS Code

## Problema: Testes não aparecendo na IDE

Se os testes do Rust não aparecem no VS Code (Antigravity), siga estas etapas:

### 1. Reinicie o Rust Analyzer

**Opção A: Via Command Palette**

- Pressione `Ctrl+Shift+P` (Windows/Linux) ou `Cmd+Shift+P` (Mac)
- Digite "Rust Analyzer: Restart server" e pressione Enter

**Opção B: Reload Window**

- Pressione `Ctrl+Shift+P` (Windows/Linux) ou `Cmd+Shift+P` (Mac)
- Digite "Developer: Reload Window" e pressione Enter

### 2. Verifique as Configurações

As configurações atuais do rust-analyzer estão em:

- `.vscode/settings.json` - Configurações do VS Code
- `.vscode/rust-analyzer.json` - Configurações específicas do rust-analyzer

Principais configurações:

```json
{
  "rust-analyzer.cargo.allTargets": true,
  "rust-analyzer.check.allTargets": true,
  "rust-analyzer.testExplorer": true,
  "rust-analyzer.cargo.loadOutDirsFromCheck": true,
  "rust-analyzer.runnables.extraArgs": ["--workspace"]
}
```

### 3. Reconstrua o Projeto

Se o rust-analyzer ainda não mostrar os testes:

```bash
# Limpe os artefatos de build
cargo clean

# Reconstrua os testes
cargo test --workspace --no-run

# Verifique se os testes compilam
cargo test --workspace --list | head -20
```

### 4. Verifique Logs do Rust Analyzer

Para ver logs detalhados do rust-analyzer:

1. Abra o painel "Output" em VS Code (Ctrl+Shift+U)
2. No menu dropdown, selecione "Rust Analyzer Language Server"
3. Procure por erros ou avisos relacionados a testes

### 5. Desabilite Extensões Conflitantes

Se você tiver a extensão "rust-test-adapter" instalada, pode haver conflitos:

```bash
# Verifique se está instalada
code --list-extensions | grep rust-test

# Se estiver causando problemas, considere desabilitá-la:
# File > Preferences > Extensions > desabilitar swellaby.vscode-rust-test-adapter
```

### 6. Verifique Arquivo de Testes

Certifique-se de que os arquivos de teste têm o formato correto:

```rust
// Para testes no mesmo arquivo
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() {
        // teste aqui
    }

    #[tokio::test]
    async fn test_async_something() {
        // teste assíncrono aqui
    }
}
```

### 7. Testes do Aroeira

O projeto Aroeira tem testes em:

- `libs/domain/src/modules/*/tests.rs` - Testes de domínio
- `libs/infra/src/database/tests.rs` - Testes de infraestrutura
- `libs/infra/src/database/repositories/tests/*.rs` - Testes de repositórios
- `apps/desktop/src-tauri/src/*_tests.rs` - Testes de commands
- `apps/desktop/src-tauri/src/security_tests/*.rs` - Testes de segurança

Total atual: 119 testes (82 + 1 + 3 + 33)

### 8. Solução Alternativa: Via Command Palette

Se os testes não aparecerem no explorador de testes, você ainda pode executá-los:

1. Pressione `Ctrl+Shift+P`
2. Digite "Test: Show All Tests"
3. Ou use "Test: Run Test" com o cursor sobre uma função de teste

### 9. Verifique Compilação

Certifique-se de que o projeto compila:

```bash
# Verifica se há erros de compilação
cargo check --workspace

# Verifica se há erros de linting
cargo clippy --workspace --all-targets -- -D warnings
```

### 10. Atualize Rust e Ferramentas

```bash
rustup update
cargo install --force --locked cargo-binstall  # opcional
```

## Se Nada Funcionar

Se após todas essas etapas os testes ainda não aparecerem:

1. Verifique se há erros no output do rust-analyzer
2. Tente abrir o VS Code com extensões desabilitadas para testar
3. Desinstale e reinstale a extensão rust-analyzer
4. Considere usar o IntelliJ IDEA com o plugin Rust como alternativa

## Links Úteis

- [Rust Analyzer Issues](https://github.com/rust-lang/rust-analyzer/issues)
- [VS Code Test Explorer](https://code.visualstudio.com/docs/editor/testing)
- [Rust Testing Book](https://doc.rust-lang.org/book/ch11-00-testing.html)
