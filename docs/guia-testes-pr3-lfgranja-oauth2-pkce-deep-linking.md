# Guia de Teste Manual - OAuth2 PKCE com Deep Linking

Guia completo para verificar todas as funcionalidades implementadas no PR #3.

---

## 📋 Pré-requisitos

### 1. Configurar Credenciais OAuth-

Crie um arquivo `.env` na raiz do projeto:

```bash
# .env
GOOGLE_CLIENT_ID=seu-client-id-do-google.apps.googleusercontent.com
GITHUB_CLIENT_ID=seu-client-id-do-github

# Obrigatório para GitHub OAuth (troca code→token via BFF; sem isso, GitHub OAuth fica desabilitado)
GITHUB_BFF_PROXY_URL=https://auth.seu-dominio.com/github/exchange
```

**Como obter:**

- **Google**: [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials → Create OAuth 2.0 Client ID (Desktop application)
- **GitHub**: [GitHub Settings](https://github.com/settings/developers) → OAuth Apps → New OAuth App (Authorization callback URL: `aroeira://auth/callback`)

### 2. Instalar Dependências do Sistema

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev libwebkit2gtk-4.1-dev

# macOS
# (XCode Command Line Tools já inclui tudo necessário)

# Windows
# (Visual Studio Build Tools necessário)
```

---

## 🔨 Build e Execução

### Passo 1: Build do Projeto

```bash
# Na raiz do projeto
cargo build --release

# Ou para desenvolvimento (mais rápido)
cargo build
```

### Passo 2: Executar Testes

```bash
# Todos os testes
cargo test --workspace

# Apenas testes de integração do keyring
cargo test --test oauth_keyring_integration
```

**Verificação**: Devem passar 187 testes (incluindo 11 de integração do keyring).

---

## 🧪 Testes Manuais

### Teste 1: Verificar Deep Link Registration

**Objetivo**: Confirmar que o protocolo `aroeira://` está registrado no sistema.

#### Linux

```bash
# Verificar se o arquivo .desktop existe
cat ~/.local/share/applications/aroeira.desktop | grep MimeType

# Deve mostrar: MimeType=x-scheme-handler/aroeira;

# Testar o handler
xdg-mime query default x-scheme-handler/aroeira

# Deve retornar: aroeira.desktop
```

#### macOS

```bash
# Verificar registro do protocolo
lsappinfo info -only bundleid aroeira

# Ou verificar no Info.plist do bundle
cat /Applications/Aroeira.app/Contents/Info.plist | grep -A2 aroeira
```

#### Windows (PowerShell)

```powershell
# Verificar registro do protocolo
Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\aroeira"

# Deve mostrar o URL Protocol
```

**✅ Sucesso**: O protocolo `aroeira://` está registrado.

---

### Teste 2: Iniciar Fluxo OAuth (Google)

**Objetivo**: Verificar geração de PKCE e abertura do navegador.

#### Passos:

1. **Abrir o aplicativo**:

   ```bash
   cargo tauri dev
   # ou
   ./target/release/aroeira
   ```

2. **Clicar em "Sign in with Google"** no frontend

3. **Verificar logs do backend**:

   ```bash
   # Em outro terminal, verifique os logs
   tail -f /tmp/aroeira.log

   # Deve mostrar algo como:
   # [INFO] Starting OAuth flow for provider: Google
   # [INFO] Generated PKCE verifier: [hashed]
   # [INFO] Saved PKCE session to keyring: service=aroeira-oauth-pkce, key=...
   # [INFO] Opening browser: https://accounts.google.com/o/oauth2/v2/auth?...
   ```

4. **Verificar keyring** (opcional):

   #### Linux

   ```bash
   # Instalar secret-tool
   sudo apt-get install libsecret-tools

   # Buscar a sessão PKCE (descoberta)
   secret-tool search service aroeira-oauth-pkce

   # Se sua implementação armazenar também "account", faça o lookup direto:
   # (substitua <ACCOUNT> pelo valor retornado no search)
   secret-tool lookup service aroeira-oauth-pkce account <ACCOUNT>

   # Deve retornar os dados da sessão (JSON)
   ```

   #### macOS

   ```bash
   # Buscar no Keychain
   security find-generic-password -s "aroeira-oauth-pkce" -g

   # Deve mostrar a entrada
   ```

   #### Windows

   ```powershell
   # Listar credenciais
   cmdkey /list | findstr aroeira

   # Deve mostrar a entrada
   ```

**✅ Sucesso**: Navegador abre com URL do Google OAuth + PKCE parameters.

---

### Teste 3: Verificar Armazenamento Seguro no Keyring

**Objetivo**: Confirmar que o `code_verifier` não é armazenado em arquivos.

#### Passos:

1. **Após clicar em "Sign in"**, verifique que NÃO existem arquivos PKCE:

   ```bash
   # Linux
   find ~/.local/share/aroeira -name "*pkce*" 2>/dev/null

   # macOS
   find ~/Library/Application\ Support/aroeira -name "*pkce*" 2>/dev/null

   # Windows
   dir "%APPDATA%\\aroeira\\*pkce*" /s 2>nul
   ```

2. **Verificar que existe no keyring**:

   ```bash
   # Linux (usando secret-tool)
   secret-tool search service aroeira-oauth-pkce

   # Deve retornar a entrada da sessão
   ```

3. **Inspecionar conteúdo** (Linux):

   ```bash
   # O conteúdo deve ser JSON com code_verifier
   secret-tool lookup service aroeira-oauth-pkce | python3 -m json.tool

   # Deve mostrar estrutura:
   # {
   #   "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
   #   "state_hash": "...",
   #   "expires_at": 1234567890
   # }
   ```

**✅ Sucesso**: Nenhum arquivo PKCE no sistema, dados apenas no keyring.

---

### Teste 4: Callback OAuth e Troca de Token

**Objetivo**: Verificar recebimento do callback e troca do code por tokens.

#### Passos:

1. **Após autenticar no Google**, você será redirecionado para:

   ```
   aroeira://auth/callback?code=4/0A...&state=xyz123...
   ```

2. **O aplicativo deve receber automaticamente** o deep link

3. **Verificar logs**:

   ```bash
   # Deve mostrar:
   # [INFO] Received OAuth callback
   # [INFO] State parameter: xyz123...
   # [INFO] Retrieving PKCE session from keyring: key=...
   # [INFO] Exchanging code for tokens...
   # [INFO] Tokens received and stored securely
   # [INFO] Deleted PKCE session from keyring (replay protection)
   ```

4. **Verificar que a sessão foi deletada**:

   ```bash
   # Tentar buscar novamente
   secret-tool lookup service aroeira-oauth-pkce

   # Deve retornar vazio (session consumida)
   ```

**✅ Sucesso**: Tokens recebidos, sessão PKCE removida do keyring.

---

### Teste 5: Proteção Contra Replay (Consume-Once)

**Objetivo**: Verificar que a sessão PKCE só pode ser usada uma vez.

#### Passos:

1. **Tente chamar o callback novamente** com os mesmos parâmetros:

   ```bash
   # Simular re-chamada (usando curl ou browser)
   xdg-open "aroeira://auth/callback?code=4/0A...&state=xyz123..."
   ```

2. **Verificar logs**:
   ```bash
   # Deve mostrar erro:
   # [ERROR] PKCE session not found: SessionAlreadyConsumed
   # ou
   # [ERROR] Failed to exchange code: InvalidGrant
   ```

**✅ Sucesso**: Segunda tentativa falha (proteção contra replay).

---

### Teste 6: GitHub OAuth

**Objetivo**: Verificar fluxo com provider alternativo.

#### Passos:

1. **Clicar em "Sign in with GitHub"**

2. **Verificar URL gerada**:

   ```
   https://github.com/login/oauth/authorize?client_id=...&redirect_uri=aroeira://auth/callback&state=...&code_challenge=...&code_challenge_method=S256
   ```

3. **Autenticar no GitHub** e completar o fluxo

4. **Verificar que funciona igual ao Google**

**✅ Sucesso**: Fluxo GitHub completo funciona corretamente.

---

### Teste 7: CSRF Protection (State Parameter)

**Objetivo**: Verificar validação do parâmetro state.

#### Passos:

1. **Iniciar fluxo OAuth** (não complete)

2. **Modificar o callback manualmente**:

   ```bash
   # Trocar o state parameter
   xdg-open "aroeira://auth/callback?code=4/0A...&state=TAMPERED_VALUE"
   ```

3. **Verificar logs**:
   ```bash
   # Deve mostrar erro:
   # [ERROR] State mismatch: expected=abc123..., received=TAMPERED_VALUE
   # [ERROR] CSRF validation failed
   ```

**✅ Sucesso**: Callback com state inválido é rejeitado.

---

### Teste 8: Expiração de Sessão PKCE

**Objetivo**: Verificar que sessões expiradas são rejeitadas.

#### Passos:

1. **Iniciar fluxo OAuth** (não complete)

2. **Esperar 10+ minutos** (ou editar código para tempo menor em dev)

3. **Tentar completar o fluxo**

4. **Verificar logs**:
   ```bash
   # Deve mostrar:
   # [ERROR] PKCE session expired: expired_at=..., now=...
   # [WARN] Deleted expired session from keyring
   ```

**✅ Sucesso**: Sessão expirada é rejeitada e removida.

---

### Teste 9: Armazenamento de Tokens

**Objetivo**: Verificar que tokens são armazenados no keyring.

#### Passos:

1. **Complete o fluxo OAuth**

2. **Verificar tokens armazenados**:

   ```bash
   # Linux
   secret-tool lookup service aroeira-tokens account user@example.com

   # Deve mostrar JSON com:
   # - access_token
   # - refresh_token
   # - expires_at
   ```

3. **Reinicie o aplicativo**

4. **Verifique que a sessão persiste** (usuário ainda logado)

**✅ Sucesso**: Tokens persistem entre reinicializações.

---

### Teste 10: Teste de Integridade do Keyring

**Objetivo**: Verificar que o keyring funciona corretamente em diferentes cenários.

#### Passos:

1. **Executar testes de integração**:

   ```bash
   cd libs/infra
   cargo test --test oauth_keyring_integration -- --nocapture

   # Deve mostrar:
   # running 11 tests
   # test test_keyring_roundtrip ... ok
   # test test_keyring_replay_protection ... ok
   # test test_keyring_large_data ... ok
   # test test_keyring_unicode ... ok
   # test test_keyring_concurrent_access ... ok
   # test test_keyring_multiple_sessions ... ok
   # ...
   ```

2. **Verificar logs detalhados**:

   ```bash
   # Se algum teste for skipped (ambiente sem keyring):
   # [SKIP] Keyring not available, skipping test

   # Se todos passarem:
   # [INFO] Keyring test passed: roundtrip successful
   ```

**✅ Sucesso**: Todos os 11 testes de integração passam.

---

### Teste 11: Teste Cross-Process

**Objetivo**: Verificar que o cold retrieval funciona (processo diferente).

#### Passos:

1. **Iniciar fluxo OAuth no App A** (processo principal)

2. **Mat o processo do app**:

   ```bash
   pkill aroeira
   ```

3. **Simular callback de outro processo**:

   ```bash
   # Executar apenas o handler de callback em novo processo
   cargo run --bin aroeira-callback-handler "aroeira://auth/callback?code=...&state=..."
   ```

4. **Verificar que a sessão é recuperada do keyring**:
   ```bash
   # Logs devem mostrar:
   # [INFO] Cold retrieval: PKCE session not in memory, fetching from keyring...
   # [INFO] Successfully retrieved from keyring
   ```

**✅ Sucesso**: Sessão recuperada do keyring mesmo em processo diferente.

---

## 🔍 Verificações de Segurança

### Verificação 1: Nenhum Secret em Arquivos

```bash
# Buscar por strings suspeitas em arquivos
grep -r "code_verifier" ~/.local/share/aroeira/ 2>/dev/null | head -5
grep -r "access_token" ~/.local/share/aroeira/ 2>/dev/null | head -5

# Não deve retornar nada (dados só no keyring)
```

### Verificação 2: Permissões do Keyring

```bash
# Linux: Verificar que o secret-tool requer autenticação
secret-tool lookup service aroeira-oauth-pkce

# Deve retornar dados (se sessão existir)
# Se alguém tentar acessar diretamente os arquivos do keyring:
ls -la ~/.local/share/keyrings/

# Arquivos devem ter permissões restritas: -rw------- (600)
```

### Verificação 3: Verificação de Binary

```bash
# Verificar que não há CLIENT_SECRET no binário
strings target/release/aroeira | grep -i "client_secret"

# Não deve retornar nada (usamos PKCE, não client_secret)
```

---

## 📝 Checklist Final de Verificação

- [ ] Protocolo `aroeira://` registrado no sistema
- [ ] Build completo sem erros
- [ ] Todos os 187 testes passam
- [ ] Fluxo Google OAuth completo funciona
- [ ] Fluxo GitHub OAuth completo funciona
- [ ] PKCE sessions NÃO aparecem em arquivos
- [ ] PKCE sessions aparecem no keyring
- [ ] Sessão é deletada após uso (consume-once)
- [ ] Proteção CSRF funciona (state validation)
- [ ] Tokens armazenados no keyring (não em arquivos)
- [ ] Sessão persiste entre reinicializações (via keyring)
- [ ] Sessões expiradas são rejeitadas
- [ ] Tentativas de replay são bloqueadas
- [ ] Cold retrieval funciona (cross-process)

---

## 🐛 Troubleshooting

### Problema: Keyring não disponível no Linux headless

**Solução**:

```bash
# Instalar e iniciar o serviço de secrets
sudo apt-get install gnome-keyring libsecret-1-0

# Ou definir backend alternativo
export KEYRING_BACKEND=secret-service
```

### Problema: Deep link não funciona no Linux

**Solução**:

```bash
# Registrar manualmente o protocolo
xdg-mime default aroeira.desktop x-scheme-handler/aroeira

# Ou atualizar banco de dados de mime
update-mime-database ~/.local/share/mime
```

### Problema: Erro "No such file or directory" no callback

**Causa**: Sessão PKCE não encontrada no keyring.

**Verificação**:

```bash
# Verifique se a sessão existe
secret-tool lookup service aroeira-oauth-pkce

# Se vazio, o fluxo não iniciou corretamente ou já foi consumido
```

### Problema: Tokens não persistem

**Verificação**:

```bash
# Verificar se o keyring está travado
secret-tool lookup service aroeira-tokens

# Se pedir senha, o keyring está bloqueado. Desbloqueie-o primeiro.
```

---

## 📊 Métricas de Sucesso

| Métrica                     | Valor Esperado    |
| --------------------------- | ----------------- |
| Testes passando             | 187/187           |
| Tempo de build              | < 5 min (release) |
| Tempo de fluxo OAuth        | < 30 segundos     |
| Falhas de segurança         | 0                 |
| Dados sensíveis em arquivos | 0                 |

---

## ✅ Aprovação Final

Se todos os testes acima passarem, o PR está pronto para merge. O único bloqueio restante é a remoção manual do label **"Possible security concern"** por um maintainer.

**Comando para verificação final**:

```bash
./check_project.sh && \
cargo test --workspace && \
echo "✅ PR #3 pronto para merge!"
```

---

## Referências

- [PR #3 - Implementação OAuth2 PKCE](https://github.com/MDMV-Laboratorio-de-Solucoes-Digitais/aroeira-CE/pull/3)
- [Issue #2 - OAuth2 Authentication](https://github.com/MDMV-Laboratorio-de-Solucoes-Digitais/aroeira-CE/issues/2)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [Keyring Crate Documentation](https://docs.rs/keyring/latest/keyring/)

---

_Documento gerado em: 2026-02-05_
_Versão: 1.0_
_Autor: Claude (baseado na implementação do PR #3)_
