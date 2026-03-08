# Guia Completo de Testes - OAuth2 PKCE com Deep Linking (PR #3)

Guia exaustivo e detalhado para testar TODAS as funcionalidades implementadas no PR #3, com base em pesquisa aprofundada de segurança OAuth2, RFCs e melhores práticas de implementação cross-platform.

---

## 📋 Índice

1. [Pré-requisitos](#pré-requisitos)
2. [Arquitetura e Fluxo OAuth2 PKCE](#arquitetura-e-fluxo-oauth2-pkce)
3. [Build e Execução de Testes](#build-e-execução-de-testes)
4. [Testes Manuais - Plataforma-Específicos](#testes-manuais-plataforma-específicos)
   - 4.1. [Testes de Deep Linking](#testes-de-deep-linking)
   - 4.2. [Testes de Armazenamento Seguro (Keyring)](#testes-de-armazenamento-seguro-keyring)
   - 4.3. [Testes de Fluxo OAuth](#testes-de-fluxo-oauth)
5. [Testes de Segurança Profundos](#testes-de-segurança-profundos)
   - 5.1. [Testes de PKCE e RFC 7636](#testes-de-pkce-e-rfc-7636)
   - 5.2. [Testes de Proteção CSRF](#testes-de-proteção-csrf)
   - 5.3. [Testes de Replay e Consume-Once](#testes-de-replay-e-consume-once)
   - 5.4. [Testes de Validação de Redirect URI](#testes-de-validação-de-redirect-uri)
   - 5.5. [Testes de Segurança de Deep Linking](#testes-de-segurança-de-deep-linking)
   - 5.6. [Testes de CSP e Headers de Segurança](#testes-de-csp-e-headers-de-segurança)
6. [Testes Automatizados](#testes-automatizados)
7. [Métricas de Sucesso](#métricas-de-sucesso)
8. [Troubleshooting](#troubleshooting)
9. [Referências e Fontes](#referências-e-fontes)

---

## Pré-requisitos

### 1. Configurar Credenciais OAuth

Crie um arquivo `.env` na raiz do projeto:

```bash
# .env

# Google OAuth (PKCE-only - seguro para desktop)
GOOGLE_CLIENT_ID=seu-client-id-do-google.apps.googleusercontent.com

# GitHub OAuth - IMPORTANTE: Configuração de segurança
# ⚠️ PRODUÇÃO: NÃO USE GITHUB_CLIENT_SECRET no binário desktop!
# GitHub OAuth requer BFF proxy em produção para evitar embed de client_secret.
GITHUB_CLIENT_ID=seu-client-id-do-github

# Desenvolvimento APENAS: permite usar client_secret localmente
# ⚠️ NUNCA commite ou embede em builds de release!
# GITHUB_CLIENT_SECRET=seu-client-secret-do-github

# Produção (OBRIGATÓRIO para GitHub OAuth em produção)
# O BFF proxy segura o client_secret no servidor, não no cliente desktop.
GITHUB_TOKEN_URL=https://auth.seu-dominio.com/github/exchange
```

**⚠️ Segurança GitHub OAuth:**

| Ambiente            | Configuração                        | Seguro?                           |
| ------------------- | ----------------------------------- | --------------------------------- |
| **Desenvolvimento** | `GITHUB_CLIENT_SECRET` + URL padrão | ✅ Aceitável (não distribuído)    |
| **Produção**        | `GITHUB_TOKEN_URL` (BFF proxy)      | ✅ **OBRIGATÓRIO**                |
| **Produção**        | `GITHUB_CLIENT_SECRET` embedado     | ❌ **PROIBIDO** - Viola segurança |

**Como obter:**

- **Google**: [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials → Create OAuth 2.0 Client ID (Desktop application)
  - Authorized redirect URIs: `aroeira://auth/callback`
- **GitHub**: [GitHub Settings](https://github.com/settings/developers) → OAuth Apps → New OAuth App
  - Authorization callback URL: `aroeira://auth/callback`
  - Application type: Desktop application

### 2. Instalar Dependências do Sistema

#### Linux (Ubuntu/Debian)

```bash
# Dependências de build Tauri
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev libwebkit2gtk-4.1-dev

# Ferramentas de verificação de keyring
sudo apt-get install -y libsecret-tools gnome-keyring

# Ferramentas de teste de deep linking
sudo apt-get install -y xdg-utils desktop-file-utils
```

#### Linux (Fedora KDE)

```bash
# Dependências de build Tauri
sudo dnf install -y gcc gcc-c++ make cmake openssl-devel \
  gtk3-devel libappindicator-gtk3-devel librsvg2-devel \
  webkit2gtk4.1-devel

# Ferramentas de verificação de keyring
sudo dnf install -y libsecret gnome-keyring

# Ferramentas de teste de deep linking
sudo dnf install -y xdg-utils desktop-file-utils

# Ferramentas adicionais úteis (opcional)
sudo dnf install -y pkg-config clang
```

#### macOS

```bash
# XCode Command Line Tools já inclui tudo necessário
xcode-select --install

# Ferramentas de verificação (já incluídas)
security list-keychains
```

#### Windows

```bash
# Visual Studio Build Tools necessário
# Instalar via Visual Studio Installer

# Ferramentas de verificação (já incluídas)
cmdkey /list
powershell (Get-ItemProperty)
```

---

## Arquitetura e Fluxo OAuth2 PKCE

### Visão Geral do Fluxo

O PR #3 implementa autenticação OAuth2 com PKCE (Proof Key for Code Exchange - RFC 7636) para **aplicações de desktop** (navegador externo + deep link de callback).

**Fluxo PKCE Completo:**

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. FRONTEND                                                     │
│    Usuário clica "Sign in with Google/GitHub"                   │
│                                                                 │
│ 2. TAURI COMMANDS                                               │
│    start_oauth_flow()                                           │
│    - Gera code_verifier (43-128 chars, 256+ bits)               │
│    - Deriva code_challenge = SHA256(code_verifier)              │
│    - Gera state único (UUID)                                    │
│    - Armazena sessão PKCE no keyring                            │
│    - Abre navegador com URL de autorização                      │
│                                                                 │
│ 3. PROVIDER (Google/GitHub)                                     │
│    Usuário autentica no navegador                               │
│    Provider redireciona para:                                   │
│    aroeira://auth/callback?code=...&state=...                   │
│                                                                 │
│ 4. DEEP LINK HANDLER                                            │
│    on_open_url() - Tauri recebe callback                        │
│    - Valida state (proteção CSRF)                               │
│    - Recupera code_verifier do keyring                          │
│    - Troca code por tokens (HTTP POST)                          │
│                                                                 │
│ 5. TOKEN STORAGE                                                │
│    Tokens armazenados no keyring OS                             │
│    - access_token (JWT curto 5-15 min)                          │
│    - refresh_token (longa duração, dias/semanas)                │
│    - Sessão PKCE deletada (consume-once)                        │
│                                                                 │
│ 6. FRONTEND (Callback Sucesso)                                  │
│    Sessão JWT estabelecida                                      │
│    Usuário autenticado e redirecionado                          │
└─────────────────────────────────────────────────────────────────┘
```

### Componentes Implementados

#### 1. Backend Rust (`apps/desktop/src-tauri/`)

**Comandos Tauri OAuth** (`commands/oauth.rs` - 896 linhas):

```rust
// Estrutura principal
pub struct OAuthState {
    pub session_store: OAuthSessionStore,      // Memória de sessões
    pub oauth_service: Arc<OAuthServiceImpl>, // Serviço OAuth
    pub pkce_storage: Arc<dyn PkceSessionStorage>, // Keyring OS
}

// Comandos expostos ao frontend
#[tauri::command]
async fn start_oauth_flow(provider, state) -> StartOAuthResponse

#[tauri::command]
async fn handle_oauth_callback(callback_url, state) -> OAuthCallbackResponse

#[tauri::command]
async fn get_oauth_availability(state) -> OAuthAvailability
```

**Armazenamento de Sessão** (`oauth/session_store.rs` - 373 linhas):

```rust
// Thread-safe store com validação
pub struct OAuthSessionStore {
    sessions: Arc<Mutex<HashMap<String, OAuthPkceSession>>>,
    pkce_storage: Arc<dyn PkceSessionStorage>,
}

// Validações implementadas:
// - State matching (proteção CSRF)
// - Expiração (10 minutos)
// - Consume-once (uma sessão só pode ser usada uma vez)
```

**Utilitários de Validação** (`oauth_utils.rs` - 299 linhas):

```rust
// Validação de callback URL
// - Esquema aroeira://auth/callback
// - localhost:{porta}/auth/callback (apenas dev)
// - Bloqueia userinfo, portas customizadas
// - Limite de 8192 caracteres

// Deduplicação de callbacks
// - Previne processamento duplicado de deep links
// - Rate limiting de callbacks (500ms mínimo)
```

#### 2. Frontend Svelte (`apps/desktop/src/`)

**Utilities OAuth** (`lib/oauth.ts` - 521 linhas):

```typescript
// Funções principais
export function startOAuthFlow(
  provider: OAuthProvider,
): Promise<StartOAuthResponse>;
export function processOAuthCallback(
  url: string,
): Promise<OAuthCallbackResponse>;
export function openOAuthAuthUrl(authUrl: string): Promise<void>;

// Recursos de segurança
// - Deduplicação de callbacks (lastCallbackKey)
// - Sanitização de erros para audit logging
// - Obfuscação de email em logs (***@dominio)
```

**Página de Login** (`routes/login/+page.svelte` - 352 linhas):

```svelte
// Integração completa // - Estado de loading com timeout // - Reset de estado
de erro // - Tratamento de cancelamento // - Redirecionamento após sucesso //
Eventos de deep linking import {onOpenUrl} from '@tauri-apps/plugin-deep-link';
```

#### 3. BFF Proxy GitHub (`apps/proxy/`)

**Proxy de Troca de Token** (`src/routes/oauth.rs`):

```rust
// Endpoint POST /github/exchange
// - Recebe: code, redirect_uri, code_verifier
// - Valida: redirect_uri (host permitido)
// - Troca: code → access_token + refresh_token
// - Proteção SSRF (allowed hosts hardcoded)

// Validações de segurança:
// - Bounded body size (8KB máximo)
// - Strict redirect URI matching
// - Resolução segura de URL token
```

#### 4. Configuração Tauri

**tauri.conf.json** - CSP e Deep Links:

```json
{
  "plugins": {
    "deep-link": {
      "desktop": {
        "schemes": ["aroeira"]
      }
    }
  },
  "app": {
    "security": {
      "csp": "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' asset: data:; font-src 'self' asset: data:; connect-src 'self' ipc: https://accounts.google.com https://oauth2.googleapis.com https://www.googleapis.com https://github.com https://api.github.com; frame-src 'self' https://accounts.google.com https://github.com; form-action 'self'",
      "devCsp": "default-src 'self' http://localhost:1420; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; script-src 'self' 'unsafe-eval' http://localhost:1420; style-src 'self' 'unsafe-inline'; img-src 'self' asset: data: http://localhost:1420; font-src 'self' asset: data: http://localhost:1420; connect-src 'self' ipc: https://accounts.google.com https://oauth2.googleapis.com https://www.googleapis.com https://github.com https://api.github.com http://localhost:1420 ws://localhost:1420; frame-src 'self' http://localhost:1420 https://accounts.google.com https://github.com; form-action 'self'"
    }
  }
}
```

**CSP Implementada:**

- **Produção:**
  - `default-src 'self'` - JavaScript apenas do app
  - `connect-src` - Permite apenas: self, ipc, accounts.google.com, github.com, api.github.com, oauth2.googleapis.com
  - `frame-src` - Permite: self, accounts.google.com, github.com (para iframes OAuth)
  - `form-action 'self'` - Formulários apenas para mesmo origin

- **Desenvolvimento:**
  - Permite `http://localhost:1420` para hot-reload
  - WebSockets permitidos para Vite HMR

### Testes de Integração Keyring

**11 Testes Automatizados** (`libs/infra/tests/oauth_keyring_integration.rs`):

```rust
#[tokio::test]
async fn test_keyring_availability()  // Verifica se keyring está disponível

#[tokio::test]
async fn test_save_and_retrieve_session_roundtrip()  // Roundtrip completo

#[tokio::test]
async fn test_replay_protection()  // Consume-once

#[tokio::test]
async fn test_large_data()  // Dados grandes (token JWT)

#[tokio::test]
async fn test_unicode()  // Caracteres especiais em email/nome

#[tokio::test]
async fn test_concurrent_access()  // Acesso concorrente thread-safe

#[tokio::test]
async fn test_multiple_sessions()  // Múltiplas sessões simultâneas

#[tokio::test]
async fn test_persistence_across_restarts()  // Persistência entre restarts

#[tokio::test]
async fn test_cleanup_expired()  // Limpeza automática de expirados
```

---

## Build e Execução de Testes

### Passo 1: Build do Projeto

```bash
# Na raiz do projeto
cargo build --release

# Ou para desenvolvimento (mais rápido)
cargo build
```

### Passo 2: Executar Testes

```bash
# Todos os testes do workspace
cargo test --workspace

# Apenas testes de integração do keyring
cargo test --test oauth_keyring_integration -- --nocapture

# Verificar cobertura
cargo test --workspace -- --nocapture --test-threads=1
```

**Verificação Esperada:**

- 187 testes passando total (incluindo 11 de integração keyring)
- Zero warnings de clippy
- Zero testes skipped (exceto se keyring não disponível em CI headless)

---

## Testes Manuais - Plataforma-Específicos

### 4.1 Testes de Deep Linking

#### Teste 1: Verificação de Registro de Protocolo

**Objetivo**: Confirmar que o protocolo `aroeira://` está registrado corretamente no sistema operacional.

##### Linux (xdg-mime)

```bash
# Verificar se o arquivo .desktop foi criado
cat ~/.local/share/applications/aroeira-handler.desktop | grep -i "MimeType"

# Deve mostrar:
# MimeType=x-scheme-handler/aroeira;

# Verificar associação MIME padrão
xdg-mime query default x-scheme-handler/aroeira

# Deve retornar:
# aroeira-handler.desktop

# Listar todas as entradas de scheme handler
xdg-mime query default x-scheme-handler/aroeira

# Se vazio, registrar manualmente
# (O plugin deep-link registra automaticamente em debug)
update-desktop-database ~/.local/share/applications
xdg-mime default aroeira-handler.desktop x-scheme-handler/aroeira
```

**Verificação de Arquivo .desktop Esperado:**

```ini
[Desktop Entry]
Type=Application
Name=Aroeira
Exec="/path/to/executable" %u
Terminal=false
MimeType=x-scheme-handler/aroeira
NoDisplay=true
```

##### macOS (Info.plist)

```bash
# Verificar registro no bundle do app
cat /Applications/Aroeira.app/Contents/Info.plist | grep -A 10 "CFBundleURLTypes"

# Deve mostrar:
# <key>CFBundleURLTypes</key>
# <array>
#   <dict>
#     <key>CFBundleURLSchemes</key>
#       <array>
#           <string>aroeira</string>
#       </array>
#       <key>CFBundleURLName</key>
#       <string>aroeira</string>
#   </dict>
# </array>

# Verificar com lsappinfo
lsappinfo info -only bundleid aroeira

# Consultar Launch Services
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -i aroeira
```

**Verificação de Info.plist Esperado:**

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>aroeira</string>
        </array>
        <key>CFBundleURLName</key>
        <string>aroeira</string>
    </dict>
</array>
```

##### Windows (Registry)

```powershell
# Verificar registro no Registry (usuário atual)
Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Classes\aroeira"

# Deve mostrar:
# (default)    : URL:aroeira protocol
# URL Protocol :

# Verificar command de handler
Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Classes\aroeira\shell\open\command"

# Deve mostrar path para executável
# (default)    : "C:\path\to\aroeira.exe" "%1"

# Listar todos os protocolos custom
Get-ChildItem -Path "Registry::HKEY_CURRENT_USER\Software\Classes" | Where-Object { $_.PSChildName -like "aroeira*" }
```

**Estrutura de Registry Esperada:**

```registry
HKEY_CURRENT_USER\Software\Classes\aroeira
    (Default) = URL:aroeira protocol
    URL Protocol =

HKEY_CURRENT_USER\Software\Classes\aroeira\DefaultIcon
    (Default) = C:\path\to\icon.ico,0

HKEY_CURRENT_USER\Software\Classes\aroeira\shell\open\command
    (Default) = "C:\path\to\aroeira.exe" "%1"
```

**✅ Sucesso**: O protocolo `aroeira://` está registrado em todas as plataformas testadas.

---

#### Teste 2: Trigger de Deep Link via Browser

**Objetivo**: Verificar que o navegador pode invocar o deep link corretamente.

##### Teste via HTML Local

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Teste Deep Link</title>
  </head>
  <body>
    <h1>Teste de Deep Link Aroeira</h1>

    <!-- Link direto -->
    <a href="aroeira://auth/callback?code=test_code_123&state=test_state_456">
      Clique para Testar Callback OAuth
    </a>

    <h2>Testes Específicos</h2>

    <!-- Teste 1: Parâmetros Válidos -->
    <a href="aroeira://auth/callback?code=valid_code&state=valid_state">
      Teste 1: Parâmetros Válidos
    </a>
    <br />

    <!-- Teste 2: State Ausente -->
    <a href="aroeira://auth/callback?code=valid_code">
      Teste 2: State Ausente (deve falhar)
    </a>
    <br />

    <!-- Teste 3: Code Ausente -->
    <a href="aroeira://auth/callback?state=valid_state">
      Teste 3: Code Ausente (deve falhar)
    </a>

    <script>
      console.log("Links carregados. Clique para testar.");
    </script>
  </body>
</html>
```

**Como Executar:**

```bash
# Linux
firefox teste-deep-link.html
# ou
chromium-browser teste-deep-link.html

# macOS
open -a Safari teste-deep-link.html
# ou
open -a "Google Chrome" teste-deep-link.html

# Windows
start "" "teste-deep-link.html"
# ou abrir diretamente no navegador
```

**✅ Sucesso**: O aplicativo é lançado automaticamente quando um deep link é clicado.

---

#### Teste 3: Validação de URL de Deep Link

**Objetivo**: Verificar que o aplicativo rejeita deep links maliciosos ou inválidos.

##### Testes de Validação (Código Rust em `oauth_utils.rs`)

O código Rust implementa estas validações:

```rust
pub fn validate_callback_url_base(url: &Url) -> Result<(), String> {
    // 1. Validação de tamanho
    const MAX_CALLBACK_URL_LEN: usize = 8192;
    if url.as_str().len() > MAX_CALLBACK_URL_LEN {
        return Err("URL too large".to_string());
    }

    // 2. Verificação de esquema
    let is_aroeira_protocol = url.scheme().eq_ignore_ascii_case(OAUTH_CALLBACK_SCHEME);

    // 3. Bloqueio de userinfo (username:password@)
    let has_userinfo = !url.username().is_empty() || url.password().is_some();

    // 4. Validação de host
    let host = url.host_str().map(|h| h.trim_end_matches('.'));

    // 5. Modo desenvolvimento (localhost permitido)
    let is_localhost_dev = cfg!(debug_assertions)
        && url.scheme() == "http"
        && host == Some("localhost")
        && url.port() == Some(get_dev_port())
        && url.path() == "/auth/callback"
        && !has_userinfo;

    // Rejeitar se não for aroeira:// nem localhost dev
    if !is_aroeira_protocol && !is_localhost_dev {
        return Err("Invalid callback scheme".to_string());
    }

    // Rejeitar se tiver userinfo (mesmo localhost)
    if has_userinfo {
        return Err("Userinfo not allowed in callback URL".to_string());
    }

    Ok(())
}
```

**Testes Manuais de Validação:**

| Caso              | URL                                          | Resultado Esperado            |
| ----------------- | -------------------------------------------- | ----------------------------- |
| Válido            | `aroeira://auth/callback?code=...&state=...` | ✅ Aceito                     |
| Esquema inválido  | `http://other://auth/callback`               | ❌ Erro: Invalid scheme       |
| Host inválido     | `aroeira://malicious.com/auth/callback`      | ❌ Erro: Invalid host         |
| Userinfo presente | `aroeira://user:pass@auth/callback`          | ❌ Erro: Userinfo not allowed |
| Porta customizada | `aroeira://auth/callback:8080`               | ❌ Erro: Invalid port         |
| Path inválido     | `aroeira://other/path`                       | ❌ Erro: Invalid path         |
| URL muito grande  | `aroeira://auth/callback?...[>8192 chars]`   | ❌ Erro: URL too large        |

##### Teste via Comando Direto

```bash
# Linux
xdg-open "aroeira://malicious.com/auth/callback?code=test"

# macOS
open "aroeira://malicious.com/auth/callback?code=test"

# Windows
start "" "aroeira://malicious.com/auth/callback?code=test"
```

**Verificação de Logs:**

```bash
# Deve mostrar:
# [WARN] OAuth callback: invalid scheme or host
# [WARN] OAuth callback: userinfo not allowed in callback URL
# [WARN] OAuth callback: URL too large
```

**✅ Sucesso**: Deep links inválidos são rejeitados com mensagens de erro claras.

---

#### Teste 4: Comportamento Multi-Instância

**Objetivo**: Verificar que o aplicativo não abre múltiplas instâncias (Windows/Linux) ao receber deep links.

**Nota**: Tauri inclui plugin `single-instance` para este propósito.

```bash
# Linux
# 1. Iniciar o app
cargo tauri dev

# 2. Em outro terminal, clicar no deep link
xdg-open "aroeira://auth/callback?code=test&state=test"

# 3. Verificar logs
# Deve mostrar apenas uma instância aberta
# Deve mostrar callback sendo processado na instância existente
```

**Verificação de Comportamento:**

- ✅ **Single-Instance Ativo**: Uma única instância, callback redirecionado para ela
- ❌ **Single-Instance Inativo**: Múltiplas instâncias (requer configuração de plugin)

**Logs Esperados (com Single-Instance):**

```
[INFO] Single instance: Received arguments from new instance
[INFO] Deep link: aroeira://auth/callback?code=...
[INFO] Processing callback in existing instance...
```

---

### 4.2 Testes de Armazenamento Seguro (Keyring)

#### Teste 5: Verificação de Disponibilidade de Keyring

**Objetivo**: Confirmar que o keyring do sistema operacional está disponível e funcional.

##### Linux (libsecret/Secret Service)

```bash
# Verificar se serviço de secrets está rodando
dbus-send --session --dest=org.freedesktop.Secret \
    --type=method_call \
    /org/freedesktop/Secret \
    org.freedesktop.Secret.Service.OpenSession \
    2>/dev/null

# Deve retornar exit code 0 (sucesso)

# Verificar se gnome-keyring-daemon está rodando
ps aux | grep gnome-keyring-daemon

# Deve mostrar o processo em execução
```

**Se keyring não estiver disponível:**

```bash
# Instalar gnome-keyring (Ubuntu/Debian)
sudo apt-get install -y gnome-keyring libsecret-1-0

# Iniciar serviço (se necessário)
gnome-keyring-daemon --daemonize

# Verificar variável de ambiente
echo $XDG_SESSION_TYPE

# Deve mostrar: gnome, wayland, etc.
```

##### macOS (Keychain)

```bash
# Verificar keychains disponíveis
security list-keychains

# Deve mostrar:
#     "/Users/user/Library/Keychains/login.keychain-db"
#     "/Users/user/Library/Keychains/System.keychain-db"

# Testar acesso ao keychain
security find-generic-password -s "test-keyring" -g 2>&1

# Se pedir senha, keychain está funcionando
```

**Se Keychain estiver bloqueado:**

```bash
# Desbloquear keychain de login
security unlock-keychain ~/Library/Keychains/login.keychain-db

# Desbloquear keychain de sistema (requer senha de admin)
sudo security unlock-keychain /Library/Keychains/System.keychain-db
```

##### Windows (Credential Manager)

```powershell
# Verificar Credential Vault
cmdkey /list

# Deve mostrar:
# Currently stored credentials:
#
# * Target: Windows:Credential

# Listar credenciais específicas
cmdkey /list:aroeira

# Listar credenciais genéricas
cmdkey /list:Target=aroeira

# Testar criação de credencial
cmdkey /generic:test-cred /user:test /pass:test123

# Listar novamente para verificar
cmdkey /list | findstr test-cred

# Deve mostrar a credencial criada
```

**Acesso via PowerShell (PasswordVault):**

```powershell
# Testar PasswordVault API
$vault = New-Object Windows.Security.Credentials.PasswordVault
$cred = New-Object Windows.Security.Credentials.PasswordCredential
$cred.Resource = "test-aroeira"
$cred.UserName = "test-user"
$cred.Password = "test-pass"
$vault.Add($cred)

# Recuperar credencial
$retrieved = $vault.FindAllByResource("test-aroeira")
$retrieved[0].RetrievePassword()

# Deve retornar "test-pass"
```

**✅ Sucesso**: Keyring está disponível e funcional para operações CRUD.

---

#### Teste 6: Armazenamento de PKCE Code Verifier

**Objetivo**: Verificar que o `code_verifier` é armazenado apenas no keyring (NUNCA em arquivos).

##### Passos de Teste

**1. Iniciar Fluxo OAuth:**

```bash
# Abrir o aplicativo
cargo tauri dev

# Clicar em "Sign in with Google"
# O navegador deve abrir com URL de autorização
```

**2. Verificar Armazenamento em Arquivos:**

```bash
# Linux
find ~/.local/share/aroeira -name "*pkce*" -o -name "*verifier*" 2>/dev/null

# macOS
find ~/Library/Application\ Support/aroeira -name "*pkce*" 2>/dev/null

# Windows
dir "%APPDATA%\aroeira\*pkce*" /s /b 2>nul
dir "%APPDATA%\aroeira\*verifier*" /s /b 2>nul
```

**Resultado Esperado**: NENHUM arquivo encontrado (vazio).

**3. Verificar Armazenamento no Keyring:**

##### Linux (secret-tool)

```bash
# Listar todas as entradas do keyring para aroeira
secret-tool search --all service aroeira-oauth-pkce

# Deve mostrar:
# secret-tool lookup service aroeira-oauth-pkce account <ACCOUNT>

# Se sua implementação usa account como identificador:
# Substitua <ACCOUNT> pelo valor retornado no search

# Deve retornar JSON:
# {
#   "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
#   "state": "uuid-do-state",
#   "provider": "Google",
#   "expires_at": 1234567890
# }
```

**Verificação de Formato Esperado:**

```json
{
  "verifier": "string criptografada 43-128 caracteres (base64url-encoded)",
  "state": "UUID único",
  "provider": "Google ou GitHub",
  "expires_at": "timestamp Unix (agora + 600s)"
}
```

##### macOS (security command)

```bash
# Buscar no Keychain
security find-generic-password -s "aroeira-oauth-pkce" -g

# Deve mostrar entrada com:
# account: "<ACCOUNT>"
# service: "aroeira-oauth-pkce"
# attributes: [JSON com dados da sessão]

# Recuperar senha específica
# (Substitua <ACCOUNT> pelo valor retornado)
security find-generic-password \
  -s "aroeira-oauth-pkce" \
  -a "<ACCOUNT>" \
  -w

# Deve retornar o JSON da sessão
```

##### Windows (cmdkey)

```powershell
# Listar credenciais
cmdkey /list | findstr aroeira-oauth-pkce

# Deve mostrar:
# Target: aroeira-oauth-pkce
# Type: Generic
# User: <ACCOUNT>

# Recuperar senha
# (Substitua <ACCOUNT> pelo valor retornado)
cmdkey /generic:aroeira-oauth-pkce /user:<ACCOUNT>

# Deve pedir para mostrar senha (Credential Manager não mostra em texto)
```

**4. Inspecionar Conteúdo Criptografado:**

```bash
# Linux: Verificar que arquivo não é legível
hexdump -C ~/.local/share/keyrings/default.keyring | head -20

# Deve mostrar bytes aleatórios (não legível)

# macOS: Verificar keychain criptografado
security dump-keychain login.keychain | grep aroeira-oauth

# Deve mostrar dados criptografados (AES-256-GCM)

# Windows: Verificar vault criptografado
Get-ChildItem "$env:APPDATA\Microsoft\Credentials" -Recurse | Where-Object { $_.Name -like "*aroeira*" }

# Arquivos de credencial não são legíveis (protegidos por DPAPI)
```

**✅ Sucesso:**

- ✅ Nenhum arquivo PKCE no sistema
- ✅ Dados da sessão encontrados no keyring
- ✅ Dados não são legíveis em texto puro

---

#### Teste 7: Recuperação de Tokens do Keyring

**Objetivo**: Verificar que os tokens OAuth (access_token, refresh_token) são armazenados e recuperados corretamente do keyring.

##### Passos de Teste

**1. Completar Fluxo OAuth:**

```bash
# Autenticar com Google ou GitHub
# Após callback bem-sucedido, tokens são armazenados
```

**2. Verificar Armazenamento de Tokens:**

##### Linux (secret-tool)

```bash
# Buscar tokens de usuário
secret-tool lookup service aroeira-tokens account user@example.com

# Deve retornar JSON:
# {
#   "access_token": "eyJhbGci...",
#   "refresh_token": "v1.ref...",
#   "expires_at": 1234567890,
#   "provider": "google"
# }

# Listar todos os tokens armazenados
secret-tool search --all service aroeira-tokens
```

##### macOS (security command)

```bash
# Buscar tokens no Keychain
security find-generic-password \
  -s "aroeira-tokens" \
  -a "user@example.com" \
  -w

# Deve retornar o access_token

# Listar todas as entradas de token
security dump-keychain login.keychain | grep -A 3 "aroeira-tokens"
```

##### Windows (cmdkey/PowerShell)

```powershell
# Listar tokens
cmdkey /list | findstr aroeira-tokens

# Deve mostrar:
# Target: aroeira-tokens
# Type: Generic
# User: user@example.com

# Acessar via PowerShell PasswordVault
$vault = New-Object Windows.Security.Credentials.PasswordVault
$cred = $vault.FindAllByResource("aroeira-tokens") | Where-Object { $_.UserName -eq "user@example.com" }
$cred[0].RetrievePassword()
```

**Verificação de Formato Esperado:**

```json
{
  "access_token": "JWT string (assinatura digital)",
  "refresh_token": "string opaca para renovação",
  "expires_at": "timestamp Unix (agora + 3600s)",
  "provider": "google ou github",
  "token_type": "Bearer"
}
```

**3. Verificar Persistência Após Reinício:**

```bash
# 1. Verificar que tokens estão armazenados
secret-tool lookup service aroeira-tokens account user@example.com

# 2. Reiniciar o aplicativo
cargo tauri dev

# 3. Tentar recuperar tokens novamente
# Deve ser possível SEM nova autenticação

# 4. Verificar logs
# Deve mostrar: [INFO] Session restored from keyring
```

**Logs Esperados:**

```
[INFO] Retrieving tokens from keyring
[INFO] Session restored successfully
[INFO] User authenticated: user@example.com
```

**✅ Sucesso:**

- ✅ Tokens armazenados no keyring
- ✅ Tokens recuperáveis após reinício do app
- ✅ Sessão persiste sem nova autenticação

---

#### Teste 8: Rotação de Refresh Token

**Objetivo**: Verificar que refresh tokens são rotacionados (novos invalidam os antigos).

##### Implementação Esperada

```rust
// No código Rust, verifique se existe lógica de rotação:
// - Quando access_token expira, usa refresh_token
// - Armazena novo refresh_token (rotação)
// - Invalida refresh_token anterior

// Exemplo (pseudo-código):
async fn refresh_access_token(refresh_token: &str) -> Result<TokenPair> {
    let new_tokens = call_refresh_endpoint(refresh_token)?;

    // Armazenar novo refresh_token (rotação)
    keyring.set_password("aroeira-tokens", "refresh", &new_tokens.refresh_token);

    // Novo access_token também é armazenado
    Ok(new_tokens)
}
```

**Teste de Rotação:**

```bash
# 1. Obter refresh token atual
REFRESH=$(secret-tool lookup service aroeira-tokens account user@example.com | jq -r '.refresh_token')

# 2. Forçar expiração do access token (simular passagem de tempo)
# (Editar timestamp no keyring ou esperar 1 hora)

# 3. Iniciar app e tentar operação que requer refresh
cargo tauri dev

# 4. Verificar que novo refresh token foi gerado
NEW_REFRESH=$(secret-tool lookup service aroeira-tokens account user@example.com | jq -r '.refresh_token')

# 5. Verificar se rotacionou
if [ "$REFRESH" != "$NEW_REFRESH" ]; then
    echo "✅ Refresh token rotacionado com sucesso"
else
    echo "❌ Refresh token não rotacionado"
fi
```

**✅ Sucesso**: Novo refresh token é gerado e antigo é invalidado.

---

#### Teste 9: Limpeza de Tokens em Logout

**Objetivo**: Verificar que os tokens são removidos do keyring ao fazer logout.

##### Passos de Teste

**1. Fazer Logout no App:**

```bash
# Implementar botão de logout no frontend
# Deve chamar comando Tauri de logout
```

**2. Verificar Remoção do Keyring:**

##### Linux

```bash
# Antes: Verificar que tokens existem
secret-tool lookup service aroeira-tokens account user@example.com

# Executar logout
# (No app, invocar: logout() do Rust)

# Depois: Verificar que foram removidos
secret-tool lookup service aroeira-tokens account user@example.com

# Deve retornar vazio (erro: not found)
```

##### macOS

```bash
# Verificar antes
security find-generic-password -s "aroeira-tokens" -a "user@example.com" -g 2>&1

# Executar logout
# (Verificar logs do app)

# Verificar depois
security find-generic-password -s "aroeira-tokens" -a "user@example.com" 2>&1

# Deve mostrar: password: not found
```

##### Windows

```powershell
# Verificar antes
cmdkey /list | findstr aroeira-tokens

# Executar logout

# Verificar depois
cmdkey /list | findstr aroeira-tokens

# Deve não mostrar mais
```

**Logs Esperados:**

```
[INFO] Logout requested for user: user@example.com
[INFO] Deleting tokens from keyring
[INFO] Tokens deleted successfully
```

**✅ Sucesso**: Tokens são completamente removidos do keyring.

---

### 4.3 Testes de Fluxo OAuth

#### Teste 10: Inicialização do Fluxo PKCE

**Objetivo**: Verificar geração correta de PKCE (code_verifier, code_challenge, state).

##### Passos de Teste

**1. Iniciar App e Clicar em "Sign in with Google"**

```bash
cargo tauri dev
# Clicar no botão de login do frontend
```

**2. Verificar Logs de Geração PKCE:**

```bash
# Deve mostrar:
# [INFO] Starting OAuth flow for provider: Google
# [INFO] Generated PKCE verifier: [43-128 chars, base64url-encoded]
# [INFO] Derived PKCE challenge (S256): [base64url-encoded SHA256]
# [INFO] Generated state: [UUID]
# [INFO] Saved PKCE session to keyring: service=aroeira-oauth-pkce, key=state_hash
# [INFO] Opening browser: https://accounts.google.com/o/oauth2/v2/auth?...
```

**3. Verificar Parâmetros da URL de Autorização:**

A URL aberta no navegador deve conter:

```
https://accounts.google.com/o/oauth2/v2/auth?
  client_id=<GOOGLE_CLIENT_ID>
  &redirect_uri=aroeira%3A//auth/callback
  &response_type=code
  &scope=email profile
  &state=<UUID-único>
  &code_challenge=<SHA256(code_verifier)>
  &code_challenge_method=S256
```

**Validações de PKCE (RFC 7636):**

| Parâmetro               | Requisito                                | Como Verificar      |
| ----------------------- | ---------------------------------------- | ------------------- |
| `code_verifier`         | 43-128 caracteres, ≥256 bits de entropia | Verificar logs      |
| `code_challenge`        | Derivado de `code_verifier` via SHA256   | Verificar hash      |
| `code_challenge_method` | OBRIGATORIAMENTE "S256"                  | Nunca "plain"       |
| `state`                 | UUID único por sessão                    | Verificar unicidade |

**4. Verificar Armazenamento de Sessão PKCE:**

```bash
# Linux
secret-tool lookup service aroeira-oauth-pkce account <STATE_HASH>

# Deve retornar JSON com code_verifier

# macOS
security find-generic-password -s "aroeira-oauth-pkce" -a <STATE_HASH> -w

# Deve retornar senha (code_verifier codificado)
```

**✅ Sucesso**: PKCE gerado corretamente, sessão armazenada no keyring.

---

#### Teste 11: Callback OAuth e Troca de Token

**Objetivo**: Verificar recebimento de callback, recuperação de code_verifier, e troca por tokens.

##### Passos de Teste

**1. Completar Autenticação no Provider:**

```bash
# Autenticar no Google ou GitHub no navegador
# Após login, é redirecionado para:
aroeira://auth/callback?code=4/0Abc...&state=uuid-abc...
```

**2. Verificar Logs de Callback:**

```bash
# Deve mostrar:
# [INFO] Received OAuth callback: aroeira://auth/callback?code=...&state=...
# [INFO] Retrieving PKCE session from keyring: key=...
# [INFO] PKCE session retrieved successfully
# [INFO] Verifying state parameter: expected=abc..., received=abc...
# [INFO] State validation passed
# [INFO] Exchanging code for tokens...
```

**3. Verificar Chamada HTTP de Troca de Token:**

```bash
# Monitorar tráfego de rede (Linux)
sudo tcpdump -i any -A port 443 | grep -i "POST.*oauth2.*token"

# Verificar que:
# - POST para /oauth2/v4/token (Google)
# - Parâmetros: code, redirect_uri, client_id, code_verifier
# - Headers: Content-Type: application/x-www-form-urlencoded
```

**Troca de Token Google (sem BFF):**

```
POST https://oauth2.googleapis.com/token
Content-Type: application/x-www-form-urlencoded

client_id=<CLIENT_ID>
&redirect_uri=aroeira%3A//auth/callback
&grant_type=authorization_code
&code=<CODE_DO_CALLBACK>
&code_verifier=<CODE_VERIFIER_DO_KEYRING>
```

**Troca de Token GitHub (com BFF):**

```
POST https://auth.seu-dominio.com/github/exchange
Content-Type: application/json

{
  "code": "<CODE_DO_CALLBACK>",
  "redirect_uri": "aroeira://auth/callback",
  "code_verifier": "<CODE_VERIFIER_DO_KEYRING>"
}
```

**4. Verificar Armazenamento de Tokens Após Troca:**

```bash
# Recuperar tokens recém-armazenados
secret-tool lookup service aroeira-tokens account user@example.com

# Deve mostrar:
# {
#   "access_token": "eyJhbGci...",
#   "refresh_token": "v1.ref...",
#   "expires_at": 1234567890
# }
```

**5. Verificar Deleção de Sessão PKCE (Consume-Once):**

```bash
# Tentar recuperar sessão novamente
secret-tool lookup service aroeira-oauth-pkce account <STATE_HASH>

# Deve retornar vazio (erro: not found)

# Verificar logs
# Deve mostrar:
# [INFO] Deleted PKCE session from keyring (consume-once protection)
```

**✅ Sucesso**: Tokens recebidos e armazenados, sessão PKCE removida.

---

#### Teste 12: Tratamento de Erros de OAuth

**Objetivo**: Verificar que erros de OAuth são tratados e exibidos ao usuário.

##### Cenários de Erro:

**1. Cancelamento pelo Usuário:**

```bash
# Fechar janela de OAuth no navegador antes de autenticar
# Após tempo de expiração, deve mostrar mensagem

# Logs esperados:
# [WARN] OAuth flow timeout: session expired after 10 minutes
# [WARN] Cleaning up expired PKCE session
# [INFO] Session expired. Please try again.
```

**2. Erro de Estado Mismatch (CSRF):**

```bash
# Modificar parâmetro state manualmente
xdg-open "aroeira://auth/callback?code=valid_code&state=TAMPERED_VALUE"

# Logs esperados:
# [ERROR] State mismatch: expected=<original>, received=TAMPERED_VALUE
# [ERROR] CSRF validation failed
# [ERROR] Authorization rejected: Invalid state parameter
```

**3. Erro de Código Inválido/Expirado:**

```bash
# Usar código expirado ou inválido
# Simular callback com código expirado (esperar >10min)

# Logs esperados:
# [ERROR] Failed to exchange code: invalid_grant
# [ERROR] Authorization code expired or already used
# [INFO] PKCE session not found (already consumed)
```

**4. Erro de Rede/Provider Indisponível:**

```bash
# Desconectar internet e tentar OAuth

# Logs esperados:
# [ERROR] Failed to send token request: Connection refused
# [ERROR] Network error: Unable to reach provider
# [INFO] Authentication failed. Please check your connection and try again.
```

**Verificação de Tratamento de Erros no Frontend:**

```typescript
// No código Svelte, verificar tratamento de erros
try {
  await processOAuthCallback(callbackUrl);
} catch (error) {
  console.error("OAuth error:", error);
  // Deve mostrar mensagem amigável ao usuário
  // Deve resetar estado de loading
  // Deve limpar localStorage de estado pendente
}
```

**✅ Sucesso**: Todos os erros são tratados com mensagens claras ao usuário.

---

## Testes de Segurança Profundos

### 5.1 Testes de PKCE e RFC 7636

#### Teste 13: Entropia de Code Verifier

**Objetivo**: Verificar que `code_verifier` tem entropia adequada (≥256 bits).

**Referência**: RFC 7636 Seção 7.1 - O cliente DEVE criar code_verifier com mínimo 256 bits de entropia.

##### Verificação Manual

```bash
# Extrair code_verifier dos logs
# [INFO] Generated PKCE verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

# Verificar comprimento
echo "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" | wc -c

# Deve ser: 43-128 caracteres

# Verificar que é base64url válido
echo "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" | base64 -d

# Não deve retornar erro

# Calcular entropia aproximada
# Base64url com 43 caracteres ≈ 256 bits
# 43 * 6 = 258 bits de dados brutos ≈ 256 bits de entropia
```

**Verificação no Código:**

```rust
// No código Rust, verificar geração de code_verifier
use rand::rngs::OsRng;
use base64::prelude::*;

fn generate_code_verifier() -> String {
    let mut verifier = vec
![0u8; 128]; // 128 bytes aleatórios = 1024 bits

    OsRng.fill_bytes(&mut verifier);

    // Codificar em base64url
    BASE64_URL_SAFE_NO_PAD.encode(&verifier)

    // 43-128 caracteres é o tamanho correto
    // (43 * 6 = 258 bits de dados brutos ≈ 256 bits de entropia)
}
```

**✅ Sucesso**: Code verifier tem 43-128 caracteres (≥256 bits entropia).

---

#### Teste 14: Derivação de Code Challenge S256

**Objetivo**: Verificar que `code_challenge` é derivado corretamente via SHA256 de `code_verifier`.

**Referência**: RFC 7636 Seção 4.3 - code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)).

##### Verificação Manual

```bash
# Dados de exemplo:
CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE_ESPERADO="E9Melhoa2O-4cN0gHJNQf8r1T8H0Z3uY6qXsQbE"

# Verificar SHA256
echo -n "$CODE_VERIFIER" | sha256sum | cut -d' ' ' -f1

# Deve ser o mesmo que decodificado do CHALLENGE_ESPERADO
echo -n "$CHALLENGE_ESPERADO" | base64 -d | sha256sum | cut -d' ' -f1

# Deve ser: c1e80a45ef89c70d3928a6581bd8c7f0bd666c60c502
```

**Verificação no Código:**

```rust
use sha2::{Digest, Sha256};
use base64::prelude::*;

fn derive_code_challenge(verifier: &str) -> Result<String, Error> {
    // 1. Decodificar verifier de base64url
    let verifier_bytes = BASE64_URL_SAFE_NO_PAD.decode(verifier)?;

    // 2. Calcular SHA256
    let mut hasher = Sha256::new();
    hasher.update(&verifier_bytes);
    let hash = hasher.finalize();

    // 3. Codificar em base64url
    Ok(BASE64_URL_SAFE_NO_PAD.encode(&hash))
}
```

**✅ Sucesso**: Code challenge é SHA256 base64url-encoded do code verifier.

---

#### Teste 15: Proibição de Método "plain"

**Objetivo**: Verificar que o cliente NUNCA aceita `code_challenge_method=plain`.

**Referência**: RFC 7636 Seção 7.2 - Clientes NÃO DEVEM fazer downgrade de "S256" para "plain".

##### Verificação de Código

```rust
// No código Rust, verificar que nunca usa "plain"
// Deve ser hardcoded como "S256"

const CODE_CHALLENGE_METHOD: &str = "S256";

fn build_authorization_url() -> Url {
    // VERIFICAR: Nunca usar plain
    url.query_pairs_mut()
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", CODE_CHALLENGE_METHOD)

    // ...
}
```

**Teste de MITM (Interceptação e Tentativa de Downgrade):**

```bash
# Usar proxy (ex: mitmproxy, Burp Suite)
# Interceptar requisição de autorização
# Modifica code_challenge_method para plain
# Verificar se cliente rejeita

# Esperado: Rejeição com erro
# (RFC 7636: Client must not downgrade to plain)
```

**Logs Esperados (se tentativa de downgrade):**

```
[ERROR] Authorization server rejected code_challenge_method=plain
[WARN] PKCE downgrade attempt detected
[ERROR] PKCE protection violated
```

**✅ Sucesso**: Cliente sempre usa "S256", rejeita "plain".

---

#### Teste 16: Validação de Redirect URI Exata

**Objetivo**: Verificar que apenas redirect URIs pré-registradas são aceitas (sem wildcards).

**Referência**: RFC 9700 BCP 240 - Exact string matching para redirect URIs (sem wildcards).

##### Testes de Validação:

| URI de Teste                                | Resultado Esperado                     |
| ------------------------------------------- | -------------------------------------- |
| `aroeira://auth/callback`                   | ✅ Aceito (URI exata registrada)       |
| `aroeira://auth/callback/extra`             | ❌ Rejeitado (path diferente)          |
| `aroeira://other-callback`                  | ❌ Rejeitado (path diferente)          |
| `http://localhost:1420/auth/callback` (dev) | ✅ Aceito (localhost permitido em dev) |
| `http://malicious.com/auth/callback`        | ❌ Rejeitado (host diferente)          |
| `https://evil.com/auth/callback`            | ❌ Rejeitado (esquema diferente)       |

**Verificação no Código Rust (`oauth_utils.rs`):**

```rust
pub fn validate_callback_url_base(url: &Url) -> Result<(), String> {
    // Validações implementadas:
    // 1. Esquema deve ser aroeira:// ou http://localhost
    // 2. Host não deve userinfo
    // 3. Path deve ser exatamente /auth/callback
    // 4. Porta customizada não permitida (exceto em dev)

    // Implementação usa validação estrita (sem wildcards)
    // if url.path() != "/auth/callback" {
    //     return Err("Invalid callback path".to_string());
    // }
}
```

**Teste de Configuração BFF GitHub (`apps/proxy/src/routes/oauth.rs`):**

```rust
// No código do proxy, verificar validação de redirect_uri
fn validate_redirect_uri(payload: &GitHubTokenRequest, config: &OAuthConfig) -> Result<(), AppError> {
    // Validações:
    // 1. Host deve estar na lista de allowed_hosts
    // 2. Não deve ter port customizada
    // 3. Path deve ser exato (prefix matching)
    // 4. Bloqueia userinfo na redirect URI

    // Verificação de SSRF: Hosts permitidos são hardcoded
    // if !config.github_allowed_hosts.contains(&redirect_uri.host_str()) {
    //     return Err("Invalid redirect URI host".to_string());
    // }
}
```

**✅ Sucesso**: Apenas URIs exatamente registradas são aceitas.

---

#### Teste 17: Validação de Tamanho de Token

**Objetivo**: Verificar que tokens têm limite de tamanho (8KB para prevenir DoS).

**Referência**: RFC 9700 - Tokens razoavelmente pequenos (JWTs tipicamente <2KB, mas 8KB como limite defensivo).

##### Verificação de Código

```rust
// No código Rust, verificar limite de tamanho
const MAX_TOKEN_SIZE: usize = 8 * 1024; // 8KB

fn validate_token_size(token: &str) -> Result<(), Error> {
    if token.len() > MAX_TOKEN_SIZE {
        return Err("Token too large".to_string());
    }
    Ok(())
}
```

**Teste de Token Excessivamente Grande:**

```bash
# Simular token gigante (>8KB)
# Tentar armazenar no keyring
TOKEN=$(python3 -c "print('A' * 10000)")  # 10KB
secret-tool store service test account user --password "$TOKEN"

# Deve ser rejeitado pelo código
# Ou pelo menos avisar no logs
```

**Logs Esperados:**

```
[WARN] Token size (10000 bytes) exceeds recommended maximum (8KB)
[WARN] Token validation: size check passed but unusual size detected
```

**✅ Sucesso**: Tokens grandes são rejeitados ou avisados.

---

### 5.2 Testes de Proteção CSRF

#### Teste 18: Geração e Validação de State Parameter

**Objetivo**: Verificar que o parâmetro `state` previne ataques CSRF.

**Referência**: Auth0 Documentation - State parameter previne CSRF usando nonce único por requisição.

##### Passos de Teste

**1. Iniciar Fluxo OAuth:**

```bash
# Iniciar app
cargo tauri dev

# Clicar em "Sign in with Google"
# Verificar logs:
# [INFO] Generated state: abc123-def456...
```

**2. Verificar que State é Único:**

```bash
# Iniciar 2 fluxos OAuth sequencialmente
# Verificar que states são diferentes

# Logs devem mostrar:
# [INFO] Generated state: uuid-1...
# [INFO] Generated state: uuid-2...

# (UUIDs devem ser diferentes)
```

**3. Verificar Validação no Callback:**

```bash
# Completar autenticação normalmente
# Callback deve ter state correto: aroeira://auth/callback?code=...&state=uuid-1

# Logs esperados:
# [INFO] Received OAuth callback
# [INFO] Verifying state parameter: expected=uuid-1, received=uuid-1
# [INFO] State validation passed
```

**4. Teste de Tamperamento de State:**

```bash
# Modificar parâmetro state manualmente
xdg-open "aroeira://auth/callback?code=valid_code&state=TAMPERED_VALUE"

# Logs esperados:
# [ERROR] State mismatch: expected=uuid-1, received=TAMPERED_VALUE
# [ERROR] CSRF validation failed
# [ERROR] Authorization rejected: Invalid state parameter
```

**Verificação no Código Rust:**

```rust
// No código Rust, verificar validação
fn verify_state_parameter(
    session: &OAuthPkceSession,
    callback_state: &str,
) -> Result<(), String> {
    // Comparar state da sessão com state do callback
    if session.state != callback_state {
        return Err("State mismatch".to_string());
    }
    Ok(())
}

// Deve também invalidar state de callback no código
// para evitar reuso de states antigos
```

**✅ Sucesso**: States únicos são validados, states modificados são rejeitados.

---

#### Teste 19: State com Dados da Aplicação

**Objetivo**: Verificar que o state pode incluir dados da aplicação (redirect URL, etc.).

**Referência**: Auth0 Documentation - State pode armazenar estado da aplicação (redirect URL após auth).

##### Teste com Redirect URL no State:\*\*

```bash
# Simular state com redirect URL codificado
STATE_URL_ENCODED=$(echo '{"redirect":"/dashboard"}' | base64 -w 0)

# Navegar para URL com state customizado
# (Simular que frontend usa state para redirecionamento)
# aroeira://auth/callback?code=...&state=$STATE_URL_ENCODED

# Verificar logs
# Deve mostrar decode do state e redirecionamento
```

**Verificação no Código:**

```rust
// Verificar se state codifica dados adicionais
struct OAuthPkceSession {
    pub state: String,           // UUID único (anti-CSRF)
    pub redirect_url: Option<String>,  // Opcional: redirecionar após sucesso
    // ...
}

// No callback, verificar decodificação
fn handle_callback_with_redirect(session: &OAuthPkceSession) -> String {
    if let Some(redirect) = session.redirect_url {
        return redirect;  // Redirecionar para URL armazenada no state
    }
    "/dashboard".to_string()  // Padrão
}
```

**✅ Sucesso**: State pode incluir dados da aplicação para redirecionamento.

---

### 5.3 Testes de Replay e Consume-Once

#### Teste 20: Proteção Consume-Once para Authorization Code

**Objetivo**: Verificar que um código de autorização só pode ser usado uma vez.

**Referência**: RFC 9700 - Authorization codes devem ser single-use para prevenir replay.

##### Passos de Teste

**1. Iniciar Fluxo OAuth:**

```bash
# Autenticar normalmente
# Verificar logs:
# [INFO] PKCE session saved: key=state_hash
```

**2. Capturar Authorization Code do Callback:**

```bash
# Monitorar logs ou interceptar requisição
# URL de callback: aroeira://auth/callback?code=4/0Abc...&state=...

# Copiar o código de autorização
CODE="4/0Abc..."
```

**3. Tentar Reusar o Mesmo Código:**

```bash
# Simular nova requisição de token com o MESMO código
xdg-open "aroeira://auth/callback?code=$CODE&state=...&code_verifier=..."

# Verificar logs
# Deve mostrar erro:
# [ERROR] PKCE session not found: SessionAlreadyConsumed
# ou
# [ERROR] Failed to exchange code: invalid_grant
```

**Verificação no Código Rust (`oauth/session_store.rs`):**

```rust
// Verificar implementação de consume-once
pub struct OAuthSessionStore {
    // ...
}

impl OAuthSessionStore {
    pub fn take_valid(
        &self,
        state: &str,
        request_id: &str,
    ) -> Option<OAuthPkceSession> {
        let mut sessions = self.sessions.lock();

        // 1. Buscar sessão por state
        let session = sessions.get(state)?;

        // 2. Validar
        if session.is_expired() {
            // Remover e retornar None
            sessions.remove(state);
            return None;
        }

        // 3. Remover (consume-once)
        // Deleta também do keyring para limpeza imediata
        self.pkce_storage.delete_session(state);
        let session_to_return = sessions.remove(state);

        Some(session_to_return)
    }
    // ...
}
```

**Logs Esperados:**

```
[INFO] Taking session: key=state_hash
[INFO] Session valid and not consumed
[INFO] Deleting PKCE session from keyring (consume-once protection)
[INFO] Session deleted successfully

# (Na segunda tentativa)
[ERROR] PKCE session not found: SessionAlreadyConsumed
[ERROR] Authorization code already used or expired
```

**✅ Sucesso**: Segunda tentativa com mesmo código falha (consume-once).

---

#### Teste 21: Proteção Consume-Once para PKCE Session

**Objetivo**: Verificar que a sessão PKCE no keyring também é single-use.

##### Passos de Teste

**1. Verificar que Sessão Foi Deletada Após Uso:**

```bash
# Depois de troca bem-sucedida:

secret-tool lookup service aroeira-oauth-pkce account <STATE_HASH>

# Deve retornar vazio (erro: not found)

# 2. Tentar reusar code_verifier
# Simular nova tentativa com o mesmo state
```

**Verificação de Limpeza Automática:**

```rust
// Verificar código de limpeza em session_store
fn clean_expired_sessions(&self) {
    let mut sessions = self.sessions.lock();

    // Coletar expirados
    let expired: Vec<_> = sessions
        .iter()
        .filter(|(_, s)| s.is_expired())
        .map(|(k, _)| k.clone())
        .collect();

    // Deletar da memória e do keyring
    for state_hash in expired {
        sessions.remove(&state_hash);
        self.pkce_storage.delete_session(&state_hash);
    }
}
```

**✅ Sucesso**: Sessões PKCE expiradas são limpas automaticamente.

---

#### Teste 22: Expiração de Sessão PKCE

**Objetivo**: Verificar que sessões PKCE expiram após 10 minutos (ou tempo configurado).

**Referência**: Implementação usa expiração de 10 minutos (600 segundos).

##### Passos de Teste

**1. Iniciar Fluxo OAuth:**

```bash
# Anotar timestamp atual
BEFORE=$(date +%s)

# Iniciar app
cargo tauri dev

# Clicar em "Sign in with Google"
```

**2. Esperar Expiração (10 minutos):**

```bash
# Aguardar 11 minutos
sleep 660

# Tentar completar fluxo
xdg-open "aroeira://auth/callback?code=...&state=..."

# Logs esperados:
# [ERROR] PKCE session expired: expired_at=..., now=...
# [WARN] Deleted expired session from keyring
# [ERROR] Authorization failed: Session expired
```

**3. Verificar Implementação:**

```rust
// No código Rust, verificar lógica de expiração
struct OAuthPkceSession {
    pub expires_at: i64,  // Timestamp Unix de expiração
    // ...
}

impl OAuthPkceSession {
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now >= self.expires_at
    }
}
```

**Teste com Expiração Curta (para desenvolvimento):**

```bash
# Modificar código para usar 30 segundos em dev
// const SESSION_EXPIRATION_SECONDS: u64 = if cfg!(debug_assertions) { 30 } else { 600 };

# Testar com expiração de 30s
sleep 35

# Tentar callback
# Deve ser rejeitado
```

**✅ Sucesso**: Sessões expiram após período configurado.

---

### 5.4 Testes de Validação de Redirect URI

#### Teste 23: Validação de Host Permitido (BFF GitHub)

**Objetivo**: Verificar que o BFF GitHub só aceita hosts pré-configurados (proteção SSRF).

**Referência**: Implementação em `apps/proxy/src/routes/oauth.rs` usa `allowed_hosts` hardcoded.

##### Configuração de Allowed Hosts:\*\*

```bash
# Verificar configuração no código ou .env
# .env deve conter:
GITHUB_ALLOWED_HOSTS=github.com,github-enterprise.com

# Ou hardcoded no código Rust:
const ALLOWED_HOSTS: &[&str] = &["github.com", "api.github.com", "github-enterprise.com"];
```

**Testes de Validação:**

| Redirect URI                               | Resultado Esperado                |
| ------------------------------------------ | --------------------------------- |
| `aroeira://auth/callback` (github.com)     | ✅ Aceito                         |
| `aroeira://auth/callback` (malicious.com)  | ❌ Rejeitado (host não permitido) |
| `aroeira://auth/callback` (evil.com)       | ❌ Rejeitado (host não permitido) |
| `aroeira://auth/callback` (sub.github.com) | ⚠️ Depende de configuração        |

**Verificação no Código Rust (`apps/proxy/src/routes/oauth.rs`):**

```rust
fn resolve_github_token_url(
    token_url: &Option<String>,
    allowed_hosts: &[String],
) -> Result<Url, AppError> {
    // 1. Resolver URL token
    let url = match token_url {
        Some(u) => Url::parse(&u)?,
        None => Url::parse("https://github.com/login/oauth/access_token")?,
    };

    // 2. Validar host
    let host = url.host_str().ok_or_else(|| {
        AppError::BadRequest("Invalid token URL host".to_string())
    })?;

    // 3. Verificar se está na lista de permitidos
    if !allowed_hosts.contains(&host) {
        return Err(AppError::BadRequest(
            format!("Redirect URI host not allowed: {}", host)
        ));
    }

    Ok(url)
}
```

**Logs Esperados (host inválido):**

```
[ERROR] Invalid OAuth request payload
[ERROR] Redirect URI host not allowed: malicious.com
[WARN] SSRF attempt detected
```

**✅ Sucesso**: Apenas hosts configurados são permitidos.

---

#### Teste 24: Validação de Parâmetros de Callback

**Objetivo**: Verificar que o BFF valida todos os parâmetros obrigatórios.

**Referência**: Implementação usa `validator` crate para validar payload JSON.

##### Testes de Validação:\*\*

```bash
# Teste 1: Payload Válido
curl -X POST https://auth.seu-dominio.com/github/exchange \
  -H "Content-Type: application/json" \
  -d '{
    "code": "valid_code",
    "redirect_uri": "aroeira://auth/callback",
    "code_verifier": "valid_verifier"
  }'

# Deve retornar 200 OK

# Teste 2: Campo Ausente
curl -X POST https://auth.seu-dominio.com/github/exchange \
  -H "Content-Type: application/json" \
  -d '{
    "code": "valid_code",
    "redirect_uri": "aroeira://auth/callback"
    }'  # code_verifier ausente

# Deve retornar 400 Bad Request
```

**Verificação no Código Rust:**

```rust
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct GitHubTokenRequest {
    #[validate(length(min = 1, max = 2048))]
    pub code: String,

    #[validate(length(min = 1, max = 2048))]
    pub code_verifier: String,

    #[validate(url)]
    pub redirect_uri: String,
}

// Validação automática via derive Validate
// payload.validate()? retorna Err se inválido
```

**✅ Sucesso**: Payloads inválidos são rejeitados com erro 400.

---

### 5.5 Testes de Segurança de Deep Linking

#### Teste 25: Validação de Input de Deep Link

**Objetivo**: Verificar que deep links são validados antes de processamento.

**Referência**: Implementação em `oauth_utils.rs` valida URL scheme, host, path, userinfo.

##### Testes de Validação:\*\*

| URL de Deep Link                               | Resultado Esperado                  |
| ---------------------------------------------- | ----------------------------------- |
| `aroeira://auth/callback?code=...`             | ✅ Aceito                           |
| `aroeira://auth/callback?code=...&extra=param` | ✅ Aceito (params extras ignorados) |
| `aroeira://other/path`                         | ❌ Rejeitado (path inválido)        |
| `aroeira://malicious.com/callback`             | ❌ Rejeitado (host inválido)        |
| `aroeira://user:pass@auth/callback`            | ❌ Rejeitado (userinfo presente)    |
| `javascript:alert(1)//aroeira://...`           | ❌ Rejeitado (obfuscação detectada) |

**Verificação no Código Rust (`oauth_utils.rs`):**

```rust
// Validações implementadas:
// 1. Esquema deve ser "aroeira"
// 2. Path deve ser "/auth/callback"
// 3. Host não deve ter userinfo
// 4. Tamanho máximo de 8192 caracteres

pub fn validate_callback_url_base(url: &Url) -> Result<(), String> {
    // Validação de hostless (scheme://path sem host)
    const HOSTLESS_PATH: &str = "auth/callback";

    // Bloquear userinfo (username:password@)
    let has_userinfo = !url.username().is_empty() || url.password().is_some();
    if has_userinfo {
        return Err("Userinfo not allowed in callback URL".to_string());
    }

    Ok(())
}
```

**Teste de Obfuscação:**

```bash
# Testar com obfuscação de esquema
# "java\u0000script:aroeira://auth/callback"

# Deve ser rejeitado
# [WARN] OAuth callback: invalid scheme or host (detected obfuscation)
```

**✅ Sucesso**: Deep links são validados, rejeitando entradas maliciosas.

---

#### Teste 26: Deduplicação de Callbacks

**Objetivo**: Verificar que callbacks duplicados são deduplicados (previne processamento múltiplo).

**Referência**: Implementação em `lib/oauth.ts` usa `lastCallbackKey` para deduplicar.

##### Teste de Deduplicação:\*\*

```bash
# 1. Iniciar fluxo OAuth
cargo tauri dev

# 2. Clicar em "Sign in with Google"
# Callback deve ser processado uma vez

# 3. Simular callbacks duplicados (rápidos)
# O plugin deep-link pode disparar múltiplos callbacks
# + evento de single-instance também pode disparar

# Verificar logs
# Deve mostrar dedup working:
# [INFO] Callback dedup: key=... already processed recently (500ms ago)
# [INFO] Skipping duplicate callback processing
```

**Verificação no Código TypeScript (`lib/oauth.ts`):**

```typescript
// Variáveis de deduplicação
let lastCallbackKey: string | null = null;
let lastCallbackAt = 0;

export function processOAuthCallback(
  url: string,
): Promise<OAuthCallbackResponse> {
  // Chave única do callback (state ou hash)
  const callbackKey = extractCallbackKey(url);

  // Rate limiting: 500ms mínimo entre callbacks com mesma chave
  const now = Date.now();
  if (lastCallbackKey === callbackKey && now - lastCallbackAt < 500) {
    console.log("[OAuth] Skipping duplicate callback (too soon)");
    oauthCallbackQueue.resolve();
    return;
  }

  // Atualizar estado
  lastCallbackKey = callbackKey;
  lastCallbackAt = now;

  // Processar callback
  // ...
}
```

**✅ Sucesso**: Callbacks duplicados próximos são rejeitados (mínimo 500ms entre mesmos).

---

### 5.6 Testes de CSP e Headers de Segurança

#### Teste 27: Validação de CSP (Content Security Policy)

**Objetivo**: Verificar que CSP está configurada corretamente para restringir scripts e recursos externos.

**Referência**: `tauri.conf.json` - CSP configurada para produção e desenvolvimento.

##### Verificação de CSP de Produção:\*\*

```json
{
  "csp": "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' asset: data:; font-src 'self' asset: data:; connect-src 'self' ipc: https://accounts.google.com https://oauth2.googleapis.com https://www.googleapis.com https://github.com https://api.github.com; frame-src 'self' https://accounts.google.com https://github.com; form-action 'self'"
}
```

**Diretivas CSP Explicadas:**

| Diretiva                           | Propósito                                                                | Valor                                                 |
| ---------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------- |
| `default-src 'self'`               | Frame principal apenas do app                                            | `self`                                                |
| `script-src 'self'`                | Scripts apenas do app (inline permitido via 'unsafe-inline' para Svelte) | `self`                                                |
| `style-src 'self' 'unsafe-inline'` | Styles do app (inline permitido)                                         | `self 'unsafe-inline'`                                |
| `connect-src`                      | Conexões permitidas (OAuth endpoints + IPC)                              | `self ipc: https://accounts.google.com ...`           |
| `img-src`                          | Imagens do app                                                           | `self asset: data:`                                   |
| `font-src`                         | Fontes do app                                                            | `self asset: data:`                                   |
| `frame-src`                        | Iframes OAuth permitidos                                                 | `self https://accounts.google.com https://github.com` |
| `form-action 'self'`               | Formulários apenas para mesmo origin                                     | `self`                                                |

**Teste de CSP:**

```bash
# 1. Iniciar app em modo produção
cargo tauri build --release
./target/release/aroeira

# 2. Abrir DevTools do WebView (se disponível)
# 3. Tentar injetar script externo (via console ou extensão)
document.createElement('script').src = 'https://evil.com/evil.js'

# 4. Verificar logs
# Deve mostrar violação de CSP
# [WARN] CSP violation: script-src blocked https://evil.com/evil.js
```

##### Verificação de CSP de Desenvolvimento:\*\*

```json
{
  "devCsp": "default-src 'self' http://localhost:1420; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; script-src 'self' 'unsafe-eval' http://localhost:1420; style-src 'self' 'unsafe-inline'; img-src 'self' asset: data: http://localhost:1420; font-src 'self' asset: data: http://localhost:1420; connect-src 'self' ipc: https://accounts.google.com https://oauth2.googleapis.com https://www.googleapis.com https://github.com https://api.github.com http://localhost:1420 ws://localhost:1420; frame-src 'self' http://localhost:1420 https://accounts.google.com https://github.com; form-action 'self'"
}
```

**Diferenças Dev vs Prod:**

| Diretiva      | Produção      | Desenvolvimento                               |
| ------------- | ------------- | --------------------------------------------- |
| `default-src` | `'self'`      | `'self' http://localhost:1420`                |
| `script-src`  | `'self'`      | `'self' 'unsafe-eval'` (permite eval do Vite) |
| `connect-src` | Sem WebSocket | `ws://localhost:1420` (permite HMR)           |

**✅ Sucesso**: CSP restringe scripts e recursos externos.

---

#### Teste 28: Headers de Segurança HTTP

**Objetivo**: Verificar que requisições OAuth usam headers de segurança apropriados.

**Referência**: RFC 9700 - Requisições OAuth devem incluir headers padrão.

##### Headers Esperados:\*\*

| Header                                            | Propósito                   |
| ------------------------------------------------- | --------------------------- |
| `User-Agent`                                      | Identificar cliente (Tauri) |
| `Accept: application/json`                        | Esperar JSON em respostas   |
| `Authorization: Bearer <token>`                   | Autenticação com tokens     |
| `Content-Type: application/x-www-form-urlencoded` | POST com form data          |

**Verificação no Código Rust:**

```rust
use reqwest::Client;

// Verificar headers nas requisições OAuth
let response = client
    .post(token_url)
    .header("Accept", "application/json")           // Esperar JSON
    .header("Content-Type", "application/x-www-form-urlencoded")  // Form data
    .header("User-Agent", "Aroeira/1.0")           // Identificar cliente
    .form(&params)
    .send()
    .await?;
```

**Teste com curl:**

```bash
# Verificar headers em requisição real
curl -v -X POST https://oauth2.googleapis.com/token \
  -H "Accept: application/json" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=...&code=...&code_verifier=..." \
  2>&1 | grep -i "HTTP/"

# Deve mostrar:
# > Accept: application/json
# > Content-Type: application/x-www-form-urlencoded
```

**✅ Sucesso**: Headers de segurança são enviados corretamente.

---

## Testes Automatizados

### Execução de Testes Unitários e Integração

```bash
# Todos os testes do workspace (187 testes)
cargo test --workspace -- --nocapture

# Testes específicos de segurança
cargo test --test filesystem_security_tests
cargo test --test auth_tests
cargo test --test oauth_keyring_integration

# Verificar warnings
cargo clippy --all-targets -- -D warnings

# Verificar formato
cargo fmt -- --check

# Teste de cobertura (se configurado)
cargo tarpaulin --out-dir ./coverage
```

### Testes de Keyring Integration (11 testes)

```bash
# Executar apenas testes de integração de keyring
cargo test --test oauth_keyring_integration -- --nocapture --test-threads=1

# Saída esperada:
# running 11 tests
# test test_keyring_availability ... ok
# test test_save_and_retrieve_session_roundtrip ... ok
# test test_replay_protection ... ok
# test test_large_data ... ok
# test test_unicode ... ok
# test test_concurrent_access ... ok
# test test_multiple_sessions ... ok
# test test_persistence_across_restarts ... ok
# test test_cleanup_expired ... ok
# test test_deduplication ... ok
# test test_consume_once_with_callback ... ok
# ...

# test result: ok. 11 passed; 0 failed; 0 skipped; 0 measured
```

### Testes de Segurança de Arquivos

```bash
# Verificar que não há segredos em arquivos
grep -r "code_verifier" ~/.local/share/aroeira/ 2>/dev/null | head -5
grep -r "access_token" ~/.local/share/aroeira/ 2>/dev/null | head -5
grep -r "client_secret" ~/.local/share/aroeira/ 2>/dev/null | head -5

# Não deve retornar nada (dados só no keyring)
# Verificar logs em busca de vazamento
grep -r "token.*=" /tmp/aroeira.log | head -5

# Tokens não devem aparecer em logs
```

---

## Métricas de Sucesso

### Métricas de Cobertura

| Métrica             | Valor Esperado   | Como Verificar                                |
| ------------------- | ---------------- | --------------------------------------------- |
| Testes Totais       | 187/187 passando | `cargo test --workspace`                      |
| Testes Keyring      | 11/11 passando   | `cargo test --test oauth_keyring_integration` |
| Testes de Segurança | Todos passando   | Verificar logs de testes de segurança         |
| Warnings de Clippy  | 0                | `cargo clippy`                                |
| Formatação          | Sem erros        | `cargo fmt --check`                           |
| Build Release       | Sucesso          | `cargo build --release`                       |

### Métricas de Performance

| Métrica                         | Valor Esperado    |
| ------------------------------- | ----------------- | --------------------------------- |
| Tempo de Build                  | < 5 min (release) | `time cargo build --release`      |
| Tempo de Fluxo OAuth            | < 30 segundos     | Cronometrar do clique ao callback |
| Tempo de Troca de Token         | < 5 segundos      | Cronometrar do callback ao token  |
| Tempo de Recuperação do Keyring | < 100ms           | Monitorar logs                    |

### Métricas de Segurança

| Métrica                  | Valor Esperado | Como Verificar                                  |
| ------------------------ | -------------- | ----------------------------------------------- |
| Segredos em Arquivos     | 0              | `grep -r "secret"` em arquivos                  |
| Segredos em Logs         | 0              | `grep -r "token"` em logs (deve estar ofuscado) |
| Falhas de CSRF           | 0              | Tentar state tampering                          |
| Falhas de Replay         | 0              | Tentar reusar authorization code                |
| Falhas de PKCE Downgrade | 0              | Tentar plain method                             |
| Vazamento de Tokens      | 0              | Verificar logs do backend                       |
| Validação de CSP         | 100%           | Testar injeção de scripts externos              |
| Validação de PKCE        | 100%           | Sempre usar S256, never plain                   |

---

## Troubleshooting

### Problema: Keyring Não Disponível (Linux)

**Sintoma**: Erro "Keyring not available" ao iniciar OAuth.

**Causa**: Ambiente headless sem gnome-keyring/libsecret rodando.

**Solução:**

```bash
# 1. Instalar gnome-keyring (Ubuntu/Debian)
sudo apt-get install -y gnome-keyring libsecret-1-0

# 2. Iniciar serviço (se necessário)
gnome-keyring-daemon --daemonize

# 3. Verificar variável de ambiente
echo $XDG_SESSION_TYPE

# Deve mostrar: gnome, wayland, etc.

# 4. Para CI headless
# Configurar backend alternativo
export KEYRING_BACKEND=file  # Fallback para armazenamento em arquivo
```

---

### Problema: Deep Link Não Funciona no Linux

**Sintoma**: Clicar em deep link no navegador não abre o app.

**Causa**: Handler de scheme não registrado no sistema.

**Solução:**

```bash
# 1. Verificar registro atual
xdg-mime query default x-scheme-handler/aroeira

# Se vazio, registrar manualmente
# (O plugin deep-link registra automaticamente em debug)
update-desktop-database ~/.local/share/applications
xdg-mime default aroeira-handler.desktop x-scheme-handler/aroeira
```

---

### Problema: Callback Não Recebido (App Aberto)

**Sintoma**: Deep link abre app mas callback não é processado.

**Causa**: Evento `on_open_url` não registrado ou erro de parsing.

**Solução:**

```bash
# 1. Verificar logs do Tauri
grep "on_open_url" /tmp/aroeira.log

# Deve mostrar registro do evento

# 2. Verificar se plugin deep-link está configurado
# tauri.conf.json deve conter:
# "plugins": { "deep-link": { "desktop": { "schemes": ["aroeira"] } } } }
```

---

### Problema: Estado PKCE Não Encontrado

**Sintoma**: Erro "PKCE session not found" ao processar callback.

**Causa**: Sessão expirou ou já foi consumida (consume-once).

**Solução:**

```bash
# 1. Verificar se sessão existe no keyring
secret-tool lookup service aroeira-oauth-pkce account <STATE_HASH>

# Se vazio, sessão não existe mais
# (Usuário deve reiniciar fluxo OAuth)

# 2. Verificar logs de tempo de expiração
grep "expires_at" /tmp/aroeira.log

# Deve mostrar expiração esperada (+10 minutos)

# 3. Verificar implementação de consume-once
# Código deve deletar sessão imediatamente após uso
# (session_store.rs -> take_valid())
```

---

### Problema: Tokens Não Persistem

**Sintoma**: Após reinício do app, usuário precisa re-autenticar.

**Causa**: Tokens não estão sendo armazenados no keyring ou keyring está bloqueado.

**Solução:**

```bash
# 1. Verificar se tokens estão no keyring
secret-tool lookup service aroeira-tokens account user@example.com

# Se vazio, armazenamento falhou

# 2. Verificar se keyring está bloqueado
# (macOS) - Deve pedir senha ao acessar
security find-generic-password -s "aroeira-tokens" -a user@example.com

# 3. Verificar logs de armazenamento
grep "keyring.*save" /tmp/aroeira.log
grep "keyring.*get" /tmp/aroeira.log

# Deve mostrar sucesso/falha de operações
```

---

## Referências e Fontes

### Documentação Oficial

- **RFC 7636**: Proof Key for Code Exchange (PKCE) - https://tools.ietf.org/html/rfc7636
- **RFC 9700**: Best Current Practice for OAuth 2.0 Security - https://andrew-scott.co.uk/docs/rfc-pdf/rfc9700.pdf
- **RFC 6749**: OAuth 2.0 Authorization Framework - https://tools.ietf.org/html/rfc6749
- **OWASP WSTG**: Web Security Testing Guide - OAuth Weaknesses - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses
- **Auth0 Documentation**: State Parameters - https://auth0.com/docs/secure/attack-protection/state-parameters
- **Tauri Documentation**: Security Best Practices - https://tauri.app/security
- **Tauri Deep Link Plugin**: Documentation - https://v2.tauri.app/plugin/deep-linking

### Fontes de Segurança

- **Obsidian Security Blog**: OAuth Vulnerabilities - https://www.obsidiansecurity.com/blog/oauth-vulnerabilities-security-teams
- **APIsec Blog**: OAuth 2.0 Common Security Flaws - https://www.apisec.ai/blog/oauth-2-0-common-security-flaws
- **Hoop.dev Blog**: Session Replay Attacks in OAuth 2.0 - https://hoop.dev/blog/session-replay-attacks-in-oauth-2-0/
- **Apple Security**: Keychain Data Protection - https://support.apple.com/guide/security/
- **Microsoft Docs**: Windows Credential Manager - https://learn.microsoft.com/en-us/windows/win32/secapi/capi/credential-manager

### Implementação do PR #3

- **PR #3**: feat(auth): implement OAuth2 authentication with PKCE & deep linking (issue #2)
- **Arquivos Principais**:
  - `apps/desktop/src-tauri/src/commands/oauth.rs` - Comandos Tauri OAuth (896 linhas)
  - `apps/desktop/src-tauri/src/oauth/session_store.rs` - Store de sessões PKCE (373 linhas)
  - `apps/desktop/src-tauri/src/oauth_utils.rs` - Validações e utilitários (299 linhas)
  - `apps/desktop/src/lib/oauth.ts` - Utilities OAuth frontend (521 linhas)
  - `apps/desktop/src/routes/login/+page.svelte` - Página de login (352 linhas)
  - `libs/infra/tests/oauth_keyring_integration.rs` - 11 testes de integração
  - `apps/proxy/src/routes/oauth.rs` - BFF GitHub proxy
  - `apps/desktop/src-tauri/tauri.conf.json` - CSP e configuração de deep links

### Commit History (27 Commits)

1. Feat: Implementação base de OAuth com PKCE
2. Fix: Tauri argument name (url → callback_url)
3. Fix: Tratamento de erros duplicados
4. Fix: Timeout usando tokio::time::timeout
5. Fix: Validação percent-encoded de scheme
6. Fix: Limite de tamanho de token (8KB)
7. Fix: Remoção de código sensível de fingerprint
8. Fix: Validação de redirect URI no proxy
9. Fix: Proteção contra bypass de callback authority
10. 27. Testes, documentação e hardening de segurança

---

## Checklist Final de Verificação

### Pré-Deployment

- [ ] Protocolo `aroeira://` registrado no sistema (Linux/macOS/Windows)
- [ ] Build completo sem erros ou warnings
- [ ] Todos os 187 testes passando (incluindo 11 keyring)
- [ ] Keyring disponível e funcional
- [ ] CSP configurada corretamente
- [ ] Deep link handler registrado no Tauri

### Testes de Segurança PKCE

- [ ] Code verifier tem 43-128 caracteres (≥256 bits entropia)
- [ ] Code challenge usa método S256 (nunca plain)
- [ ] State parameter é UUID único por sessão
- [ ] Validação de state implementada (proteção CSRF)
- [ ] Sessões PKCE são single-use (consume-once)
- [ ] Sessões PKCE expiram após 10 minutos
- [ ] Redirect URI usa matching exato (no wildcards)
- [ ] Tokens têm limite de tamanho (8KB)

### Testes de Deep Linking

- [ ] Deep link handler registrado no sistema
- [ ] Callbacks são recebidos via on_open_url
- [ ] URLs de callback são validadas (scheme, host, path)
- [ ] Userinfo bloqueado em callbacks
- [ ] Obfuscação de esquema é detectada
- [ ] Callbacks duplicados são deduplicados

### Testes de Armazenamento Seguro

- [ ] PKCE code_verifier NUNCA em arquivos
- [ ] Tokens armazenados no keyring (não em arquivos)
- [ ] Tokens recuperáveis após reinício do app
- [ ] Tokens são criptografados em repouso
- [ ] Refresh tokens são rotacionados
- [ ] Tokens são limpos ao logout

### Testes de CSP e Headers

- [ ] CSP restringe scripts externos (script-src 'self')
- [ ] CSP permite only OAuth endpoints
- [ ] Headers de segurança configurados corretamente
- [ ] No vazamento de tokens em logs

---

_Documento gerado em: 2026-02-14_  
_Versão: 2.0 (Completo e Profundo)_  
_Baseado em: Pesquisa exaustiva de RFC 7636, RFC 9700, OWASP WSTG, documentação Tauri/Auth0, e implementação completa do PR #3 (27 commits)_
