//! The gist side: find or create the private `tern-sync` gist, read and write its files.
//! Blocking HTTP (ureq with the system TLS); callers run it off the UI thread.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const API: &str = "https://api.github.com";
const DESCRIPTION: &str = "tern-sync";
const META: &str = "tern-meta.json";
const VAULT: &str = "vault.age.b64";
const DATA: &str = "data.age.b64";
const KEYCHAIN_SERVICE: &str = "tern";
const KEYCHAIN_ACCOUNT: &str = "github-token";

#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("no GitHub token: paste one in Settings → Sync, or sign in with `gh auth login`")]
    NoToken,
    #[error("GitHub refused the token (it needs the gist scope)")]
    Unauthorized,
    #[error("GitHub: {0}")]
    Http(String),
    #[error("the tern-sync gist is not in the expected format: {0}")]
    Format(String),
    #[error("Keychain: {0}")]
    Keychain(String),
}

impl From<ureq::Error> for GithubError {
    fn from(e: ureq::Error) -> Self {
        match e {
            ureq::Error::StatusCode(401 | 403) => GithubError::Unauthorized,
            other => GithubError::Http(other.to_string()),
        }
    }
}

/// Where the token came from, for the Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    Keychain,
    GhCli,
}

pub(crate) trait Keychain: Send + Sync {
    fn get(&self) -> Result<String, keyring::Error>;
    fn set(&self, token: &str) -> Result<(), keyring::Error>;
    fn delete(&self) -> Result<(), keyring::Error>;
    fn clone_box(&self) -> Box<dyn Keychain>;
}

impl Clone for Box<dyn Keychain> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct OsKeychain;

impl Keychain for OsKeychain {
    fn get(&self) -> Result<String, keyring::Error> {
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?.get_password()
    }

    fn set(&self, token: &str) -> Result<(), keyring::Error> {
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?.set_password(token)
    }

    fn delete(&self) -> Result<(), keyring::Error> {
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?.delete_credential()
    }

    fn clone_box(&self) -> Box<dyn Keychain> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GhOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(crate) trait GhCli: Send + Sync {
    fn run(&self, args: &[&str]) -> Result<GhOutput, std::io::Error>;
    fn clone_box(&self) -> Box<dyn GhCli>;
}

impl Clone for Box<dyn GhCli> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct SystemGh;

#[allow(clippy::disallowed_methods)]
impl GhCli for SystemGh {
    fn run(&self, args: &[&str]) -> Result<GhOutput, std::io::Error> {
        let out = std::process::Command::new("gh").args(args).output()?;
        Ok(GhOutput {
            success: out.status.success(),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }

    fn clone_box(&self) -> Box<dyn GhCli> {
        Box::new(self.clone())
    }
}

pub(crate) trait GithubHttp: std::fmt::Debug + Send + Sync {
    fn get(&self, token: &str, path: &str) -> Result<Value, GithubError>;
    fn send(&self, token: &str, method: &str, path: &str, body: Value) -> Result<(), GithubError>;
    fn clone_box(&self) -> Box<dyn GithubHttp>;
}

impl Clone for Box<dyn GithubHttp> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UreqHttp {
    agent: ureq::Agent,
}

impl UreqHttp {
    pub(crate) fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .provider(ureq::tls::TlsProvider::NativeTls)
                    // The macOS trust store, not a bundled root list.
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .http_status_as_error(true)
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl GithubHttp for UreqHttp {
    fn get(&self, token: &str, path: &str) -> Result<Value, GithubError> {
        let mut res = self
            .agent
            .get(format!("{API}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "tern")
            .call()?;
        res.body_mut()
            .read_json::<Value>()
            .map_err(|e| GithubError::Http(e.to_string()))
    }

    fn send(&self, token: &str, method: &str, path: &str, body: Value) -> Result<(), GithubError> {
        let builder = match method {
            "POST" => self.agent.post(format!("{API}{path}")),
            _ => self.agent.patch(format!("{API}{path}")),
        };
        builder
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "tern")
            .send_json(body)?;
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn GithubHttp> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
thread_local! {
    static TEST_KEYCHAIN: std::cell::RefCell<Option<Box<dyn Keychain>>> = const { std::cell::RefCell::new(None) };
    static TEST_GH: std::cell::RefCell<Option<Box<dyn GhCli>>> = const { std::cell::RefCell::new(None) };
    static TEST_HTTP: std::cell::RefCell<Option<Box<dyn GithubHttp>>> = const { std::cell::RefCell::new(None) };
}

pub(crate) fn current_keychain() -> Box<dyn Keychain> {
    #[cfg(test)]
    {
        if let Some(kc) = TEST_KEYCHAIN.with(|k| k.borrow().as_ref().map(|b| b.clone_box())) {
            return kc;
        }
    }
    Box::new(OsKeychain)
}

pub(crate) fn current_gh() -> Box<dyn GhCli> {
    #[cfg(test)]
    {
        if let Some(gh) = TEST_GH.with(|g| g.borrow().as_ref().map(|b| b.clone_box())) {
            return gh;
        }
    }
    Box::new(SystemGh)
}

pub(crate) fn current_http() -> Box<dyn GithubHttp> {
    #[cfg(test)]
    {
        if let Some(h) = TEST_HTTP.with(|h| h.borrow().as_ref().map(|b| b.clone_box())) {
            return h;
        }
    }
    Box::new(UreqHttp::new())
}

#[cfg(test)]
pub(crate) struct KeychainGuard;
#[cfg(test)]
impl Drop for KeychainGuard {
    fn drop(&mut self) {
        TEST_KEYCHAIN.with(|k| *k.borrow_mut() = None);
    }
}
#[cfg(test)]
pub(crate) fn set_test_keychain(kc: Box<dyn Keychain>) -> KeychainGuard {
    TEST_KEYCHAIN.with(|k| *k.borrow_mut() = Some(kc));
    KeychainGuard
}

#[cfg(test)]
pub(crate) struct GhGuard;
#[cfg(test)]
impl Drop for GhGuard {
    fn drop(&mut self) {
        TEST_GH.with(|g| *g.borrow_mut() = None);
    }
}
#[cfg(test)]
pub(crate) fn set_test_gh(gh: Box<dyn GhCli>) -> GhGuard {
    TEST_GH.with(|g| *g.borrow_mut() = Some(gh));
    GhGuard
}

#[cfg(test)]
pub(crate) struct HttpGuard;
#[cfg(test)]
impl Drop for HttpGuard {
    fn drop(&mut self) {
        TEST_HTTP.with(|h| *h.borrow_mut() = None);
    }
}
#[cfg(test)]
pub(crate) fn set_test_http(http: Box<dyn GithubHttp>) -> HttpGuard {
    TEST_HTTP.with(|h| *h.borrow_mut() = Some(http));
    HttpGuard
}

/// The token from the Keychain, else from `gh auth token`.
///
/// # Errors
/// [`GithubError::NoToken`] when neither has one.
pub fn token() -> Result<(String, TokenSource), GithubError> {
    token_with(&*current_keychain(), &*current_gh())
}

pub(crate) fn token_with(
    keychain: &dyn Keychain,
    gh: &dyn GhCli,
) -> Result<(String, TokenSource), GithubError> {
    if let Ok(t) = keychain.get()
        && !t.trim().is_empty()
    {
        return Ok((t, TokenSource::Keychain));
    }
    gh_token_with(gh)
        .map(|t| (t, TokenSource::GhCli))
        .ok_or(GithubError::NoToken)
}

// Runs on a background thread, never on an executor, so the blocking call is fine here.
#[allow(clippy::disallowed_methods, dead_code)]
pub(crate) fn gh_token() -> Option<String> {
    gh_token_with(&*current_gh())
}

pub(crate) fn gh_token_with(gh: &dyn GhCli) -> Option<String> {
    let out = gh.run(&["auth", "token"]).ok()?;
    let t = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (out.success && !t.is_empty()).then_some(t)
}

/// Stores a pasted token in the macOS Keychain.
///
/// # Errors
/// [`GithubError::Keychain`] when the Keychain refuses.
pub fn save_token(token: &str) -> Result<(), GithubError> {
    save_token_with(&*current_keychain(), token)
}

pub(crate) fn save_token_with(keychain: &dyn Keychain, token: &str) -> Result<(), GithubError> {
    keychain
        .set(token.trim())
        .map_err(|e| GithubError::Keychain(e.to_string()))
}

/// Removes tern's token from the Keychain; `gh` is left alone.
///
/// # Errors
/// [`GithubError::Keychain`] when the Keychain refuses.
pub fn forget_token() -> Result<(), GithubError> {
    forget_token_with(&*current_keychain())
}

pub(crate) fn forget_token_with(keychain: &dyn Keychain) -> Result<(), GithubError> {
    match keychain.delete() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(GithubError::Keychain(e.to_string())),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Meta {
    version: u32,
    hash: String,
    /// Seconds since the epoch, for display.
    updated_at: u64,
    device: String,
}

/// What the gist holds, decoded.
#[derive(Debug, Clone)]
pub struct RemoteBundle {
    pub hash: String,
    pub updated_at: u64,
    pub device: String,
    pub vault: Vec<u8>,
    pub sealed: Vec<u8>,
}

#[derive(Debug)]
pub struct Gist {
    http: Box<dyn GithubHttp>,
    token: String,
}

#[derive(Deserialize)]
struct GistSummary {
    id: String,
    description: Option<String>,
}

impl Gist {
    pub fn new(token: String) -> Self {
        Self::with_http(current_http(), token)
    }

    pub(crate) fn with_http(http: Box<dyn GithubHttp>, token: String) -> Self {
        Self { http, token }
    }

    fn get(&self, path: &str) -> Result<Value, GithubError> {
        self.http.get(&self.token, path)
    }

    fn find(&self) -> Result<Option<String>, GithubError> {
        for page in 1..=10 {
            let list: Vec<GistSummary> =
                serde_json::from_value(self.get(&format!("/gists?per_page=100&page={page}"))?)
                    .map_err(|e| GithubError::Format(e.to_string()))?;
            if let Some(g) = list
                .iter()
                .find(|g| g.description.as_deref() == Some(DESCRIPTION))
            {
                return Ok(Some(g.id.clone()));
            }
            if list.len() < 100 {
                break;
            }
        }
        Ok(None)
    }

    /// The gist's bundle, or `None` when there is no `tern-sync` gist yet.
    ///
    /// # Errors
    /// Network, auth or format errors.
    pub fn fetch(&self) -> Result<Option<RemoteBundle>, GithubError> {
        let Some(id) = self.find()? else {
            return Ok(None);
        };
        let gist = self.get(&format!("/gists/{id}"))?;
        let file = |name: &str| -> Result<String, GithubError> {
            gist["files"][name]["content"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| GithubError::Format(format!("{name} missing")))
        };
        let meta: Meta =
            serde_json::from_str(&file(META)?).map_err(|e| GithubError::Format(e.to_string()))?;
        let decode = |name: &str| -> Result<Vec<u8>, GithubError> {
            B64.decode(file(name)?.trim())
                .map_err(|e| GithubError::Format(format!("{name}: {e}")))
        };
        Ok(Some(RemoteBundle {
            hash: meta.hash,
            updated_at: meta.updated_at,
            device: meta.device,
            vault: decode(VAULT)?,
            sealed: decode(DATA)?,
        }))
    }

    /// Writes the bundle, creating the private gist on first use.
    ///
    /// # Errors
    /// Network or auth errors.
    pub fn push(
        &self,
        hash: &str,
        device: &str,
        vault: &[u8],
        sealed: &[u8],
    ) -> Result<(), GithubError> {
        let meta = Meta {
            version: 1,
            hash: hash.to_owned(),
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            device: device.to_owned(),
        };
        let files = json!({
            META: { "content": serde_json::to_string_pretty(&meta).map_err(|e| GithubError::Format(e.to_string()))? },
            VAULT: { "content": B64.encode(vault) },
            DATA: { "content": B64.encode(sealed) },
        });
        match self.find()? {
            Some(id) => self.http.send(
                &self.token,
                "PATCH",
                &format!("/gists/{id}"),
                json!({ "files": files }),
            ),
            None => self.http.send(
                &self.token,
                "POST",
                "/gists",
                json!({ "description": DESCRIPTION, "public": false, "files": files }),
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::disallowed_methods)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default, Clone)]
    struct FakeKeychain {
        token: Arc<Mutex<Option<String>>>,
        fail: Arc<AtomicBool>,
    }

    impl Keychain for FakeKeychain {
        fn get(&self) -> Result<String, keyring::Error> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(keyring::Error::PlatformFailure(Box::new(
                    std::io::Error::other("keychain failure"),
                )));
            }
            self.token
                .lock()
                .unwrap()
                .clone()
                .ok_or(keyring::Error::NoEntry)
        }

        fn set(&self, token: &str) -> Result<(), keyring::Error> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(keyring::Error::PlatformFailure(Box::new(
                    std::io::Error::other("keychain failure"),
                )));
            }
            *self.token.lock().unwrap() = Some(token.to_owned());
            Ok(())
        }

        fn delete(&self) -> Result<(), keyring::Error> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(keyring::Error::PlatformFailure(Box::new(
                    std::io::Error::other("keychain failure"),
                )));
            }
            let mut t = self.token.lock().unwrap();
            if t.is_some() {
                *t = None;
                Ok(())
            } else {
                Err(keyring::Error::NoEntry)
            }
        }

        fn clone_box(&self) -> Box<dyn Keychain> {
            Box::new(self.clone())
        }
    }

    #[derive(Debug, Default, Clone)]
    struct FakeGh {
        responses: Arc<Mutex<HashMap<String, Result<GhOutput, String>>>>,
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl GhCli for FakeGh {
        fn run(&self, args: &[&str]) -> Result<GhOutput, std::io::Error> {
            let key = args.join(" ");
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|s| (*s).to_owned()).collect());
            if let Some(res) = self.responses.lock().unwrap().get(&key) {
                match res {
                    Ok(out) => Ok(out.clone()),
                    Err(e) => Err(std::io::Error::other(e.clone())),
                }
            } else {
                Ok(GhOutput {
                    success: false,
                    stdout: Vec::new(),
                    stderr: b"command failed".to_vec(),
                })
            }
        }

        fn clone_box(&self) -> Box<dyn GhCli> {
            Box::new(self.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct FakeHttp {
        get_responses: Arc<Mutex<HashMap<String, Result<Value, String>>>>,
        send_calls: Arc<Mutex<Vec<(String, String, Value)>>>,
        send_result: Arc<Mutex<Result<(), String>>>,
    }

    impl Default for FakeHttp {
        fn default() -> Self {
            Self {
                get_responses: Arc::new(Mutex::new(HashMap::new())),
                send_calls: Arc::new(Mutex::new(Vec::new())),
                send_result: Arc::new(Mutex::new(Ok(()))),
            }
        }
    }

    impl GithubHttp for FakeHttp {
        fn get(&self, token: &str, path: &str) -> Result<Value, GithubError> {
            assert_eq!(token, "test-token");
            if let Some(res) = self.get_responses.lock().unwrap().get(path) {
                match res {
                    Ok(val) => Ok(val.clone()),
                    Err(err) => Err(GithubError::Http(err.clone())),
                }
            } else {
                Err(GithubError::Http(format!("unexpected GET {path}")))
            }
        }

        fn send(
            &self,
            token: &str,
            method: &str,
            path: &str,
            body: Value,
        ) -> Result<(), GithubError> {
            assert_eq!(token, "test-token");
            self.send_calls
                .lock()
                .unwrap()
                .push((method.to_owned(), path.to_owned(), body));
            self.send_result
                .lock()
                .unwrap()
                .clone()
                .map_err(GithubError::Http)
        }

        fn clone_box(&self) -> Box<dyn GithubHttp> {
            Box::new(self.clone())
        }
    }

    #[test]
    fn token_from_keychain() {
        let kc = FakeKeychain::default();
        *kc.token.lock().unwrap() = Some("kc-secret".to_owned());
        let _g1 = set_test_keychain(Box::new(kc));

        let gh = FakeGh::default();
        let _g2 = set_test_gh(Box::new(gh.clone()));

        let (t, src) = token().unwrap();
        assert_eq!(t, "kc-secret");
        assert_eq!(src, TokenSource::Keychain);
        assert!(gh.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn token_from_keychain_whitespace_falls_back_to_gh() {
        let kc = FakeKeychain::default();
        *kc.token.lock().unwrap() = Some("   \t  \n".to_owned());
        let _g1 = set_test_keychain(Box::new(kc));

        let gh = FakeGh::default();
        gh.responses.lock().unwrap().insert(
            "auth token".into(),
            Ok(GhOutput {
                success: true,
                stdout: b"gh-secret\n".to_vec(),
                stderr: Vec::new(),
            }),
        );
        let _g2 = set_test_gh(Box::new(gh));

        let (t, src) = token().unwrap();
        assert_eq!(t, "gh-secret");
        assert_eq!(src, TokenSource::GhCli);
    }

    #[test]
    fn token_from_gh_cli_when_keychain_empty() {
        let kc = FakeKeychain::default();
        let _g1 = set_test_keychain(Box::new(kc));

        let gh = FakeGh::default();
        gh.responses.lock().unwrap().insert(
            "auth token".into(),
            Ok(GhOutput {
                success: true,
                stdout: b"gh-token-123\n".to_vec(),
                stderr: Vec::new(),
            }),
        );
        let _g2 = set_test_gh(Box::new(gh));

        let (t, src) = token().unwrap();
        assert_eq!(t, "gh-token-123");
        assert_eq!(src, TokenSource::GhCli);
        assert_eq!(gh_token().unwrap(), "gh-token-123");
    }

    #[test]
    fn token_no_token_when_both_empty() {
        let kc = FakeKeychain::default();
        let _g1 = set_test_keychain(Box::new(kc));

        let gh = FakeGh::default();
        gh.responses.lock().unwrap().insert(
            "auth token".into(),
            Ok(GhOutput {
                success: false,
                stdout: Vec::new(),
                stderr: b"not logged in".to_vec(),
            }),
        );
        let _g2 = set_test_gh(Box::new(gh));

        assert!(matches!(token().unwrap_err(), GithubError::NoToken));
        assert!(gh_token().is_none());
    }

    #[test]
    fn token_no_token_when_gh_whitespace_only() {
        let kc = FakeKeychain::default();
        let _g1 = set_test_keychain(Box::new(kc));

        let gh = FakeGh::default();
        gh.responses.lock().unwrap().insert(
            "auth token".into(),
            Ok(GhOutput {
                success: true,
                stdout: b"   \n".to_vec(),
                stderr: Vec::new(),
            }),
        );
        let _g2 = set_test_gh(Box::new(gh));

        assert!(matches!(token().unwrap_err(), GithubError::NoToken));
    }

    #[test]
    fn save_token_stores_trimmed_value() {
        let kc = FakeKeychain::default();
        let _g = set_test_keychain(Box::new(kc.clone()));

        save_token("  my-new-token \n").unwrap();
        assert_eq!(kc.token.lock().unwrap().as_deref(), Some("my-new-token"));
    }

    #[test]
    fn save_token_error_reported() {
        let kc = FakeKeychain::default();
        kc.fail.store(true, Ordering::SeqCst);
        let _g = set_test_keychain(Box::new(kc));

        let err = save_token("token").unwrap_err();
        assert!(matches!(err, GithubError::Keychain(_)));
    }

    #[test]
    fn forget_token_removes_token_and_is_idempotent() {
        let kc = FakeKeychain::default();
        *kc.token.lock().unwrap() = Some("old-token".to_owned());
        let _g = set_test_keychain(Box::new(kc.clone()));

        forget_token().unwrap();
        assert!(kc.token.lock().unwrap().is_none());

        // Second call when already deleted succeeds without error.
        forget_token().unwrap();
    }

    #[test]
    fn forget_token_error_reported() {
        let kc = FakeKeychain::default();
        kc.fail.store(true, Ordering::SeqCst);
        let _g = set_test_keychain(Box::new(kc));

        let err = forget_token().unwrap_err();
        assert!(matches!(err, GithubError::Keychain(_)));
    }

    #[test]
    fn gist_find_matches_exact_description() {
        let http = FakeHttp::default();
        http.get_responses.lock().unwrap().insert(
            "/gists?per_page=100&page=1".into(),
            Ok(json!([
                { "id": "other-gist", "description": "not-ours" },
                { "id": "null-desc", "description": null },
                { "id": "found-id", "description": "tern-sync" }
            ])),
        );
        let _g = set_test_http(Box::new(http));

        let gist = Gist::new("test-token".into());
        assert_eq!(gist.find().unwrap(), Some("found-id".into()));
    }

    #[test]
    fn gist_find_paginates_until_found() {
        let http = FakeHttp::default();
        let page1: Vec<Value> = (0..100)
            .map(|i| json!({ "id": format!("id-{i}"), "description": "other" }))
            .collect();
        http.get_responses
            .lock()
            .unwrap()
            .insert("/gists?per_page=100&page=1".into(), Ok(Value::Array(page1)));
        http.get_responses.lock().unwrap().insert(
            "/gists?per_page=100&page=2".into(),
            Ok(json!([
                { "id": "target-on-page-2", "description": "tern-sync" }
            ])),
        );
        let _g = set_test_http(Box::new(http));

        let gist = Gist::new("test-token".into());
        assert_eq!(gist.find().unwrap(), Some("target-on-page-2".into()));
    }

    #[test]
    fn gist_find_stops_when_page_less_than_100() {
        let http = FakeHttp::default();
        let page1: Vec<Value> = (0..42)
            .map(|i| json!({ "id": format!("id-{i}"), "description": "other" }))
            .collect();
        http.get_responses
            .lock()
            .unwrap()
            .insert("/gists?per_page=100&page=1".into(), Ok(Value::Array(page1)));
        let _g = set_test_http(Box::new(http));

        let gist = Gist::new("test-token".into());
        assert_eq!(gist.find().unwrap(), None);
    }

    #[test]
    fn gist_fetch_returns_none_when_no_gist() {
        let http = FakeHttp::default();
        http.get_responses
            .lock()
            .unwrap()
            .insert("/gists?per_page=100&page=1".into(), Ok(json!([])));
        let _g = set_test_http(Box::new(http));

        let gist = Gist::new("test-token".into());
        assert!(gist.fetch().unwrap().is_none());
    }

    #[test]
    fn gist_fetch_decodes_valid_bundle() {
        let http = FakeHttp::default();
        http.get_responses.lock().unwrap().insert(
            "/gists?per_page=100&page=1".into(),
            Ok(json!([{ "id": "g123", "description": "tern-sync" }])),
        );
        http.get_responses.lock().unwrap().insert(
            "/gists/g123".into(),
            Ok(json!({
                "files": {
                    "tern-meta.json": {
                        "content": "{\n  \"version\": 1,\n  \"hash\": \"h789\",\n  \"updated_at\": 1000,\n  \"device\": \"test-mac\"\n}"
                    },
                    "vault.age.b64": {
                        "content": "dmF1bHQtYnl0ZXM=\n"
                    },
                    "data.age.b64": {
                        "content": "c2VhbGVkLWJ5dGVz\n"
                    }
                }
            })),
        );
        let _g = set_test_http(Box::new(http));

        let gist = Gist::new("test-token".into());
        let bundle = gist.fetch().unwrap().unwrap();
        assert_eq!(bundle.hash, "h789");
        assert_eq!(bundle.updated_at, 1000);
        assert_eq!(bundle.device, "test-mac");
        assert_eq!(bundle.vault, b"vault-bytes");
        assert_eq!(bundle.sealed, b"sealed-bytes");
    }

    #[test]
    fn gist_fetch_fails_when_file_missing_or_corrupt() {
        let http = FakeHttp::default();
        http.get_responses.lock().unwrap().insert(
            "/gists?per_page=100&page=1".into(),
            Ok(json!([{ "id": "g1", "description": "tern-sync" }])),
        );
        // Missing tern-meta.json
        http.get_responses
            .lock()
            .unwrap()
            .insert("/gists/g1".into(), Ok(json!({ "files": {} })));
        let _g = set_test_http(Box::new(http.clone()));

        let gist = Gist::new("test-token".into());
        let err = gist.fetch().unwrap_err();
        assert!(
            matches!(err, GithubError::Format(ref msg) if msg.contains("tern-meta.json missing"))
        );

        // Invalid base64 in vault.age.b64
        http.get_responses.lock().unwrap().insert(
            "/gists/g1".into(),
            Ok(json!({
                "files": {
                    "tern-meta.json": {
                        "content": "{\"version\": 1, \"hash\": \"h\", \"updated_at\": 0, \"device\": \"d\"}"
                    },
                    "vault.age.b64": {
                        "content": "not-valid-base64!!!"
                    },
                    "data.age.b64": {
                        "content": "AAA="
                    }
                }
            })),
        );
        let err2 = gist.fetch().unwrap_err();
        assert!(matches!(err2, GithubError::Format(ref msg) if msg.contains("vault.age.b64")));
    }

    #[test]
    fn gist_push_creates_new_gist_when_none_exists() {
        let http = FakeHttp::default();
        http.get_responses
            .lock()
            .unwrap()
            .insert("/gists?per_page=100&page=1".into(), Ok(json!([])));
        let _g = set_test_http(Box::new(http.clone()));

        let gist = Gist::new("test-token".into());
        gist.push("my-hash", "device-x", b"v-bytes", b"s-bytes")
            .unwrap();

        let calls = http.send_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (method, path, body) = &calls[0];
        assert_eq!(method, "POST");
        assert_eq!(path, "/gists");
        assert_eq!(body["description"], "tern-sync");
        assert_eq!(body["public"], false);

        let files = &body["files"];
        assert_eq!(files[VAULT]["content"], B64.encode(b"v-bytes"));
        assert_eq!(files[DATA]["content"], B64.encode(b"s-bytes"));

        let meta_str = files[META]["content"].as_str().unwrap();
        assert!(meta_str.contains("\"hash\": \"my-hash\""));
        assert!(meta_str.contains("\"device\": \"device-x\""));
    }

    #[test]
    fn gist_push_patches_existing_gist() {
        let http = FakeHttp::default();
        http.get_responses.lock().unwrap().insert(
            "/gists?per_page=100&page=1".into(),
            Ok(json!([{ "id": "existing-456", "description": "tern-sync" }])),
        );
        let _g = set_test_http(Box::new(http.clone()));

        let gist = Gist::new("test-token".into());
        gist.push("hash-patched", "device-y", b"v2", b"s2").unwrap();

        let calls = http.send_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (method, path, body) = &calls[0];
        assert_eq!(method, "PATCH");
        assert_eq!(path, "/gists/existing-456");
        assert!(body.get("description").is_none());
        assert!(body["files"].is_object());
    }
}
