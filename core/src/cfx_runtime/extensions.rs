use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use std::collections::HashMap;
use std::sync::Mutex;

// ── Registry ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
enum ExtensionKind {
    /// Shell out to a binary (subfinder, httpx, nuclei, etc.)
    Cli { binary: String },
    /// Talk to a Crossfyre extension daemon over TCP JSON protocol (mach, voyage)
    Daemon { port: u16 },
}

static REGISTRY: Mutex<Option<HashMap<String, ExtensionKind>>> = Mutex::new(None);

/// Populate the default extension registry.
pub fn inject_defaults() {
    let mut map = HashMap::new();

    // Crossfyre extension daemons (TCP JSON protocol)
    map.insert("mach".to_string(), ExtensionKind::Daemon { port: 4441 });
    map.insert("voyage".to_string(), ExtensionKind::Daemon { port: 4442 });

    // Common CLI recon tools (shell out to binary)
    for name in [
        "subfinder", "httpx", "nuclei", "naabu", "amass", "ffuf", "dnsx",
        "katana", "gau", "waybackurls",
    ] {
        map.insert(name.to_string(), ExtensionKind::Cli { binary: name.to_string() });
    }

    *REGISTRY.lock().unwrap() = Some(map);
}

pub fn clear() {
    *REGISTRY.lock().unwrap() = None;
}

// ── Python types ─────────────────────────────────────────────────────

/// Wraps a CLI tool.  `ext.run(["-d", "example.com"])` shells out.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct Extension {
    name: String,
    binary: String,
}

#[pymethods]
impl Extension {
    fn run(&self, args: Vec<String>) -> PyResult<String> {
        let binary = self.binary.clone();
        let output = std::process::Command::new(&binary)
            .args(&args)
            .output()
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "Failed to run '{}': {}", binary, e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "'{}' exited with {}: {}", binary, output.status, stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    fn __repr__(&self) -> String {
        format!("Extension(name='{}', binary='{}')", self.name, self.binary)
    }
}

/// Wraps a Crossfyre extension daemon (mach, voyage).
/// Communicates over TCP with newline-delimited JSON.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct DaemonExtension {
    name: String,
    port: u16,
}

#[pymethods]
impl DaemonExtension {
    /// Send a raw JSON request to the daemon and return the response.
    ///
    ///   mach = extensions.get("mach")
    ///   mach.send({"operation": "probe", "url": "https://example.com", ...})
    fn send(&self, py: Python<'_>, request: Bound<'_, PyDict>) -> PyResult<Py<PyAny>> {
        let value: serde_json::Value = pythonize::depythonize(&request)?;
        let port = self.port;

        // Synchronous TCP - we're inside spawn_blocking so this is fine
        let response = std::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .and_then(|mut stream| {
                use std::io::{BufRead, Write};
                stream.set_nodelay(true)?;
                let mut req_str = serde_json::to_string(&value).unwrap();
                req_str.push('\n');
                stream.write_all(req_str.as_bytes())?;
                stream.flush()?;

                let mut reader = std::io::BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                Ok(line)
            })
            .map_err(|e| {
                pyo3::exceptions::PyConnectionError::new_err(format!(
                    "{} daemon not reachable on port {}: {}",
                    self.name, port, e
                ))
            })?;

        let parsed: serde_json::Value = serde_json::from_str(response.trim())
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Invalid JSON from {} daemon: {}", self.name, e
                ))
            })?;

        pythonize::pythonize(py, &parsed)
            .map(|b| b.unbind())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Convenience: run a scan operation (stream mode).
    /// Returns a list of all result events.
    ///
    ///   results = mach.scan({
    ///       "endpoint": "https://example.com/::FUZZ::",
    ///       "wordlist": "/path/to/wordlist.txt",
    ///       "method": "GET",
    ///       "tasks": 10
    ///   })
    fn scan(&self, py: Python<'_>, params: Bound<'_, PyDict>) -> PyResult<Py<PyAny>> {
        let mut value: serde_json::Value = pythonize::depythonize(&params)?;
        value["operation"] = serde_json::json!("scan");
        value["response"] = serde_json::json!("stream");

        let port = self.port;
        let name = self.name.clone();

        let events = std::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .and_then(|mut stream| {
                use std::io::{BufRead, Write};
                stream.set_nodelay(true)?;
                let mut req_str = serde_json::to_string(&value).unwrap();
                req_str.push('\n');
                stream.write_all(req_str.as_bytes())?;
                stream.flush()?;

                let reader = std::io::BufReader::new(&stream);
                let mut results = Vec::new();

                for line in reader.lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                        let is_done = event["type"].as_str() == Some("done");
                        results.push(event);
                        if is_done {
                            break;
                        }
                    }
                }

                Ok(results)
            })
            .map_err(|e| {
                pyo3::exceptions::PyConnectionError::new_err(format!(
                    "{} daemon not reachable on port {}: {}",
                    name, port, e
                ))
            })?;

        pythonize::pythonize(py, &events)
            .map(|b| b.unbind())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Convenience: single-URL probe (instant mode).
    ///
    ///   result = mach.probe("https://example.com/admin", method="GET")
    #[pyo3(signature = (url, method="GET", success_codes=None, volatility=0))]
    fn probe(
        &self,
        py: Python<'_>,
        url: &str,
        method: &str,
        success_codes: Option<Vec<u16>>,
        volatility: u32,
    ) -> PyResult<Py<PyAny>> {
        let codes = success_codes.unwrap_or_else(|| vec![200, 201, 301, 302, 403]);
        let payload = serde_json::json!({
            "operation": "probe",
            "response": "instant",
            "url": url,
            "method": method,
            "success_codes": codes,
            "volatility": volatility,
        });

        let port = self.port;
        let name = self.name.clone();

        let response = std::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .and_then(|mut stream| {
                use std::io::{BufRead, Write};
                stream.set_nodelay(true)?;
                let mut req_str = serde_json::to_string(&payload).unwrap();
                req_str.push('\n');
                stream.write_all(req_str.as_bytes())?;
                stream.flush()?;

                let mut reader = std::io::BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                Ok(line)
            })
            .map_err(|e| {
                pyo3::exceptions::PyConnectionError::new_err(format!(
                    "{} daemon not reachable on port {}: {}",
                    name, port, e
                ))
            })?;

        let parsed: serde_json::Value = serde_json::from_str(response.trim())
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Invalid JSON from {} daemon: {}", name, e
                ))
            })?;

        pythonize::pythonize(py, &parsed)
            .map(|b| b.unbind())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn port(&self) -> u16 {
        self.port
    }

    fn __repr__(&self) -> String {
        format!("DaemonExtension(name='{}', port={})", self.name, self.port)
    }
}

// ── Module‑level functions ───────────────────────────────────────────

/// Look up an extension by name. Returns Extension or DaemonExtension.
#[pyfunction]
fn get(py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
    let guard = REGISTRY.lock().unwrap();
    let map = guard.as_ref().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err("Extension registry not initialized")
    })?;
    let kind = map.get(name).ok_or_else(|| {
        pyo3::exceptions::PyKeyError::new_err(format!("Unknown extension: '{}'", name))
    })?;
    match kind {
        ExtensionKind::Cli { binary } => {
            Ok(Extension { name: name.to_string(), binary: binary.clone() }.into_pyobject(py)?.into_any().unbind())
        }
        ExtensionKind::Daemon { port } => {
            Ok(DaemonExtension { name: name.to_string(), port: *port }.into_pyobject(py)?.into_any().unbind())
        }
    }
}

/// Register a custom CLI extension (name → binary path).
#[pyfunction]
fn register(name: &str, binary_path: &str) -> PyResult<()> {
    let mut guard = REGISTRY.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(name.to_string(), ExtensionKind::Cli { binary: binary_path.to_string() });
    Ok(())
}

/// Register a daemon extension (name → port).
#[pyfunction]
fn register_daemon(name: &str, port: u16) -> PyResult<()> {
    let mut guard = REGISTRY.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(name.to_string(), ExtensionKind::Daemon { port });
    Ok(())
}

/// List all registered extension names.
#[pyfunction]
fn list_all() -> PyResult<Vec<String>> {
    let guard = REGISTRY.lock().unwrap();
    match guard.as_ref() {
        Some(map) => Ok(map.keys().cloned().collect()),
        None => Ok(vec![]),
    }
}

pub fn make_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "extensions")?;
    m.add_function(wrap_pyfunction!(get, &m)?)?;
    m.add_function(wrap_pyfunction!(register, &m)?)?;
    m.add_function(wrap_pyfunction!(register_daemon, &m)?)?;
    m.add_function(wrap_pyfunction!(list_all, &m)?)?;
    m.add_class::<Extension>()?;
    m.add_class::<DaemonExtension>()?;
    Ok(m)
}
