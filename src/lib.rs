use pyo3::prelude::*;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::aead::{Aead, KeyInit, Payload};
use aes_siv::Aes256SivAead;
use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Encrypt a batch of codes in one shot.
#[pyfunction]
fn encrypt_batch(codes: Vec<String>, key_hex: &str) -> PyResult<Vec<String>> {
    let aad = GenericArray::default();
    let key = hex::decode(key_hex)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key: {}", e)))?;
    let cipher = Aes256SivAead::new_from_slice(&key)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Bad key length: {}", e)))?;
    let mut out = Vec::with_capacity(codes.len());
    for code in codes {
        let payload = Payload { msg: &code.as_bytes(), aad: &aad };
        let ct = cipher.encrypt(&aad, payload)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Encrypt error: {}", e)))?;
        out.push(STANDARD.encode(ct));
    }
    Ok(out)
}

/// Decrypt a batch of ciphertexts.
#[pyfunction]
fn decrypt_batch(cts: Vec<String>, key_hex: &str) -> PyResult<Vec<String>> {
    let aad = GenericArray::default();
    let key = hex::decode(key_hex)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key: {}", e)))?;
    let cipher = Aes256SivAead::new_from_slice(&key)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Bad key length: {}", e)))?;
    let mut out = Vec::with_capacity(cts.len());
    for b64 in cts {
        let ct = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Bad base64: {}", e)))?;
        let payload = Payload { msg: &ct, aad: &aad };
        let pt = cipher.decrypt(&aad, payload)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Decrypt error: {}", e)))?;
        out.push(String::from_utf8(pt)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyUnicodeDecodeError, _>(format!("UTF8 error: {}", e)))?);
    }
    Ok(out)
}

#[pymodule]
fn aes_siv_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_batch, m)?)?;
    Ok(())
}
