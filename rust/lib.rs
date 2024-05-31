pub mod constants;
pub mod ctr;
pub mod error;
pub mod gcm;
pub mod random;
pub mod types;

use gcm::Aes256Gcm;
use random::{gen_key as gk, gen_nonce as gn};

use pyo3::prelude::*;

#[pyfunction]
fn gen_nonce() -> PyResult<Vec<u8>> {
    Ok(gn())
}

#[pyfunction]
fn gen_key() -> PyResult<Vec<u8>> {
    Ok(gk())
}

#[pyclass]
struct Gcm(Aes256Gcm);

#[pymodule]
#[pyo3(name = "_lib_name")]
fn pyrust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(gen_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(gen_key, m)?)?;
    m.add_class::<Gcm>()?;
    Ok(())
}
