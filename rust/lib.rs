pub mod constants;
pub mod ctr;
pub mod error;
pub mod gcm;
pub mod random;
pub mod types;

use pyo3::prelude::*;

#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

#[pymodule]
#[pyo3(name = "_lib_name")]
fn pyrust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    Ok(())
}
