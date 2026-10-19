//! Serves files from a site root, following the original webxlib's behavior.

mod path;

pub use path::{PathError, PathPolicy, SafePath, sanitize};
