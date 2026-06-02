//! The physical model of a PCF file: a defensive walk, a byte-layout map, and
//! the diagnostics found along the way.

pub mod diag;
pub mod layout;
pub mod walk;

pub use diag::{DiagKind, Diagnostic, Severity};
pub use layout::{build, LayoutMap, Region, RegionKind};
pub use walk::{algo_name, walk, BlockView, EntryView, Walk};
