pub mod encoding;
pub mod engine;
pub mod external;
pub mod patterns;
pub mod preprocess;
pub mod result;
pub mod stage1;
pub mod stage2;

pub use engine::{ClassifyOptions, Engine, Sensitivity};
pub use result::{Match, Result, Severity, Verdict};
pub use stage1::CompiledPatterns;
