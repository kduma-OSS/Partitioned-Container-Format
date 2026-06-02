//! Minimal ANSI colouring with no external crate.
//!
//! When colour is disabled (`--no-color`, the `NO_COLOR` env var, or a
//! non-terminal stdout) every helper returns the text unchanged, so callers can
//! colour unconditionally and let the [`Palette`] decide.

/// A colour policy: either emits ANSI SGR codes or is the identity.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    enabled: bool,
}

impl Palette {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    fn wrap(self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn red(self, s: &str) -> String {
        self.wrap("31", s)
    }
    pub fn green(self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn yellow(self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn blue(self, s: &str) -> String {
        self.wrap("34", s)
    }
    pub fn magenta(self, s: &str) -> String {
        self.wrap("35", s)
    }
    pub fn cyan(self, s: &str) -> String {
        self.wrap("36", s)
    }
}
