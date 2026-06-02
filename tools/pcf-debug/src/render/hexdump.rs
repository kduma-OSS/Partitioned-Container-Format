//! A classic 16-column hexdump with absolute file offsets.

use super::color::Palette;

/// Hexdump `data`, labelling each row with its absolute offset (`base` is the
/// file offset of `data[0]`). At most `max` bytes are shown; the remainder is
/// summarised. Returns the formatted block (no trailing newline).
pub fn dump(data: &[u8], base: u64, max: usize, pal: Palette) -> String {
    let shown = data.len().min(max);
    let mut out = String::new();
    for (row, chunk) in data[..shown].chunks(16).enumerate() {
        let off = base + (row * 16) as u64;
        let mut hex = String::new();
        let mut ascii = String::new();
        for (i, &b) in chunk.iter().enumerate() {
            if i == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        // Pad a short final row so the ASCII column lines up.
        let pad = 16 - chunk.len();
        for i in 0..pad {
            if chunk.len() + i == 8 {
                hex.push(' ');
            }
            hex.push_str("   ");
        }
        out.push_str(&format!(
            "{}  {hex} |{ascii}|\n",
            pal.dim(&format!("{off:08x}"))
        ));
    }
    if data.len() > shown {
        out.push_str(&pal.dim(&format!(
            "  ... {} more byte(s) (use --max-bytes to show)\n",
            data.len() - shown
        )));
    }
    // Trim the trailing newline.
    if out.ends_with('\n') {
        out.pop();
    }
    out
}
