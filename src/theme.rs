//! Official Catppuccin colors, kept in one place for every UI surface.
use clap::ValueEnum;
use ratatui::style::Color;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Theme {
    #[default]
    Mocha,
    Macchiato,
    Frappe,
    Latte,
}

impl Theme {
    pub const ALL: [Self; 4] = [Self::Mocha, Self::Macchiato, Self::Frappe, Self::Latte];

    pub fn label(&self) -> &str {
        match self {
            Self::Mocha => "Mocha",
            Self::Macchiato => "Macchiato",
            Self::Frappe => "Frappe",
            Self::Latte => "Latte",
        }
    }

    pub fn palette(self) -> Palette {
        // https://catppuccin.com/palette/ — order matches Palette::from_hex.
        Palette::from_hex(match self {
            Self::Mocha => [
                0xf5e0dc, 0xf2cdcd, 0xf5c2e7, 0xcba6f7, 0xf38ba8, 0xeba0ac, 0xfab387, 0xf9e2af,
                0xa6e3a1, 0x94e2d5, 0x89dceb, 0x74c7ec, 0x89b4fa, 0xb4befe, 0xcdd6f4, 0xbac2de,
                0xa6adc8, 0x9399b2, 0x7f849c, 0x6c7086, 0x585b70, 0x45475a, 0x313244, 0x1e1e2e,
                0x181825, 0x11111b,
            ],
            Self::Macchiato => [
                0xf4dbd6, 0xf0c6c6, 0xf5bde6, 0xc6a0f6, 0xed8796, 0xee99a0, 0xf5a97f, 0xeed49f,
                0xa6da95, 0x8bd5ca, 0x91d7e3, 0x7dc4e4, 0x8aadf4, 0xb7bdf8, 0xcad3f5, 0xb8c0e0,
                0xa5adcb, 0x939ab7, 0x8087a2, 0x6e738d, 0x5b6078, 0x494d64, 0x363a4f, 0x24273a,
                0x1e2030, 0x181926,
            ],
            Self::Frappe => [
                0xf2d5cf, 0xeebebe, 0xf4b8e4, 0xca9ee6, 0xe78284, 0xea999c, 0xef9f76, 0xe5c890,
                0xa6d189, 0x81c8be, 0x99d1db, 0x85c1dc, 0x8caaee, 0xbabbf1, 0xc6d0f5, 0xb5bfe2,
                0xa5adce, 0x949cbb, 0x838ba7, 0x737994, 0x626880, 0x51576d, 0x414559, 0x303446,
                0x292c3c, 0x232634,
            ],
            Self::Latte => [
                0xdc8a78, 0xdd7878, 0xea76cb, 0x8839ef, 0xd20f39, 0xe64553, 0xfe640b, 0xdf8e1d,
                0x40a02b, 0x179299, 0x04a5e5, 0x209fb5, 0x1e66f5, 0x7287fd, 0x4c4f69, 0x5c5f77,
                0x6c6f85, 0x7c7f93, 0x8c8fa1, 0x9ca0b0, 0xacb0be, 0xbcc0cc, 0xccd0da, 0xeff1f5,
                0xe6e9ef, 0xdce0e8,
            ],
        })
    }
}

/// Complete official palette; unused accents are intentionally available to callers.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub rosewater: Color,
    pub flamingo: Color,
    pub pink: Color,
    pub mauve: Color,
    pub red: Color,
    pub maroon: Color,
    pub peach: Color,
    pub yellow: Color,
    pub green: Color,
    pub teal: Color,
    pub sky: Color,
    pub sapphire: Color,
    pub blue: Color,
    pub lavender: Color,
    pub text: Color,
    pub subtext1: Color,
    pub subtext0: Color,
    pub overlay2: Color,
    pub overlay1: Color,
    pub overlay0: Color,
    pub surface2: Color,
    pub surface1: Color,
    pub surface0: Color,
    pub base: Color,
    pub mantle: Color,
    pub crust: Color,
}

impl Palette {
    fn from_hex(values: [u32; 26]) -> Self {
        let c = values.map(|v| Color::Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8));
        Self {
            rosewater: c[0],
            flamingo: c[1],
            pink: c[2],
            mauve: c[3],
            red: c[4],
            maroon: c[5],
            peach: c[6],
            yellow: c[7],
            green: c[8],
            teal: c[9],
            sky: c[10],
            sapphire: c[11],
            blue: c[12],
            lavender: c[13],
            text: c[14],
            subtext1: c[15],
            subtext0: c[16],
            overlay2: c[17],
            overlay1: c[18],
            overlay0: c[19],
            surface2: c[20],
            surface1: c[21],
            surface0: c[22],
            base: c[23],
            mantle: c[24],
            crust: c[25],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn themes_have_stable_cli_names_and_official_base_colors() {
        assert_eq!(Theme::default(), Theme::Mocha);
        for (theme, name, base) in [
            (Theme::Mocha, "mocha", Color::Rgb(30, 30, 46)),
            (Theme::Macchiato, "macchiato", Color::Rgb(36, 39, 58)),
            (Theme::Frappe, "frappe", Color::Rgb(48, 52, 70)),
            (Theme::Latte, "latte", Color::Rgb(239, 241, 245)),
        ] {
            assert_eq!(Theme::from_str(name, false).unwrap(), theme);
            assert_eq!(theme.palette().base, base);
            assert!(!theme.label().is_empty());
        }
    }
}
