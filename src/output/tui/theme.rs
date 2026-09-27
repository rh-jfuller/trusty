use ratatui::style::Color;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    #[default]
    Dark,
    Light,
}

impl ThemeMode {
    pub fn toggle(&mut self) {
        *self = match self {
            Self::Dark => Self::Light,
            Self::Light => Self::Dark,
        };
    }

    pub(crate) fn palette(self) -> Palette {
        match self {
            Self::Dark => Palette {
                background: Color::Rgb(24, 19, 34),
                surface: Color::Rgb(35, 31, 46),
                surface_alt: Color::Rgb(47, 43, 59),
                foreground: Color::Rgb(235, 239, 234),
                muted: Color::Rgb(170, 165, 181),
                border: Color::Rgb(91, 82, 107),
                accent: Color::Rgb(33, 145, 140),
                accent_bright: Color::Rgb(53, 183, 121),
                selection: Color::Rgb(48, 77, 78),
                selection_foreground: Color::Rgb(241, 246, 237),
                status_background: Color::Rgb(36, 32, 46),
                status_foreground: Color::Rgb(232, 237, 231),
                badge_background: Color::Rgb(33, 145, 140),
                badge_foreground: Color::Rgb(14, 25, 29),
                log: Color::Rgb(164, 185, 172),
            },
            Self::Light => Palette {
                background: Color::Rgb(245, 247, 242),
                surface: Color::Rgb(255, 255, 252),
                surface_alt: Color::Rgb(231, 239, 233),
                foreground: Color::Rgb(35, 45, 46),
                muted: Color::Rgb(87, 108, 102),
                border: Color::Rgb(174, 192, 185),
                accent: Color::Rgb(39, 119, 137),
                accent_bright: Color::Rgb(30, 142, 112),
                selection: Color::Rgb(211, 233, 223),
                selection_foreground: Color::Rgb(29, 75, 67),
                status_background: Color::Rgb(229, 237, 231),
                status_foreground: Color::Rgb(39, 58, 56),
                badge_background: Color::Rgb(39, 119, 137),
                badge_foreground: Color::Rgb(255, 255, 255),
                log: Color::Rgb(81, 117, 103),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ThemeMode;

    #[test]
    fn dark_and_light_modes_have_distinct_palettes() {
        assert_ne!(
            ThemeMode::Dark.palette().background,
            ThemeMode::Light.palette().background
        );
    }

    #[test]
    fn theme_mode_toggles_between_dark_and_light() {
        let mut theme = ThemeMode::Dark;
        theme.toggle();
        assert_eq!(theme, ThemeMode::Light);
        theme.toggle();
        assert_eq!(theme, ThemeMode::Dark);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Palette {
    pub background: Color,
    pub surface: Color,
    pub surface_alt: Color,
    pub foreground: Color,
    pub muted: Color,
    pub border: Color,
    pub accent: Color,
    pub accent_bright: Color,
    pub selection: Color,
    pub selection_foreground: Color,
    pub status_background: Color,
    pub status_foreground: Color,
    pub badge_background: Color,
    pub badge_foreground: Color,
    pub log: Color,
}
