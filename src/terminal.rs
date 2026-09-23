use std::{
    io::{self, IsTerminal},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use crossterm::{
    cursor::{Hide, Show},
    event::{
        self, DisableBracketedPaste, DisableFocusChange, EnableBracketedPaste, EnableFocusChange,
    },
    execute,
    style::ResetColor,
    terminal::{
        Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use ratatui::{Terminal, backend::CrosstermBackend, widgets};
use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGTERM},
    flag,
};

use crate::{app::App, ui};

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("Cannot enter terminal raw mode")?;
        let guard = Self;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            EnableBracketedPaste,
            EnableFocusChange,
            Hide
        )
        .context("Cannot initialize terminal")?;
        Ok(guard)
    }
}

fn restore() {
    let _ = execute!(
        io::stdout(),
        Clear(ClearType::All),
        DisableBracketedPaste,
        DisableFocusChange,
        Show,
        ResetColor,
        LeaveAlternateScreen
    );
    let _ = disable_raw_mode();
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}

pub fn run(mut app: App) -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("SimpleCrypt needs an interactive terminal. Run it directly, not through a pipe.");
    }

    let stopping = Arc::new(AtomicBool::new(false));
    let mut signal_ids = Vec::new();
    for signal in [SIGINT, SIGTERM, SIGHUP] {
        signal_ids.push(flag::register(signal, Arc::clone(&stopping))?);
    }
    let _guard = TerminalGuard::enter()?;
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {
        restore();
        eprintln!(
            "SimpleCrypt stopped unexpectedly. No secret-bearing panic details were printed."
        );
    }));

    let result = (|| -> Result<()> {
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        terminal.clear()?;
        loop {
            let now = Instant::now();
            if stopping.load(Ordering::Relaxed) {
                app.lock(false);
                app.should_quit = true;
            }
            app.tick(now);
            if app.clear_terminal {
                // Overwrite both reusable rendering buffers and the visible alternate screen.
                // Ratatui's internal allocations cannot promise forensic zeroization.
                for _ in 0..2 {
                    terminal.draw(|frame| frame.render_widget(widgets::Clear, frame.area()))?;
                }
                terminal.clear()?;
                app.clear_terminal = false;
            }
            if app.should_quit {
                break;
            }
            terminal.draw(|frame| ui::render(frame, &app))?;
            if event::poll(Duration::from_millis(200))? {
                app.event(event::read()?, Instant::now());
            }
        }
        Ok(())
    })();

    app.lock(false);
    std::panic::set_hook(original_hook);
    for id in signal_ids {
        signal_hook::low_level::unregister(id);
    }
    result
}
