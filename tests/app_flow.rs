use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use simplecrypt::{
    app::{App, Mode, Pane},
    editor::{EditorControl, TextInput},
    model::FieldKind,
    storage::VaultFile,
    theme::Theme,
};
use tempfile::TempDir;

fn press(app: &mut App, code: KeyCode) {
    app.event(
        Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        Instant::now(),
    );
}

fn paste(app: &mut App, text: &str) {
    app.event(Event::Paste(text.to_owned()), Instant::now());
}

fn save(app: &mut App) {
    app.event(
        Event::Key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)),
        Instant::now(),
    );
}

fn new_app() -> (TempDir, App) {
    let dir = tempfile::tempdir().unwrap();
    let file = VaultFile::open(dir.path().join("vault.scv")).unwrap();
    let app = App::new(file, Theme::Mocha, Duration::from_secs(300)).unwrap();
    (dir, app)
}

fn create(app: &mut App) {
    assert_eq!(app.mode, Mode::Create);
    paste(app, "synthetic test master password");
    press(app, KeyCode::Enter);
    paste(app, "synthetic test master password");
    press(app, KeyCode::Enter);
    assert_eq!(app.mode, Mode::Browse, "{}", app.status);
}

#[test]
fn complete_record_search_edit_lock_and_restart_flow() {
    let (dir, mut app) = new_app();
    create(&mut app);
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode, Mode::Edit);
    app.editor.as_mut().unwrap().label.clear();
    for c in "hjkl/q猫".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    assert!(app.editor.as_ref().unwrap().label.value.as_str() == "hjkl/q猫");
    {
        let editor = app.editor.as_mut().unwrap();
        editor.label = TextInput::new("Personal Email 猫");
        let index = editor
            .record
            .fields
            .iter()
            .position(|field| field.kind == FieldKind::Password)
            .unwrap();
        editor.select_field(index as isize);
        editor.focus = EditorControl::Value;
    }
    paste(&mut app, "unique-synthetic-password-sentinel");
    save(&mut app);
    assert_eq!(app.mode, Mode::Browse, "{}", app.status);
    assert_eq!(app.records().len(), 1);
    let encrypted = std::fs::read(dir.path().join("vault.scv")).unwrap();
    for needle in ["Personal Email", "unique-synthetic-password-sentinel"] {
        assert!(
            !encrypted
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
        );
    }
    press(&mut app, KeyCode::Char('/'));
    paste(&mut app, "EMAIL");
    assert_eq!(app.filtered_indices().len(), 1);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('/'));
    paste(&mut app, "no-match");
    assert!(app.filtered_indices().is_empty());
    press(&mut app, KeyCode::Esc);
    assert!(app.query.value.as_str() == "EMAIL");
    assert_eq!(app.filtered_indices().len(), 1);
    app.pane = Pane::Fields;
    app.selected_field = app
        .current_record()
        .unwrap()
        .fields
        .iter()
        .position(|f| f.secret)
        .unwrap();
    press(&mut app, KeyCode::Char('r'));
    assert!(app.revealed());
    app.event(Event::FocusLost, Instant::now());
    assert!(!app.revealed());
    press(&mut app, KeyCode::Char('r'));
    app.tick(Instant::now() + Duration::from_secs(11));
    assert!(!app.revealed());
    press(&mut app, KeyCode::Char('e'));
    assert!(app.editor.is_some());
    app.tick(Instant::now() + Duration::from_secs(301));
    assert_eq!(app.mode, Mode::Locked);
    assert!(app.editor.is_none());
    assert!(app.session.is_none());
    assert!(app.query.value.is_empty());
    assert!(app.master.value.is_empty());
    paste(&mut app, "incorrect synthetic password");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode, Mode::Locked);
    assert!(app.is_error);
    assert!(app.master.value.is_empty());
    drop(app);

    let file = VaultFile::open(dir.path().join("vault.scv")).unwrap();
    let mut reopened = App::new(file, Theme::Latte, Duration::from_secs(300)).unwrap();
    assert_eq!(reopened.mode, Mode::Locked);
    paste(&mut reopened, "synthetic test master password");
    press(&mut reopened, KeyCode::Enter);
    assert_eq!(reopened.mode, Mode::Browse);
    assert_eq!(reopened.records().len(), 1);
    assert!(
        reopened.records()[0]
            .fields
            .iter()
            .any(|f| f.value == "unique-synthetic-password-sentinel")
    );
    press(&mut reopened, KeyCode::Char('d'));
    press(&mut reopened, KeyCode::Char('n'));
    assert_eq!(reopened.records().len(), 1);
    press(&mut reopened, KeyCode::Char('d'));
    press(&mut reopened, KeyCode::Char('y'));
    assert!(reopened.records().is_empty());
    press(&mut reopened, KeyCode::Char('q'));
    assert!(reopened.should_quit);
    assert!(reopened.session.is_none());
}

#[test]
fn setup_validation_and_mode_specific_quit() {
    let (_dir, mut app) = new_app();
    paste(&mut app, "short");
    press(&mut app, KeyCode::Enter);
    paste(&mut app, "short");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode, Mode::Create);
    assert!(app.is_error);
    press(&mut app, KeyCode::Esc);
    paste(&mut app, "sufficient length one");
    press(&mut app, KeyCode::Enter);
    paste(&mut app, "different length two");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode, Mode::Create);
    assert!(app.confirmation.value.is_empty());
    press(&mut app, KeyCode::Char('q'));
    assert!(!app.should_quit);
    assert!(app.confirmation.value.as_str() == "q");
}

#[test]
fn manual_lock_clears_all_modes() {
    let (_dir, mut app) = new_app();
    for mode in [
        Mode::Browse,
        Mode::Search,
        Mode::Edit,
        Mode::Templates,
        Mode::Delete,
        Mode::Help,
        Mode::Themes,
    ] {
        app.mode = mode;
        app.query = TextInput::new("sensitive label query");
        app.lock(false);
        assert_eq!(app.mode, Mode::Locked);
        assert!(app.query.value.is_empty());
    }
}
