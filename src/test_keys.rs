use std::time::Duration;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    crossterm::terminal::enable_raw_mode()?;
    println!("Press keys (q to quit)...");

    loop {
        if event::poll(Duration::from_millis(100))? {
            let ev = event::read()?;
            match &ev {
                Event::Key(k) => {
                    println!("\r\nKey: code={:?}, kind={:?}, modifiers={:?}", k.code, k.kind, k.modifiers);
                    if k.code == KeyCode::Char('q') {
                        break;
                    }
                }
                other => {
                    println!("\r\nOther event: {:?}", other);
                }
            }
        }
    }

    crossterm::terminal::disable_raw_mode()?;
    Ok(())
}
