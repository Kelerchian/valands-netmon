use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self, ErrorKind},
    time::Instant,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tui::Terminal;
use tui::{backend::CrosstermBackend, widgets::canvas::Canvas};
use tui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Color,
    widgets::canvas::{Map, MapResolution},
};
use tui::{
    style::Style,
    text::Span,
    widgets::{Block, Borders},
};

pub enum UIState {
    CounterExample(u8),
}

pub fn run_ui() -> Result<(), std::io::Error> {
    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let tick_rate = Duration::from_millis(50);
    let mut last_tick = Instant::now();
    let mut ui_state: Arc<Mutex<UIState>> = Arc::new(Mutex::new(UIState::CounterExample(0)));

    terminal.clear()?;
    loop {
        terminal.draw(|f| {
            let ui_state = match ui_state.lock() {
                Ok(mut ui_state) => {
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .margin(1)
                        .constraints(
                            [
                                Constraint::Length(3),
                                Constraint::Percentage(80),
                                Constraint::Percentage(10),
                            ]
                            .as_ref(),
                        )
                        .split(f.size());
                    let block = Block::default()
                        .title(match *ui_state {
                            UIState::CounterExample(x) => format!("{}", x),
                        })
                        .borders(Borders::ALL);
                    let canvas = Canvas::default().block(Block::default()).paint(|ctx| {
                        ctx.draw(&Map {
                            color: Color::White,
                            resolution: MapResolution::High,
                        });
                        ctx.print(1_f64, 1_f64, "you are here", Color::Yellow);
                    });
                    let area = block.inner(f.size());
                    f.render_widget(block, area);
                    f.render_widget(canvas, chunks[0]);
                    let block = Block::default().title("Block 2").borders(Borders::ALL);
                    f.render_widget(block, chunks[1]);
                }
                Err(_) => {}
            };
        })?;

        let polled_event_option = if event::poll(
            tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or(Duration::from_millis(0)),
        )? {
            Some(event::read()?)
        } else {
            None
        };

        if last_tick.elapsed() < tick_rate {
            std::thread::sleep(
                tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or(Duration::from_millis(0)),
            );
            last_tick = Instant::now()
        }

        if let Some(event) = polled_event_option {
            match event {
                CEvent::Key(key) => match key.code {
                    KeyCode::F(1) => {}
                    KeyCode::F(2) => match ui_state.lock() {
                        Ok(mut ui_state) => match *ui_state {
                            UIState::CounterExample(x) => {
                                *ui_state = UIState::CounterExample(x + 1);
                            }
                        },
                        Err(_) => return Err(std::io::Error::from(ErrorKind::Other)),
                    },
                    _ => {}
                },
                CEvent::Mouse(_) => {}
                CEvent::Resize(_, _) => {}
            }
        }
    }
    Ok(())
}
