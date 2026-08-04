use tracing_subscriber::fmt as tracing_fmt;
use time::macros::{ format_description as time_description, offset as time_offset };

pub fn logger_service(
    level: tracing::Level,
    with_ansi: bool,
    with_file: bool,
    with_line_number: bool
) -> tracing_appender::non_blocking::WorkerGuard
{
    // 自定义时间格式 +8时区
    let timer = tracing_fmt::time::OffsetTime::new(
        time_offset!(+8),
        time_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:6]")
    );
    // 无锁日志写入
    let (non_blocking, _guard) =
        tracing_appender::non_blocking(std::io::stdout());
    let log_subscriber = tracing_fmt::Subscriber::builder()
        .with_writer(non_blocking)
        .with_target(false)
        .with_timer(timer)
        .with_max_level(level)
        .with_ansi(with_ansi)
        .with_file(with_file)
        .with_line_number(with_line_number)
        .finish();
    tracing::subscriber::set_global_default(log_subscriber).unwrap();

    _guard
}
