use hzel::App;
use tracing::level_filters::LevelFilter;

#[tokio::main]
async fn main() {
    async_main().await;
}

async fn async_main() {
    tracing_subscriber::fmt()
        .with_file(true)
        .with_line_number(true)
        // .with_max_level(LevelFilter::TRACE)
        .init();
    let app = App::new("database_prod.db", String::from("files"))
        .await
        .unwrap();
    app.serve().await.unwrap()
}
