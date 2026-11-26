// Embeds the application icon into the executable, so Explorer and the taskbar show it.
fn main() {
    println!("cargo:rerun-if-changed=../../icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../icon.ico");
        if let Err(e) = res.compile() {
            // Without a resource compiler the program still works, just with the default file icon.
            println!("cargo:warning=Anwendungsicon nicht eingebettet: {e}");
        }
    }
}