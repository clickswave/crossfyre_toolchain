// Only referenced from voyage/src/tui.rs, which is NOT in the module tree
// (main.rs declares client_tui, not tui), so nothing compiles this today.
#[allow(dead_code)]
pub fn full() {
    let banner = "
 -----------------------[ V O Y A G E ]----------------------
 |                                                          |
 |                Thank you for choosing us.                |
 |  Wishing you exciting discoveries and successful hunts!  |
 |                                                          |
 |                         voyage.vg                        |
 ------------------------------------------------------------
";
    println!("{banner}");
}
