

#[derive(Debug, PartialEq, Clone)]
pub enum SSDP {
    Discover(Option<String>),
    Notify(String),
    BTSearch(String),
}
