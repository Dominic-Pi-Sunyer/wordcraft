//! The web build has no sockets or threads: Share Mode is reported as unavailable.

use super::{LinkEvent, LinkNotice, Links, Role};

pub struct Link;

const NO: &str = "Share Mode isn't available in the browser yet";

impl Link {
    pub fn new(_local_only: bool) -> Self {
        Link
    }
    pub fn available(&self) -> bool {
        false
    }
    pub fn busy(&self) -> bool {
        false
    }
    pub fn role(&self) -> Role {
        Role::Offline
    }
    pub fn peers(&self) -> usize {
        0
    }
    pub fn local_id(&self) -> String {
        String::new()
    }
    pub fn begin_share(&mut self, _filename: String, _bytes: Vec<u8>) -> Result<(), String> {
        Err(NO.into())
    }
    pub fn begin_join(&mut self, _uri: String) -> Result<(), String> {
        Err(NO.into())
    }
    pub fn begin_stop(&mut self) -> Result<(), String> {
        Ok(())
    }
    pub fn poll_done(&mut self) -> Option<LinkNotice> {
        None
    }
    pub fn poll_event(&mut self) -> Option<LinkEvent> {
        None
    }
    pub fn broadcast<T: serde::Serialize>(&self, _m: &T) -> Result<(), String> {
        Err(NO.into())
    }
    #[allow(dead_code)]
    fn _links(_: Links) {}
}
