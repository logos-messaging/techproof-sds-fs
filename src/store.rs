//! An untrusted archive of opaque frames, keyed by transport hash. It never sees a message id.

use std::collections::HashMap;

use crate::member::Frame;

#[derive(Debug, Default)]
pub struct Store {
    frames: Vec<Frame>,
    index: HashMap<Vec<u8>, usize>,
}

impl Store {
    pub fn put(&mut self, frame: Frame) {
        self.index.insert(frame.hint(), self.frames.len());
        self.frames.push(frame);
    }

    pub fn fetch(&self, hint: &[u8]) -> Option<&Frame> {
        self.index.get(hint).map(|&i| &self.frames[i])
    }

    pub fn latest(&self) -> Option<&Frame> {
        self.frames.last()
    }

    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }
}
