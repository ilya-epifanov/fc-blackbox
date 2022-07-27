use frame::event;
use itertools::Itertools;
use nom::FindSubstring;
use stream::{
    data::parse_next_frame,
    header::{parse_headers, Header},
    predictor::{LogProcessor, LogRecord},
};
use thiserror::Error;

extern crate itertools;

pub mod frame;
pub(crate) mod stream;

#[allow(unused)]
pub enum BlackboxRecord<'a> {
    Main(&'a [i64]),
    GNSS(&'a [i64]),
    Slow(Vec<i64>),
    Event(event::Frame),
    Garbage(usize),
}

#[derive(Copy, Clone)]
pub enum Strictness {
    Strict,
    Lenient,
}

pub struct BlackboxReader<'a> {
    strictness: Strictness,
    last_values: Vec<i64>,
    remaining_bytes: &'a [u8],
    original_length: usize,
    pub header: Header,
    processor: LogProcessor,
    pub last_loop_iteration: i64,
    pub last_time: i64,
    loop_iteration_field_ix: usize,
    time_field_ix: usize,
}

#[derive(Error, Debug)]
#[cfg_attr(test, derive(serde::Serialize))]
pub enum BlackboxReaderError {
    #[error("couldn't parse header")]
    ParseHeader,
    #[error("loopIteration or time I/P fields have not been found")]
    NoLoopIterationAndTime,
    #[error("log is truncated")]
    Incomplete,
}

impl<'a> BlackboxReader<'a> {
    pub fn new(
        bytes: &'a [u8],
        strictness: Strictness,
    ) -> Result<BlackboxReader<'a>, BlackboxReaderError> {
        let original_length = bytes.len();
        let (remaining_bytes, header) = parse_headers(bytes).map_err(|e| match e {
            nom::Err::Error(_e) => BlackboxReaderError::ParseHeader,
            nom::Err::Failure(_e) => BlackboxReaderError::ParseHeader,
            nom::Err::Incomplete(_) => BlackboxReaderError::Incomplete,
        })?;

        let loop_iteration_field_ix = header
            .ip_fields_in_order
            .iter()
            .find_position(|f| f.name == "loopIteration")
            .ok_or(BlackboxReaderError::NoLoopIterationAndTime)?
            .0;

        let time_field_ix = header
            .ip_fields_in_order
            .iter()
            .find_position(|f| f.name == "time")
            .ok_or(BlackboxReaderError::NoLoopIterationAndTime)?
            .0;

        let last_values = Vec::with_capacity(
            header
                .ip_fields_in_order
                .len()
                .max(header.s_fields_in_order.len())
                .max(header.g_fields_in_order.len()),
        );

        Ok(BlackboxReader {
            remaining_bytes,
            original_length,
            processor: LogProcessor::new(&header),
            last_values,
            loop_iteration_field_ix,
            time_field_ix,
            header,
            last_loop_iteration: 0,
            last_time: 0,
            strictness,
        })
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Result<BlackboxReader<'a>, BlackboxReaderError> {
        Self::new(bytes, Strictness::Lenient)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<BlackboxRecord> {
        loop {
            match parse_next_frame(&self.header, self.remaining_bytes) {
                Ok((remaining_bytes, frame)) => {
                    match remaining_bytes.first() {
                        Some(b'I') | Some(b'P') | Some(b'S') | Some(b'G') | Some(b'H') | Some(b'E') | None => {
                            // Next frame looks valid or it's an EOF
                        }
                        _ => {
                            // Skip the parsed frame
                            // Continue from the second byte of the parsed frame, because if it's invalid,
                            // we can't be sure what size it was and where next frame starts
                            self.remaining_bytes = &self.remaining_bytes[1..];
                            continue;
                        }
                    }
                    self.remaining_bytes = remaining_bytes;
                    if let Some(record) = self.processor.process_frame(frame) {
                        return Some(match record {
                            LogRecord::Main(values) => {
                                self.last_loop_iteration = values[self.loop_iteration_field_ix];
                                self.last_time = values[self.time_field_ix];
                                self.last_values.clear();
                                self.last_values.extend_from_slice(values);
                                BlackboxRecord::Main(&self.last_values)
                            }
                            LogRecord::GNSS(values) => {
                                self.last_values.clear();
                                self.last_values.extend_from_slice(values);
                                BlackboxRecord::GNSS(&self.last_values)
                            }
                            LogRecord::Slow(values) => BlackboxRecord::Slow(values),
                            LogRecord::Event(event) => BlackboxRecord::Event(event),
                        });
                    }
                }
                Err(e) => match e {
                    nom::Err::Error(e) => match self.strictness {
                        Strictness::Strict => return None,
                        Strictness::Lenient => {
                            if !e.input.is_empty() {
                                self.remaining_bytes = &e.input[1..];
                            }
                        }
                    },
                    nom::Err::Failure(e) => match self.strictness {
                        Strictness::Strict => return None,
                        Strictness::Lenient => {
                            if !e.input.is_empty() {
                                self.remaining_bytes = &e.input[1..];
                            }
                        }
                    },
                    nom::Err::Incomplete(_) => {
                        return None;
                    }
                },
            }
        }
    }

    pub fn bytes_read(&self) -> usize {
        self.original_length - self.remaining_bytes.len()
    }
}

pub struct MultiSegmentBlackboxReader<'a> {
    remaining_bytes: &'a [u8],
    strictness: Strictness,
}

impl<'a> MultiSegmentBlackboxReader<'a> {
    pub fn new(bytes: &'a [u8], strictness: Strictness) -> Self {
        Self {
            remaining_bytes: bytes,
            strictness,
        }
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Self::new(bytes, Strictness::Lenient)
    }

    pub fn successful_only(self) -> impl Iterator<Item = BlackboxReader<'a>> {
        self.filter_map(|r| r.ok())
    }
}

impl<'a> Iterator for MultiSegmentBlackboxReader<'a> {
    type Item = Result<BlackboxReader<'a>, BlackboxReaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        let pos = self
            .remaining_bytes
            .find_substring(&b"H Product:Blackbox"[..])?;
        self.remaining_bytes = &self.remaining_bytes[pos..];
        let reader = BlackboxReader::new(self.remaining_bytes, self.strictness);
        if let Ok(reader) = &reader {
            self.remaining_bytes = &self.remaining_bytes[reader.bytes_read()..];
        } else {
            self.remaining_bytes = &self.remaining_bytes[1..];
        }
        Some(reader)
    }
}

#[cfg(test)]
mod tests;
