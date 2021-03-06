use nom::{
    bytes::streaming::tag,
    error::{ErrorKind, ParseError},
    number::{
        complete::be_u8,
        streaming::{le_f32, le_u8},
    },
    IResult,
};

use super::{take_varint, zigzag_decode};

#[derive(Debug)]
pub enum Frame {
    SyncBeep(SyncBeep),
    FlightMode(FlightMode),
    IMUFailure(IMUFailure),
    Disarm(Disarm),
    InFlightAdjustment(InFlightAdjustment),
    LoggingResume(LoggingResume),
    EndOfLog,
}

#[allow(unused)]
#[derive(Debug)]
pub struct SyncBeep {
    time: u32,
}

#[derive(Debug)]
#[allow(unused)]
pub struct FlightMode {
    flags: u32,
    old_flags: u32,
}

#[allow(unused)]
#[derive(Debug)]
pub struct Disarm {
    reason: u32,
}

#[derive(Debug)]
pub enum Adjustment {
    Float(f32),
    Int(i32),
}

#[allow(unused)]
#[derive(Debug)]
pub struct InFlightAdjustment {
    function: u8,
    adjustment: Adjustment,
}

#[allow(unused)]
#[derive(Debug)]
pub struct LoggingResume {
    iteration: u32,
    time: u32,
}

#[allow(unused)]
#[derive(Debug)]
pub struct IMUFailure {
    error_code: u32,
}

pub(crate) fn parse_event(input: &[u8]) -> IResult<&[u8], Frame> {
    let (input, _) = tag("E")(input)?;
    let (input, event_code) = le_u8(input)?;

    let (input, event_frame) = match event_code {
        0 => {
            let (input, time) = take_varint(input)?;
            (input, Frame::SyncBeep(SyncBeep { time }))
        }
        13 => {
            let (input, function) = be_u8(input)?;

            if function & 0b1000_0000 != 0 {
                let function = function & 0b0111_1111;
                let (input, value) = le_f32(input)?;
                (
                    input,
                    Frame::InFlightAdjustment(InFlightAdjustment {
                        function,
                        adjustment: Adjustment::Float(value),
                    }),
                )
            } else {
                let (input, value) = take_varint(input)?;
                let value = zigzag_decode(value);
                (
                    input,
                    Frame::InFlightAdjustment(InFlightAdjustment {
                        function,
                        adjustment: Adjustment::Int(value),
                    }),
                )
            }
        }
        14 => {
            let (input, iteration) = take_varint(input)?;
            let (input, time) = take_varint(input)?;

            (
                input,
                Frame::LoggingResume(LoggingResume { iteration, time }),
            )
        }
        15 => {
            let (input, reason) = take_varint(input)?;
            (input, Frame::Disarm(Disarm { reason }))
        }
        30 => {
            let (input, flags) = take_varint(input)?;
            let (input, old_flags) = take_varint(input)?;

            (input, Frame::FlightMode(FlightMode { flags, old_flags }))
        }
        40 => {
            let (input, error_code) = take_varint(input)?;
            (input, Frame::IMUFailure(IMUFailure { error_code }))
        }
        255 => {
            let (input, _) = tag("End of log\0")(input)?;
            (input, Frame::EndOfLog)
        }
        _ => {
            return Err(nom::Err::Failure(nom::error::Error::from_error_kind(
                input,
                ErrorKind::Tag,
            )))
        }
    };

    Ok((input, event_frame))
}
