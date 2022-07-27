use nom::{bytes::streaming::tag, IResult};

use crate::frame::FieldEncoding;

use super::Field;

#[derive(Debug)]
pub struct OwnedIFrame {
    pub buf: Vec<i64>,
}

#[derive(Debug)]
pub struct OwnedPFrame {
    pub buf: Vec<i64>,
}

#[derive(Debug)]
pub struct OwnedSFrame {
    pub buf: Vec<i64>,
}

#[derive(Debug)]
pub struct OwnedGFrame {
    pub buf: Vec<i64>,
}

#[derive(Debug)]
pub struct OwnedHFrame {
    pub buf: Vec<i64>,
}

fn parse_owned_frame_payload<'a: 'f, 'f, 'i: 'a>(
    field_encodings: &'a [FieldEncoding],
) -> impl Fn(&'i [u8]) -> IResult<&'i [u8], Vec<i64>> + 'f {
    move |input: &'i [u8]| {
        let mut input = input;
        let mut ret = Vec::with_capacity(field_encodings.len());

        for encoding in field_encodings {
            let (remaining_input, value) = encoding.parse(input)?;
            input = remaining_input;
            match value {
                Field::Signed(v) => ret.push(v as i64),
                Field::Unsigned(v) => ret.push(v as i64),
                Field::SignedTriple(values) => {
                    for v in values.iter().copied() {
                        ret.push(v as i64);
                    }
                }
                Field::SignedQuadruple(values) => {
                    for v in values.iter().copied() {
                        ret.push(v as i64);
                    }
                }
                Field::SignedOctuple(values, values_n) => {
                    for v in &values[..values_n] {
                        ret.push(*v as i64);
                    }
                }
            };
        }

        Ok((input, ret))
    }
}

pub(crate) fn parse_owned_iframe<'a: 'f, 'f, 'i: 'a>(
    field_encodings: &'a [FieldEncoding],
) -> impl Fn(&'i [u8]) -> IResult<&'i [u8], OwnedIFrame> + 'f {
    move |input: &'i [u8]| {
        let (input, _) = tag("I")(input)?;
        let (input, ret) = parse_owned_frame_payload(field_encodings)(input)?;
        Ok((input, OwnedIFrame { buf: ret }))
    }
}

pub(crate) fn parse_owned_pframe<'a: 'f, 'f, 'i: 'a>(
    field_encodings: &'a [FieldEncoding],
) -> impl Fn(&'i [u8]) -> IResult<&'i [u8], OwnedPFrame> + 'f {
    move |input: &'i [u8]| {
        let (input, _) = tag("P")(input)?;
        let (input, ret) = parse_owned_frame_payload(field_encodings)(input)?;
        Ok((input, OwnedPFrame { buf: ret }))
    }
}

pub(crate) fn parse_owned_sframe<'a: 'f, 'f, 'i: 'a>(
    field_encodings: &'a [FieldEncoding],
) -> impl Fn(&'i [u8]) -> IResult<&'i [u8], OwnedSFrame> + 'f {
    move |input: &'i [u8]| {
        let (input, _) = tag("S")(input)?;
        let (input, ret) = parse_owned_frame_payload(field_encodings)(input)?;
        Ok((input, OwnedSFrame { buf: ret }))
    }
}

pub(crate) fn parse_owned_gframe<'a: 'f, 'f, 'i: 'a>(
    field_encodings: &'a [FieldEncoding],
) -> impl Fn(&'i [u8]) -> IResult<&'i [u8], OwnedGFrame> + 'f {
    move |input: &'i [u8]| {
        let (input, _) = tag("G")(input)?;
        let (input, ret) = parse_owned_frame_payload(field_encodings)(input)?;
        Ok((input, OwnedGFrame { buf: ret }))
    }
}

pub(crate) fn parse_owned_hframe<'a: 'f, 'f, 'i: 'a>(
    field_encodings: &'a [FieldEncoding],
) -> impl Fn(&'i [u8]) -> IResult<&'i [u8], OwnedHFrame> + 'f {
    move |input: &'i [u8]| {
        let (input, _) = tag("H")(input)?;
        let (input, ret) = parse_owned_frame_payload(field_encodings)(input)?;
        Ok((input, OwnedHFrame { buf: ret }))
    }
}
