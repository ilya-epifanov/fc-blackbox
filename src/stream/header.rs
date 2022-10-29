use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    f32::consts::PI,
};

use itertools::izip;
use nom::{
    error::{ErrorKind, ParseError},
    multi::fold_many0,
    IResult,
};
use num_rational::Ratio;

use super::predictor::{AnyIPredictor, AnyPPredictor, FieldPredictor};
use crate::{
    frame::{
        header::{parse_header, Frame},
        FieldEncoding, RawFieldEncoding,
    },
    stream::predictor::AnyGPredictor,
};

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Header {
    product: String,
    data_version: String,
    firmware_type: Option<String>,
    firmware_revision: Option<String>,
    firmware_date: Option<String>,
    board_information: Option<String>,
    log_start_datetime: Option<String>,
    craft_name: Option<String>,
    i_interval: i16,
    p_interval: Ratio<u16>,
    p_ratio: u16,
    pub gyro_scale: f32,
    pub raw_gyro_scale: f32,
    pub loop_time: u32,

    pub other_headers: HashMap<String, String>,

    pub ip_fields: HashMap<String, IPField>,
    pub s_fields: HashMap<String, SlowField>,
    pub g_fields: HashMap<String, GNSSField>,
    pub h_fields: HashMap<String, GNSSHomeField>,

    pub ip_fields_in_order: Vec<IPField>,
    pub s_fields_in_order: Vec<SlowField>,
    pub g_fields_in_order: Vec<GNSSField>,

    pub(crate) i_field_encodings: Vec<FieldEncoding>,
    pub(crate) i_field_predictors: Vec<AnyIPredictor>,
    pub(crate) p_field_encodings: Vec<FieldEncoding>,
    pub(crate) p_field_predictors: Vec<AnyPPredictor>,
    pub(crate) s_field_encodings: Vec<FieldEncoding>,
    pub(crate) g_field_encodings: Vec<FieldEncoding>,
    pub(crate) g_field_predictors: Vec<AnyGPredictor>,
    pub(crate) h_field_encodings: Vec<FieldEncoding>,
    pub(crate) h_field_predictors: Vec<AnyPPredictor>,
}

#[derive(Debug)]
pub enum HeaderBuildError {
    MissingHeader(&'static str),
    // InvalidHeader(&'static str),
}

impl AsRef<str> for HeaderBuildError {
    fn as_ref(&self) -> &str {
        match self {
            Self::MissingHeader(r) => r,
        }
    }
}

impl TryFrom<HeaderBuilder> for Header {
    type Error = HeaderBuildError;

    fn try_from(builder: HeaderBuilder) -> Result<Self, Self::Error> {
        let product = builder
            .product
            .ok_or(HeaderBuildError::MissingHeader("Product"))?;
        let data_version = builder
            .data_version
            .ok_or(HeaderBuildError::MissingHeader("Data version"))?;
        let i_interval = builder
            .i_interval
            .ok_or(HeaderBuildError::MissingHeader("I interval"))?;
        let p_interval = builder
            .p_interval
            .ok_or(HeaderBuildError::MissingHeader("P interval"))?;
        let p_ratio = builder.p_ratio.unwrap_or(1);
        let gyro_scale = builder
            .gyro_scale
            .ok_or(HeaderBuildError::MissingHeader("gyro_scale"))?;
        let loop_time = builder
            .loop_time
            .ok_or(HeaderBuildError::MissingHeader("looptime"))?;

        let mut ip_fields = HashMap::with_capacity(builder.i_field_names.len());
        let mut ip_fields_in_order = Vec::with_capacity(builder.i_field_names.len());
        let mut i_field_encodings = Vec::with_capacity(builder.i_field_names.len());
        let mut p_field_encodings = Vec::with_capacity(builder.i_field_names.len());
        let mut i_field_predictors = Vec::with_capacity(builder.i_field_names.len());
        let mut p_field_predictors = Vec::with_capacity(builder.i_field_names.len());

        fn add_encoding(encodings: &mut Vec<FieldEncoding>, new_encoding: RawFieldEncoding) {
            let new_encoding = match new_encoding {
                RawFieldEncoding::Tag8_8SVB => {
                    if let Some(FieldEncoding::Tag8_8SVB(n_fields)) = encodings.last_mut() {
                        if *n_fields != 8 {
                            *n_fields += 1;
                            return;
                        }
                    }
                    FieldEncoding::Tag8_8SVB(1)
                }
                RawFieldEncoding::Tag2_3S32 => {
                    if let Some(FieldEncoding::Tag2_3S32(n_fields)) = encodings.last_mut() {
                        if *n_fields != 3 {
                            *n_fields += 1;
                            return;
                        }
                    }
                    FieldEncoding::Tag2_3S32(1)
                }
                RawFieldEncoding::Tag2_3SVariable => {
                    if let Some(FieldEncoding::Tag2_3SVariable(n_fields)) = encodings.last_mut() {
                        if *n_fields != 3 {
                            *n_fields += 1;
                            return;
                        }
                    }
                    FieldEncoding::Tag2_3SVariable(1)
                }
                RawFieldEncoding::Tag8_4S16 => {
                    if let Some(FieldEncoding::Tag8_4S16(n_fields)) = encodings.last_mut() {
                        if *n_fields != 4 {
                            *n_fields += 1;
                            return;
                        }
                    }
                    FieldEncoding::Tag8_4S16(1)
                }
                RawFieldEncoding::Null => FieldEncoding::Null,
                RawFieldEncoding::Negative14BitVB => FieldEncoding::Negative14BitVB,
                RawFieldEncoding::SignedVB => FieldEncoding::SignedVB,
                RawFieldEncoding::UnsignedVB => FieldEncoding::UnsignedVB,
            };
            encodings.push(new_encoding);
        }

        for (ix, (name, signed, i_encoding, p_encoding)) in izip!(
            builder.i_field_names,
            builder.i_field_signedness,
            builder.i_field_encoding,
            builder.p_field_encoding
        )
        .enumerate()
        {
            add_encoding(&mut i_field_encodings, i_encoding);
            add_encoding(&mut p_field_encodings, p_encoding);

            let field = IPField {
                name: name.clone(),
                ix,
                signed,
            };
            ip_fields.insert(name, field.clone());
            ip_fields_in_order.push(field);
        }

        for (ix, i_predictor) in builder.i_field_predictors.iter().copied().enumerate() {
            i_field_predictors.push(AnyIPredictor::new(
                i_predictor,
                &builder.other_headers,
                &ip_fields,
                ix,
            ));
        }

        for (ix, p_predictor) in builder.p_field_predictors.iter().copied().enumerate() {
            p_field_predictors.push(AnyPPredictor::new(p_predictor, p_interval, ix));
        }

        let mut s_fields = HashMap::with_capacity(builder.s_field_names.len());
        let mut s_field_encodings = Vec::with_capacity(builder.s_field_names.len());
        let mut s_fields_in_order = Vec::with_capacity(builder.s_field_names.len());
        for (ix, (name, signed, encoding, predictor)) in izip!(
            builder.s_field_names,
            builder.s_field_signedness,
            builder.s_field_encoding,
            builder.s_field_predictors
        )
        .enumerate()
        {
            add_encoding(&mut s_field_encodings, encoding);
            let field = SlowField {
                name,
                ix,
                predictor,
                signed,
            };
            s_fields.insert(field.name.clone(), field.clone());
            s_fields_in_order.push(field);
        }

        let mut g_fields = HashMap::with_capacity(builder.g_field_names.len());
        let mut g_field_encodings = Vec::with_capacity(builder.g_field_names.len());
        let mut g_field_predictors = Vec::with_capacity(builder.g_field_names.len());
        let mut g_fields_in_order = Vec::with_capacity(builder.g_field_names.len());

        for (ix, (name, signed, encoding, predictor)) in izip!(
            builder.g_field_names,
            builder.g_field_signedness,
            builder.g_field_encoding,
            builder.g_field_predictors
        )
        .enumerate()
        {
            add_encoding(&mut g_field_encodings, encoding);
            let mut name_chars = name.chars();
            let sub_ix = if name_chars.any(|c| c == '[') {
                name_chars
                    .next()
                    .and_then(|c| c.to_digit(10))
                    .unwrap_or(0u32) as usize
            } else {
                0
            };

            g_field_predictors.push(AnyGPredictor::new(predictor, ix, sub_ix, &ip_fields));

            let field = GNSSField {
                name,
                ix,
                predictor,
                signed,
            };
            g_fields.insert(field.name.clone(), field.clone());
            g_fields_in_order.push(field);
        }

        let mut h_fields = HashMap::with_capacity(builder.h_field_names.len());
        let mut h_field_encodings = Vec::with_capacity(builder.h_field_names.len());
        let mut h_field_predictors = Vec::with_capacity(builder.h_field_names.len());
        for (ix, (name, signed, encoding, predictor)) in izip!(
            builder.h_field_names,
            builder.h_field_signedness,
            builder.h_field_encoding,
            builder.h_field_predictors
        )
        .enumerate()
        {
            add_encoding(&mut h_field_encodings, encoding);
            assert_eq!(predictor, FieldPredictor::None);
            h_field_predictors.push(AnyPPredictor::none(ix));

            h_fields.insert(
                name.clone(),
                GNSSHomeField {
                    name,
                    ix,
                    predictor,
                    signed,
                },
            );
        }

        Ok(Header {
            product,
            data_version,
            firmware_type: builder.firmware_type,
            firmware_revision: builder.firmware_revision,
            firmware_date: builder.firmware_date,
            board_information: builder.board_information,
            log_start_datetime: builder.log_start_datetime,
            craft_name: builder.craft_name,
            i_interval,
            p_interval,
            p_ratio,
            other_headers: builder.other_headers,
            ip_fields,
            s_fields,
            ip_fields_in_order,
            s_fields_in_order,
            g_fields_in_order,
            i_field_encodings,
            i_field_predictors,
            p_field_encodings,
            p_field_predictors,
            s_field_encodings,
            g_fields,
            h_fields,
            g_field_encodings,
            g_field_predictors,
            h_field_encodings,
            h_field_predictors,
            gyro_scale: gyro_scale * (PI / 180.0) * 0.000001,
            raw_gyro_scale: gyro_scale,
            loop_time,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct HeaderBuilder {
    product: Option<String>,
    data_version: Option<String>,
    firmware_type: Option<String>,
    firmware_revision: Option<String>,
    firmware_date: Option<String>,
    board_information: Option<String>,
    log_start_datetime: Option<String>,
    craft_name: Option<String>,
    i_interval: Option<i16>,
    p_interval: Option<Ratio<u16>>,
    p_ratio: Option<u16>,
    gyro_scale: Option<f32>,
    loop_time: Option<u32>,

    other_headers: HashMap<String, String>,

    i_field_names: Vec<String>,
    i_field_signedness: Vec<bool>,
    i_field_encoding: Vec<RawFieldEncoding>,
    i_field_predictors: Vec<FieldPredictor>,
    p_field_encoding: Vec<RawFieldEncoding>,
    p_field_predictors: Vec<FieldPredictor>,

    s_field_names: Vec<String>,
    s_field_signedness: Vec<bool>,
    s_field_encoding: Vec<RawFieldEncoding>,
    s_field_predictors: Vec<FieldPredictor>,

    g_field_names: Vec<String>,
    g_field_signedness: Vec<bool>,
    g_field_encoding: Vec<RawFieldEncoding>,
    g_field_predictors: Vec<FieldPredictor>,

    h_field_names: Vec<String>,
    h_field_signedness: Vec<bool>,
    h_field_encoding: Vec<RawFieldEncoding>,
    h_field_predictors: Vec<FieldPredictor>,
}

#[allow(unused)]
#[derive(Clone, Debug)]
pub struct IPField {
    pub name: String,
    pub ix: usize,
    pub signed: bool,
}

#[allow(unused)]
#[derive(Clone, Debug)]
pub struct SlowField {
    pub name: String,
    ix: usize,
    signed: bool,
    predictor: FieldPredictor,
}

#[allow(unused)]
#[derive(Clone, Debug)]
pub struct GNSSField {
    pub name: String,
    ix: usize,
    signed: bool,
    predictor: FieldPredictor,
}

#[allow(unused)]
#[derive(Clone, Debug)]
pub struct GNSSHomeField {
    name: String,
    ix: usize,
    signed: bool,
    predictor: FieldPredictor,
}

#[derive(Debug)]
pub enum ParseHeadersError<I> {
    HeaderBuildError(HeaderBuildError),
    Nom(I, ErrorKind),
}

impl<I> ParseError<I> for ParseHeadersError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        ParseHeadersError::Nom(input, kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I> From<nom::error::Error<I>> for ParseHeadersError<I> {
    fn from(err: nom::error::Error<I>) -> Self {
        Self::Nom(err.input, err.code)
    }
}

pub fn parse_headers(input: &[u8]) -> IResult<&[u8], Header, ParseHeadersError<&[u8]>> {
    let (input, header) = fold_many0(
        parse_header,
        HeaderBuilder::default,
        |mut header, header_frame| {
            match header_frame {
                Frame::Product(product) => header.product = Some(product.to_owned()),
                Frame::DataVersion(version) => header.data_version = Some(version.to_owned()),
                Frame::IInterval(i_interval) => header.i_interval = Some(i_interval),
                Frame::FieldIName(i_field_names) => {
                    header.i_field_names =
                        i_field_names.into_iter().map(ToOwned::to_owned).collect()
                }
                Frame::FieldIPredictor(i_field_predictors) => {
                    header.i_field_predictors = i_field_predictors
                }
                Frame::FieldISignedness(i_field_signedness) => {
                    header.i_field_signedness = i_field_signedness
                }
                Frame::FieldIEncoding(i_field_encoding) => {
                    header.i_field_encoding = i_field_encoding
                }
                Frame::PInterval(p_interval) => header.p_interval = Some(p_interval),
                Frame::PRatio(p_ratio) => header.p_ratio = Some(p_ratio),
                Frame::FieldPPredictor(p_field_predictors) => {
                    header.p_field_predictors = p_field_predictors
                }
                Frame::FieldPEncoding(p_field_encoding) => {
                    header.p_field_encoding = p_field_encoding
                }
                Frame::FieldSName(s_field_names) => {
                    header.s_field_names =
                        s_field_names.into_iter().map(ToOwned::to_owned).collect()
                }
                Frame::FieldSPredictor(s_field_predictors) => {
                    header.s_field_predictors = s_field_predictors
                }
                Frame::FieldSSignedness(s_field_signedness) => {
                    header.s_field_signedness = s_field_signedness
                }
                Frame::FieldSEncoding(s_field_encoding) => {
                    header.s_field_encoding = s_field_encoding
                }
                Frame::FieldGName(g_field_names) => {
                    header.g_field_names =
                        g_field_names.into_iter().map(ToOwned::to_owned).collect()
                }
                Frame::FieldGPredictor(g_field_predictors) => {
                    header.g_field_predictors = g_field_predictors
                }
                Frame::FieldGSignedness(g_field_signedness) => {
                    header.g_field_signedness = g_field_signedness
                }
                Frame::FieldGEncoding(g_field_encoding) => {
                    header.g_field_encoding = g_field_encoding
                }
                Frame::FieldHName(h_field_names) => {
                    header.h_field_names =
                        h_field_names.into_iter().map(ToOwned::to_owned).collect()
                }
                Frame::FieldHPredictor(h_field_predictors) => {
                    header.h_field_predictors = h_field_predictors
                }
                Frame::FieldHSignedness(h_field_signedness) => {
                    header.h_field_signedness = h_field_signedness
                }
                Frame::FieldHEncoding(h_field_encoding) => {
                    header.h_field_encoding = h_field_encoding
                }
                Frame::GyroScale(gyro_scale) => header.gyro_scale = Some(gyro_scale),
                Frame::LoopTime(loop_time) => header.loop_time = Some(loop_time),
                Frame::UnkownHeader(name, value) => {
                    header.other_headers.insert(name.into(), value.into());
                }
                _ => {}
            };
            header
        },
    )(input)
    .map_err(nom::Err::convert)?;

    let header = header
        .try_into()
        .map_err(|err| nom::Err::Failure(ParseHeadersError::HeaderBuildError(err)))?;
    Ok((input, header))
}
