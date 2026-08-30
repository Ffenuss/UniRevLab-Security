use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const UTF8_FLAG: u32 = 0x0000_0100;
const NO_INDEX: u32 = 0xffff_ffff;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxmlDocument {
    pub elements: Vec<AxmlElement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxmlElement {
    pub depth: usize,
    pub name: String,
    pub namespace: Option<String>,
    pub attributes: Vec<AxmlAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxmlAttribute {
    pub name: String,
    pub namespace: Option<String>,
    pub value: String,
    pub data_type: u8,
    pub data: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxmlError {
    Truncated(&'static str),
    Invalid(&'static str),
    Unsupported(&'static str),
    LimitExceeded(&'static str),
    Utf8,
    Utf16,
}

impl Display for AxmlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated(s) => write!(f, "truncated AXML: {s}"),
            Self::Invalid(s) => write!(f, "invalid AXML: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported AXML: {s}"),
            Self::LimitExceeded(s) => write!(f, "AXML limit exceeded: {s}"),
            Self::Utf8 => write!(f, "invalid UTF-8 in AXML string pool"),
            Self::Utf16 => write!(f, "invalid UTF-16 in AXML string pool"),
        }
    }
}

impl std::error::Error for AxmlError {}

#[derive(Debug, Clone, Copy)]
pub struct AxmlLimits {
    pub max_bytes: usize,
    pub max_chunks: usize,
    pub max_strings: usize,
    pub max_elements: usize,
    pub max_attributes_per_element: usize,
    pub max_string_bytes: usize,
}

impl Default for AxmlLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            max_chunks: 100_000,
            max_strings: 100_000,
            max_elements: 100_000,
            max_attributes_per_element: 4_096,
            max_string_bytes: 1 * 1024 * 1024,
        }
    }
}

pub fn parse_axml(input: &[u8], limits: AxmlLimits) -> Result<AxmlDocument, AxmlError> {
    if input.len() > limits.max_bytes {
        return Err(AxmlError::LimitExceeded("input bytes"));
    }
    let root = ChunkHeader::read(input, 0)?;
    if root.kind != RES_XML_TYPE {
        return Err(AxmlError::Invalid("root chunk is not RES_XML_TYPE"));
    }
    if root.header_size < 8 || root.size < root.header_size as u32 {
        return Err(AxmlError::Invalid("bad root header size"));
    }
    let root_end = checked_end(0, root.size as usize, input.len())?;

    let mut pos = root.header_size as usize;
    let mut strings: Option<StringPool> = None;
    let mut elements = Vec::new();
    let mut depth = 0usize;
    let mut chunks = 0usize;

    while pos < root_end {
        chunks += 1;
        if chunks > limits.max_chunks {
            return Err(AxmlError::LimitExceeded("chunk count"));
        }
        let chunk = ChunkHeader::read(input, pos)?;
        if chunk.size < chunk.header_size as u32 || chunk.header_size < 8 {
            return Err(AxmlError::Invalid("child chunk size/header"));
        }
        let chunk_end = checked_end(pos, chunk.size as usize, root_end)?;

        match chunk.kind {
            RES_STRING_POOL_TYPE => {
                strings = Some(StringPool::parse(input, pos, chunk, limits)?);
            }
            RES_XML_RESOURCE_MAP_TYPE | RES_XML_START_NAMESPACE_TYPE | RES_XML_END_NAMESPACE_TYPE | RES_XML_CDATA_TYPE => {
                // Resource IDs and namespace events are not needed to preserve element-level evidence.
            }
            RES_XML_START_ELEMENT_TYPE => {
                let pool = strings.as_ref().ok_or(AxmlError::Invalid("element before string pool"))?;
                if elements.len() >= limits.max_elements {
                    return Err(AxmlError::LimitExceeded("element count"));
                }
                let element = parse_start_element(input, pos, chunk, depth, pool, limits)?;
                elements.push(element);
                depth = depth.checked_add(1).ok_or(AxmlError::LimitExceeded("element depth"))?;
            }
            RES_XML_END_ELEMENT_TYPE => {
                depth = depth.saturating_sub(1);
            }
            _ => {
                // Unknown chunks are skipped by their bounded declared size for forward compatibility.
            }
        }
        if chunk_end <= pos {
            return Err(AxmlError::Invalid("non-advancing chunk"));
        }
        pos = chunk_end;
    }

    Ok(AxmlDocument { elements })
}

fn parse_start_element(
    input: &[u8],
    chunk_offset: usize,
    chunk: ChunkHeader,
    depth: usize,
    strings: &StringPool,
    limits: AxmlLimits,
) -> Result<AxmlElement, AxmlError> {
    // ResXMLTree_node is the chunk header (usually 16 bytes). ResXMLTree_attrExt follows it.
    let chunk_end = checked_end(chunk_offset, chunk.size as usize, input.len())?;
    let ext = chunk_offset
        .checked_add(chunk.header_size as usize)
        .ok_or(AxmlError::Invalid("element offset overflow"))?;
    let ext_end = ext
        .checked_add(20)
        .ok_or(AxmlError::Invalid("element extension overflow"))?;
    if ext_end > chunk_end {
        return Err(AxmlError::Truncated("start-element extension exceeds chunk"));
    }

    let ns_idx = read_u32(input, ext)?;
    let name_idx = read_u32(input, ext + 4)?;
    let attribute_start = read_u16(input, ext + 8)? as usize;
    let attribute_size = read_u16(input, ext + 10)? as usize;
    let attribute_count = read_u16(input, ext + 12)? as usize;

    if attribute_count > limits.max_attributes_per_element {
        return Err(AxmlError::LimitExceeded("attributes per element"));
    }
    if attribute_size < 20 && attribute_count > 0 {
        return Err(AxmlError::Invalid("attribute size smaller than ResXMLTree_attribute"));
    }

    let attrs_base = ext
        .checked_add(attribute_start)
        .ok_or(AxmlError::Invalid("attribute offset overflow"))?;
    let attrs_bytes = attribute_size
        .checked_mul(attribute_count)
        .ok_or(AxmlError::Invalid("attribute bytes overflow"))?;
    let attrs_end = attrs_base
        .checked_add(attrs_bytes)
        .ok_or(AxmlError::Invalid("attribute end overflow"))?;
    if attrs_end > chunk_end {
        return Err(AxmlError::Truncated("attributes exceed start-element chunk"));
    }

    let mut attributes = Vec::with_capacity(attribute_count);
    for i in 0..attribute_count {
        let base = attrs_base + i * attribute_size;
        ensure_range(input, base, 20)?;
        let attr_ns = read_u32(input, base)?;
        let attr_name = read_u32(input, base + 4)?;
        let raw_value = read_u32(input, base + 8)?;
        let value_size = read_u16(input, base + 12)?;
        if value_size < 8 {
            return Err(AxmlError::Invalid("typed value size"));
        }
        let data_type = *input.get(base + 15).ok_or(AxmlError::Truncated("typed value type"))?;
        let data = read_u32(input, base + 16)?;
        let value = if raw_value != NO_INDEX {
            strings.get(raw_value)?.to_owned()
        } else {
            typed_value_to_string(data_type, data, strings)?
        };
        attributes.push(AxmlAttribute {
            name: strings.get(attr_name)?.to_owned(),
            namespace: string_index(strings, attr_ns)?,
            value,
            data_type,
            data,
        });
    }

    Ok(AxmlElement {
        depth,
        name: strings.get(name_idx)?.to_owned(),
        namespace: string_index(strings, ns_idx)?,
        attributes,
    })
}

fn typed_value_to_string(data_type: u8, data: u32, strings: &StringPool) -> Result<String, AxmlError> {
    Ok(match data_type {
        0x00 => String::new(), // TYPE_NULL
        0x01 => format!("@0x{data:08x}"),
        0x02 => format!("?0x{data:08x}"),
        0x03 => strings.get(data)?.to_owned(),
        0x04 => f32::from_bits(data).to_string(),
        0x10 => (data as i32).to_string(),
        0x11 => format!("0x{data:08x}"),
        0x12 => if data == 0 { "false".into() } else { "true".into() },
        0x1c..=0x1f => format!("#{data:08x}"),
        _ => format!("0x{data:08x}"),
    })
}

fn string_index(pool: &StringPool, index: u32) -> Result<Option<String>, AxmlError> {
    if index == NO_INDEX {
        Ok(None)
    } else {
        Ok(Some(pool.get(index)?.to_owned()))
    }
}

#[derive(Debug, Clone, Copy)]
struct ChunkHeader {
    kind: u16,
    header_size: u16,
    size: u32,
}

impl ChunkHeader {
    fn read(input: &[u8], offset: usize) -> Result<Self, AxmlError> {
        ensure_range(input, offset, 8)?;
        Ok(Self {
            kind: read_u16(input, offset)?,
            header_size: read_u16(input, offset + 2)?,
            size: read_u32(input, offset + 4)?,
        })
    }
}

struct StringPool {
    values: Vec<String>,
}

impl StringPool {
    fn parse(input: &[u8], offset: usize, chunk: ChunkHeader, limits: AxmlLimits) -> Result<Self, AxmlError> {
        if chunk.header_size < 28 {
            return Err(AxmlError::Invalid("string pool header"));
        }
        ensure_range(input, offset, chunk.header_size as usize)?;
        let string_count = read_u32(input, offset + 8)? as usize;
        let style_count = read_u32(input, offset + 12)? as usize;
        let flags = read_u32(input, offset + 16)?;
        let strings_start = read_u32(input, offset + 20)? as usize;
        let styles_start = read_u32(input, offset + 24)? as usize;
        if string_count > limits.max_strings {
            return Err(AxmlError::LimitExceeded("string count"));
        }
        if style_count > limits.max_strings {
            return Err(AxmlError::LimitExceeded("style count"));
        }

        let chunk_end = checked_end(offset, chunk.size as usize, input.len())?;
        let offsets_start = offset
            .checked_add(chunk.header_size as usize)
            .ok_or(AxmlError::Invalid("string offsets start overflow"))?;
        let all_offsets = string_count
            .checked_add(style_count)
            .ok_or(AxmlError::Invalid("string/style count overflow"))?;
        let offset_bytes = all_offsets
            .checked_mul(4)
            .ok_or(AxmlError::Invalid("string offsets overflow"))?;
        let offsets_end = offsets_start
            .checked_add(offset_bytes)
            .ok_or(AxmlError::Invalid("string offsets end overflow"))?;
        if offsets_end > chunk_end {
            return Err(AxmlError::Truncated("string/style offsets exceed string-pool chunk"));
        }

        let strings_base = offset
            .checked_add(strings_start)
            .ok_or(AxmlError::Invalid("strings base overflow"))?;
        if strings_base > chunk_end {
            return Err(AxmlError::Invalid("strings start outside string pool"));
        }
        if styles_start != 0 {
            let styles_base = offset
                .checked_add(styles_start)
                .ok_or(AxmlError::Invalid("styles base overflow"))?;
            if styles_base > chunk_end {
                return Err(AxmlError::Invalid("styles start outside string pool"));
            }
        }

        let utf8 = flags & UTF8_FLAG != 0;
        let mut values = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let relative = read_u32(input, offsets_start + i * 4)? as usize;
            let string_offset = strings_base
                .checked_add(relative)
                .ok_or(AxmlError::Invalid("string offset overflow"))?;
            if string_offset >= chunk_end {
                return Err(AxmlError::Invalid("string offset outside pool"));
            }
            let value = if utf8 {
                decode_utf8(input, string_offset, chunk_end, limits.max_string_bytes)?
            } else {
                decode_utf16(input, string_offset, chunk_end, limits.max_string_bytes)?
            };
            values.push(value);
        }
        Ok(Self { values })
    }

    fn get(&self, index: u32) -> Result<&str, AxmlError> {
        self.values
            .get(index as usize)
            .map(String::as_str)
            .ok_or(AxmlError::Invalid("string index outside pool"))
    }
}

fn decode_utf8(input: &[u8], mut pos: usize, end: usize, max_bytes: usize) -> Result<String, AxmlError> {
    let (_utf16_len, next) = read_len8(input, pos, end)?;
    pos = next;
    let (byte_len, next) = read_len8(input, pos, end)?;
    pos = next;
    if byte_len > max_bytes {
        return Err(AxmlError::LimitExceeded("UTF-8 string bytes"));
    }
    let string_end = pos.checked_add(byte_len).ok_or(AxmlError::Invalid("UTF-8 length overflow"))?;
    if string_end >= end || string_end >= input.len() {
        return Err(AxmlError::Truncated("UTF-8 string/terminator"));
    }
    if input[string_end] != 0 {
        return Err(AxmlError::Invalid("UTF-8 string missing terminator"));
    }
    let bytes = &input[pos..string_end];
    std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| AxmlError::Utf8)
}

fn decode_utf16(input: &[u8], mut pos: usize, end: usize, max_bytes: usize) -> Result<String, AxmlError> {
    let (units, next) = read_len16(input, pos, end)?;
    pos = next;
    let bytes = units.checked_mul(2).ok_or(AxmlError::Invalid("UTF-16 length overflow"))?;
    if bytes > max_bytes {
        return Err(AxmlError::LimitExceeded("UTF-16 string bytes"));
    }
    let string_end = pos.checked_add(bytes).ok_or(AxmlError::Invalid("UTF-16 end overflow"))?;
    let terminator_end = string_end.checked_add(2).ok_or(AxmlError::Invalid("UTF-16 terminator overflow"))?;
    if terminator_end > end || terminator_end > input.len() {
        return Err(AxmlError::Truncated("UTF-16 string/terminator"));
    }
    if read_u16(input, string_end)? != 0 {
        return Err(AxmlError::Invalid("UTF-16 string missing terminator"));
    }
    let mut encoded = Vec::with_capacity(units);
    for i in 0..units {
        encoded.push(read_u16(input, pos + i * 2)?);
    }
    String::from_utf16(&encoded).map_err(|_| AxmlError::Utf16)
}

fn read_len8(input: &[u8], pos: usize, end: usize) -> Result<(usize, usize), AxmlError> {
    if pos >= end {
        return Err(AxmlError::Truncated("UTF-8 encoded length"));
    }
    let first = *input.get(pos).ok_or(AxmlError::Truncated("UTF-8 encoded length"))?;
    if first & 0x80 == 0 {
        Ok((first as usize, pos + 1))
    } else {
        if pos + 1 >= end {
            return Err(AxmlError::Truncated("UTF-8 two-byte length"));
        }
        let second = input[pos + 1];
        Ok(((((first & 0x7f) as usize) << 8) | second as usize, pos + 2))
    }
}

fn read_len16(input: &[u8], pos: usize, end: usize) -> Result<(usize, usize), AxmlError> {
    if pos + 2 > end {
        return Err(AxmlError::Truncated("UTF-16 encoded length"));
    }
    let first = read_u16(input, pos)?;
    if first & 0x8000 == 0 {
        Ok((first as usize, pos + 2))
    } else {
        if pos + 4 > end {
            return Err(AxmlError::Truncated("UTF-16 four-byte length"));
        }
        let second = read_u16(input, pos + 2)?;
        Ok(((((first & 0x7fff) as usize) << 16) | second as usize, pos + 4))
    }
}

fn checked_end(offset: usize, size: usize, bound: usize) -> Result<usize, AxmlError> {
    let end = offset.checked_add(size).ok_or(AxmlError::Invalid("chunk end overflow"))?;
    if end > bound {
        Err(AxmlError::Truncated("chunk exceeds parent/input"))
    } else {
        Ok(end)
    }
}

fn ensure_range(input: &[u8], offset: usize, size: usize) -> Result<(), AxmlError> {
    checked_end(offset, size, input.len()).map(|_| ())
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, AxmlError> {
    ensure_range(input, offset, 2)?;
    Ok(u16::from_le_bytes([input[offset], input[offset + 1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, AxmlError> {
    ensure_range(input, offset, 4)?;
    Ok(u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_xml_root() {
        let input = [0x01, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00];
        assert!(matches!(parse_axml(&input, AxmlLimits::default()), Err(AxmlError::Invalid(_))));
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let input = vec![0u8; 32];
        let limits = AxmlLimits { max_bytes: 8, ..AxmlLimits::default() };
        assert!(matches!(parse_axml(&input, limits), Err(AxmlError::LimitExceeded(_))));
    }

    #[test]
    fn parses_minimal_utf8_manifest() {
        let bytes = minimal_manifest();
        let doc = parse_axml(&bytes, AxmlLimits::default()).expect("minimal manifest parses");
        assert_eq!(doc.elements.len(), 2);
        assert_eq!(doc.elements[0].name, "manifest");
        assert_eq!(doc.elements[0].attributes[0].name, "package");
        assert_eq!(doc.elements[0].attributes[0].value, "org.example");
        assert_eq!(doc.elements[1].name, "application");
        assert_eq!(doc.elements[1].attributes[0].name, "debuggable");
        assert_eq!(doc.elements[1].attributes[0].value, "true");
    }

    fn minimal_manifest() -> Vec<u8> {
        let strings = ["manifest", "package", "org.example", "application", "debuggable"];
        let pool = utf8_string_pool(&strings);
        let manifest_start = start_element(0, 0, &[(NO_INDEX, 1, 2, 0x03, 2)]);
        let app_start = start_element(0, 3, &[(NO_INDEX, 4, NO_INDEX, 0x12, 0xffff_ffff)]);
        let app_end = end_element(3);
        let manifest_end = end_element(0);

        let total = 8 + pool.len() + manifest_start.len() + app_start.len() + app_end.len() + manifest_end.len();
        let mut out = Vec::with_capacity(total);
        push_u16(&mut out, RES_XML_TYPE);
        push_u16(&mut out, 8);
        push_u32(&mut out, total as u32);
        out.extend(pool);
        out.extend(manifest_start);
        out.extend(app_start);
        out.extend(app_end);
        out.extend(manifest_end);
        out
    }

    fn utf8_string_pool(strings: &[&str]) -> Vec<u8> {
        let header_size = 28usize;
        let offsets_size = strings.len() * 4;
        let strings_start = header_size + offsets_size;
        let mut payload = Vec::new();
        let mut offsets = Vec::new();
        for s in strings {
            offsets.push(payload.len() as u32);
            assert!(s.len() < 0x80);
            payload.push(s.chars().count() as u8);
            payload.push(s.len() as u8);
            payload.extend_from_slice(s.as_bytes());
            payload.push(0);
        }
        while payload.len() % 4 != 0 { payload.push(0); }
        let size = strings_start + payload.len();
        let mut out = Vec::with_capacity(size);
        push_u16(&mut out, RES_STRING_POOL_TYPE);
        push_u16(&mut out, header_size as u16);
        push_u32(&mut out, size as u32);
        push_u32(&mut out, strings.len() as u32);
        push_u32(&mut out, 0);
        push_u32(&mut out, UTF8_FLAG);
        push_u32(&mut out, strings_start as u32);
        push_u32(&mut out, 0);
        for offset in offsets { push_u32(&mut out, offset); }
        out.extend(payload);
        out
    }

    fn start_element(ns: u32, name: u32, attrs: &[(u32, u32, u32, u8, u32)]) -> Vec<u8> {
        let node_header = 16usize;
        let ext_size = 20usize;
        let attr_size = 20usize;
        let size = node_header + ext_size + attrs.len() * attr_size;
        let mut out = Vec::with_capacity(size);
        push_u16(&mut out, RES_XML_START_ELEMENT_TYPE);
        push_u16(&mut out, node_header as u16);
        push_u32(&mut out, size as u32);
        push_u32(&mut out, 1); // line number
        push_u32(&mut out, NO_INDEX); // comment
        push_u32(&mut out, if ns == 0 { NO_INDEX } else { ns });
        push_u32(&mut out, name);
        push_u16(&mut out, ext_size as u16); // attributes start, relative to attrExt
        push_u16(&mut out, attr_size as u16);
        push_u16(&mut out, attrs.len() as u16);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        for &(attr_ns, attr_name, raw, ty, data) in attrs {
            push_u32(&mut out, attr_ns);
            push_u32(&mut out, attr_name);
            push_u32(&mut out, raw);
            push_u16(&mut out, 8);
            out.push(0);
            out.push(ty);
            push_u32(&mut out, data);
        }
        out
    }

    fn end_element(name: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        push_u16(&mut out, RES_XML_END_ELEMENT_TYPE);
        push_u16(&mut out, 16);
        push_u32(&mut out, 24);
        push_u32(&mut out, 1);
        push_u32(&mut out, NO_INDEX);
        push_u32(&mut out, NO_INDEX);
        push_u32(&mut out, name);
        out
    }

    fn push_u16(out: &mut Vec<u8>, v: u16) { out.extend_from_slice(&v.to_le_bytes()); }
    fn push_u32(out: &mut Vec<u8>, v: u32) { out.extend_from_slice(&v.to_le_bytes()); }
}
