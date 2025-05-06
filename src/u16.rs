#[allow(unused)]
pub fn read_u16(data: &[u8], index: Option<&mut usize>) -> Result<u16, std::io::Error> {
    let mut binding = 0;
    let index = index.unwrap_or(&mut binding);

    if *index + 2 > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Not enough bytes to read u16",
        ));
    }
    let value = u16::from_be_bytes([data[*index], data[*index + 1]]);
    *index += 2;
    Ok(value)
}

pub fn write_u16(buffer: &mut Vec<u8>, number: u16) {
    buffer.push((number >> 8) as u8); // MSB (most significant byte)
    buffer.push(number as u8); // LSB (least significant byte)
}
