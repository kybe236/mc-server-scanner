use super::varint::{read_var_int, write_var_int};

pub fn read_string(data: &[u8], mut index: &mut usize) -> Result<String, std::io::Error> {
    // Step 1: Read the length of the string (VarInt), which is the number of UTF-16 code units
    let length = read_var_int(data, Some(&mut index)) as usize;

    // Step 2: Ensure we don't go beyond the bounds of the data buffer
    if *index + length > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Attempted to read beyond the buffer",
        ));
    }

    // Step 3: Read the UTF-8 bytes of the string
    let str_bytes = &data[*index..*index + length];

    // Step 4: Update the index to point after the string bytes
    *index += length;

    // Step 5: Try to convert the bytes to a string
    let decoded_string = String::from_utf8(str_bytes.to_vec())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Step 6: Return the decoded string
    Ok(decoded_string)
}

pub fn write_string(buffer: &mut Vec<u8>, string: &str) {
    // Calculate the UTF-16 code unit length
    let utf16_len = string
        .chars()
        .map(|c| if c > '\u{FFFF}' { 2 } else { 1 })
        .sum::<usize>();

    // Ensure the length is within the valid range for Minecraft protocol (32767 UTF-16 code units max)
    if utf16_len > 32767 {
        panic!("String is too long for the Minecraft protocol!");
    }

    // Write the length as a VarInt
    write_var_int(buffer, &(utf16_len as i32));

    // Write the string's UTF-8 bytes
    buffer.extend_from_slice(string.as_bytes());
}
