extern crate base64;

use base64::encode;

pub fn base64encode<T: AsRef<[u8]>>(input: T) -> String {
    encode(input)
}
