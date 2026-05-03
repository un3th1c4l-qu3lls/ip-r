pub mod v4; // RFC 791
pub mod v6; // RFC 8200
// Note that we need to make their components public.






pub fn add(left: u64, right: u64) -> u64 {
    left + right
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
