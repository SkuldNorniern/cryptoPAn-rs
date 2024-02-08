use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use openssl::{
    error::ErrorStack,
    symm::{Cipher, Crypter, Mode},
};

pub struct CryptoPAn {
    crypter: Crypter,
    padding: u128,
}

impl CryptoPAn {
    pub fn new(key: &[u8; 32]) -> Result<Self, ErrorStack> {
        let (aes_key, pad_key) = key.split_at(16);

        // 1. Initialize an AES encrypter with the first half of the key.
        let mut crypter = Crypter::new(
            Cipher::aes_128_ecb(),
            Mode::Encrypt,
            aes_key,
            None, // ECB mode does not need an initialization vector.
        )?;
        crypter.pad(false);

        // NOTE: The output buffer of `Crypter::update()` must be bigger than
        // | the input buffer's size + the cipher's block size. In this case,
        // | `pad_key.len() == 16`, `Cipher::aes_128_ecb().block_size() == 16`.
        let mut padding = [0; 16 + 16];

        // 2. Generate a padding by encrypting the second half of the key.
        let mut cnt = 0;
        cnt += crypter.update(pad_key, &mut padding)?;
        cnt += crypter.finalize(&mut padding[cnt..])?;
        let padding = &padding[..cnt];

        Ok(Self {
            crypter,
            padding: Self::to_int(padding),
        })
    }

    // Convert a byte array to a u64 value.
    fn to_int(byte_array: &[u8]) -> u128 {
        byte_array
            .iter()
            .fold(0u128, |acc, &byte| (acc << 8) | u128::from(byte))
    }

    // Convert a u64 value to a byte array.
    fn to_array(&self, int_value: u128, int_value_len: usize) -> Vec<u8> {
        let mut byte_array: Vec<u8> = Vec::with_capacity(int_value_len);
        for i in 0..int_value_len {
            byte_array.insert(0, ((int_value >> (i * 8)) & 0xff) as u8);
        }
        byte_array
    }

    pub fn anonymize(&mut self, addr: IpAddr) -> Result<IpAddr, ErrorStack> {
        let (addr_int, version) = match addr {
            IpAddr::V4(ipv4) => (u128::from(u32::from(ipv4)), 4),
            IpAddr::V6(ipv6) => (u128::from(ipv6), 6),
        };

        let anonymized = self.anonymize_bin(addr_int, version)?;

        Ok(Self::format_ip(anonymized, version))
    }

    /// Anonymizes an IP address string while preserving the subnet structure.
    ///
    /// This is a convenience method over [`anonymize()`] to accept formatted IP string
    /// instead of an [`IpAddr`]. If there is a possibility of invalid inputs, [`anonymize()`]
    /// should be prefered in order to handle parsing failure.
    ///
    /// # Panics
    ///
    /// Panics if the input string is not a correctly formatted IPv4 or IPv6 address.
    ///
    /// [`anonymize()`]: CryptoPAn::anonymize()
    #[allow(dead_code)]
    fn anonymize_str(&mut self, addr: &str) -> Result<IpAddr, ErrorStack> {
        // FIX: panicking convenience method is considered unidiomatic
        // | we should decide whether ergonomic is so important or not
        // | (O) -> make this method `pub`
        // | (X) -> move this method to the test module
        let addr: IpAddr = addr
            .parse()
            .expect("input string should be a valid IPv4 or IPv6 address");
        self.anonymize(addr)
    }

    fn anonymize_bin(&mut self, addr: u128, version: u8) -> Result<u128, ErrorStack> {
        let pos_max = if version == 4 { 32 } else { 128 };
        let ext_addr = if version == 4 { addr << 96 } else { addr };

        let mut flip_array = Vec::new();
        for pos in 0..pos_max {
            let mask = u128::MAX >> pos;
            let padded_addr = (self.padding & mask) | (ext_addr & !mask);
            let padded_bytes = self.to_array(padded_addr, 16);

            let block_size = Cipher::aes_128_ecb().block_size();
            let mut encrypted = vec![0u8; 16 + block_size];
            let mut cnt = self.crypter.update(&padded_bytes, &mut encrypted)?;
            cnt += self.crypter.finalize(&mut encrypted[cnt..])?;
            encrypted.truncate(cnt);

            flip_array.push(encrypted[0] >> 7);
        }
        let result = flip_array
            .into_iter()
            .fold(0u128, |acc, x| (acc << 1) | (x as u128));

        Ok(addr ^ result)
    }

    fn format_ip(addr: u128, version: u8) -> IpAddr {
        match version {
            4 => IpAddr::V4(Ipv4Addr::from((addr & 0xFFFFFFFF) as u32)),
            6 => IpAddr::V6(Ipv6Addr::from(addr)),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The encryption key and sample data are from the C++ reference implementation.
    // https://web.archive.org/web/20180908092841/https://www.cc.gatech.edu/computing/Telecomm/projects/cryptopan/
    const KEY: &[u8; 32] = b"\
        \x15\x22\x17\x8d\x33\xa4\xcf\x80\
        \x13\x0a\x5b\x16\x49\x90\x7d\x10\
        \xd8\x98\x8f\x83\x79\x79\x65\x27\
        \x62\x57\x4c\x2d\x2a\x84\x22\x02\
    ";

    fn run_test_cases(cases: &[(&str, &str)]) -> Result<(), ErrorStack> {
        let mut pancake = CryptoPAn::new(KEY)?;
        for (addr, expected) in cases {
            let anonymized = pancake.anonymize_str(addr)?;
            let expected: IpAddr = expected.parse().unwrap();
            assert_eq!(anonymized, expected);
        }

        Ok(())
    }

    #[test]
    fn test_anonymize_ipv4_full() -> Result<(), ErrorStack> {
        let cases = [
            ("128.11.68.132", "135.242.180.132"),
            ("129.118.74.4", "134.136.186.123"),
            ("130.132.252.244", "133.68.164.234"),
            ("141.223.7.43", "141.167.8.160"),
            ("141.233.145.108", "141.129.237.235"),
            ("152.163.225.39", "151.140.114.167"),
            ("156.29.3.236", "147.225.12.42"),
            ("165.247.96.84", "162.9.99.234"),
            ("166.107.77.190", "160.132.178.185"),
            ("192.102.249.13", "252.138.62.131"),
            ("192.215.32.125", "252.43.47.189"),
            ("192.233.80.103", "252.25.108.8"),
            ("192.41.57.43", "252.222.221.184"),
            ("193.150.244.223", "253.169.52.216"),
            ("195.205.63.100", "255.186.223.5"),
            ("198.200.171.101", "249.199.68.213"),
            ("198.26.132.101", "249.36.123.202"),
            ("198.36.213.5", "249.7.21.132"),
            ("198.51.77.238", "249.18.186.254"),
            ("199.217.79.101", "248.38.184.213"),
            ("202.49.198.20", "245.206.7.234"),
            ("203.12.160.252", "244.248.163.4"),
            ("204.184.162.189", "243.192.77.90"),
            ("204.202.136.230", "243.178.4.198"),
            ("204.29.20.4", "243.33.20.123"),
            ("205.178.38.67", "242.108.198.51"),
            ("205.188.147.153", "242.96.16.101"),
            ("205.188.248.25", "242.96.88.27"),
            ("205.245.121.43", "242.21.121.163"),
            ("207.105.49.5", "241.118.205.138"),
            ("207.135.65.238", "241.202.129.222"),
            ("207.155.9.214", "241.220.250.22"),
            ("207.188.7.45", "241.255.249.220"),
            ("207.25.71.27", "241.33.119.156"),
            ("207.33.151.131", "241.1.233.131"),
            ("208.147.89.59", "227.237.98.191"),
            ("208.234.120.210", "227.154.67.17"),
            ("208.28.185.184", "227.39.94.90"),
            ("208.52.56.122", "227.8.63.165"),
            ("209.12.231.7", "226.243.167.8"),
            ("209.238.72.3", "226.6.119.243"),
            ("209.246.74.109", "226.22.124.76"),
            ("209.68.60.238", "226.184.220.233"),
            ("209.85.249.6", "226.170.70.6"),
            ("212.120.124.31", "228.135.163.231"),
            ("212.146.8.236", "228.19.4.234"),
            ("212.186.227.154", "228.59.98.98"),
            ("212.204.172.118", "228.71.195.169"),
            ("212.206.130.201", "228.69.242.193"),
            ("216.148.237.145", "235.84.194.111"),
            ("216.157.30.252", "235.89.31.26"),
            ("216.184.159.48", "235.96.225.78"),
            ("216.227.10.221", "235.28.253.36"),
            ("216.254.18.172", "235.7.16.162"),
            ("216.32.132.250", "235.192.139.38"),
            ("216.35.217.178", "235.195.157.81"),
            ("24.0.250.221", "100.15.198.226"),
            ("24.13.62.231", "100.2.192.247"),
            ("24.14.213.138", "100.1.42.141"),
            ("24.5.0.80", "100.9.15.210"),
            ("24.7.198.88", "100.10.6.25"),
            ("24.94.26.44", "100.88.228.35"),
            ("38.15.67.68", "64.3.66.187"),
            ("4.3.88.225", "124.60.155.63"),
            ("63.14.55.111", "95.9.215.7"),
            ("63.195.241.44", "95.179.238.44"),
            ("63.97.7.140", "95.97.9.123"),
            ("64.14.118.196", "0.255.183.58"),
            ("64.34.154.117", "0.221.154.117"),
            ("64.39.15.238", "0.219.7.41"),
        ];

        run_test_cases(&cases)
    }

    #[test]
    fn test_anonymize_ipv6_partial() -> Result<(), ErrorStack> {
        let cases = [
            ("::1", "78ff:f001:9fc0:20df:8380:b1f1:704:ed"),
            ("::2", "78ff:f001:9fc0:20df:8380:b1f1:704:ef"),
            ("::ffff", "78ff:f001:9fc0:20df:8380:b1f1:704:f838"),
            ("2001:db8::1", "4401:2bc:603f:d91d:27f:ff8e:e6f1:dc1e"),
            ("2001:db8::2", "4401:2bc:603f:d91d:27f:ff8e:e6f1:dc1c"),
        ];

        run_test_cases(&cases)
    }
}
