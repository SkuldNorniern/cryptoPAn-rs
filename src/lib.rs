use openssl::symm::{Cipher, Crypter, Mode};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub enum CryptoPAnError {
    CipherError(CipherError),
    AddressParseError(AddrParseError),
}
impl std::fmt::Display for CryptoPAnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoPAnError::CipherError(err) => write!(f, "{}", err),
            CryptoPAnError::AddressParseError(err) => write!(f, "{}", err),
        }
    }
}

impl From<CipherError> for CryptoPAnError {
    fn from(err: CipherError) -> Self {
        CryptoPAnError::CipherError(err)
    }
}

impl From<AddrParseError> for CryptoPAnError {
    fn from(err: AddrParseError) -> Self {
        CryptoPAnError::AddressParseError(err)
    }
}

#[derive(Debug)]
pub enum CipherError {
    InvalidKeyLength(usize),
    CipherCreationFailed,
    EncryptionUpdateFailed,
    EncryptionFinalizeFailed,
}
impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::InvalidKeyLength(len) => write!(
                f,
                "Invalid key length (must be 32 bytes)\n Found {} bytes",
                len
            ),
            CipherError::CipherCreationFailed => write!(f, "Cipher creation failed"),
            CipherError::EncryptionUpdateFailed => write!(f, "Encryption Update failed"),
            CipherError::EncryptionFinalizeFailed => write!(f, "Encryption Finalize failed"),
        }
    }
}

pub struct CryptoPAn {
    cipher: Crypter,
    padding_int: u128,
}

impl CryptoPAn {
    pub fn new(key: &[u8]) -> Result<Self, CryptoPAnError> {
        if key.len() != 32 {
            return Err(CryptoPAnError::CipherError(CipherError::InvalidKeyLength(
                key.len(),
            )));
        }

        // Prepare the AES cipher for encryption.
        let mut cipher = Crypter::new(
            Cipher::aes_128_ecb(),
            Mode::Encrypt,
            &key[..16], // First 16 bytes are the AES key.
            None,       // ECB mode does not use an IV.
        )
        .map_err(|_| CipherError::CipherCreationFailed)?;
        
        // Disable padding from the crypter.
        cipher.pad(false);
        
        // Correctly size the buffer for the output of the encryption operation.
        // The AES block size is 16 bytes, so the output will also be 16 bytes.
        let block_size = Cipher::aes_128_ecb().block_size();
        let mut padding = vec![0; 16 + block_size]; // Output buffer sized to 16 bytes.

        // Encrypt the second half of the key to use as padding.
        // NOTE: `update` followed by `finalize` ensures complete encryption.
        let mut cnt = cipher
            .update(&key[16..], &mut padding)
            .map_err(|_| CipherError::EncryptionUpdateFailed)?;
        cnt += cipher
            .finalize(&mut padding[cnt..])
            .map_err(|_| CipherError::EncryptionFinalizeFailed)?;
        padding.truncate(cnt);

        Ok(Self {
            cipher,
            padding_int: Self::to_int(&padding),
        })
    }

    fn to_int(byte_array: &[u8]) -> u128 {
        // Convert a byte array to a u64 value.
        byte_array
            .iter()
            .fold(0u128, |acc, &byte| (acc << 8) | u128::from(byte))
    }

    fn to_array(&self, int_value: u128, int_value_len: usize) -> Vec<u8> {
        // Convert a u64 value to a byte array.
        let mut byte_array: Vec<u8> = Vec::with_capacity(int_value_len);
        for i in 0..int_value_len {
            byte_array.insert(0, ((int_value >> (i * 8)) & 0xff) as u8);
        }
        byte_array
    }

    pub fn anonymize(&mut self, addr: &str) -> Result<IpAddr, CryptoPAnError> {
        let ip: IpAddr = addr.parse()?;
        let (addr, version) = match ip {
            IpAddr::V4(ipv4) => (u128::from(u32::from(ipv4)), 4),
            IpAddr::V6(ipv6) => (u128::from(ipv6), 6),
        };

        let anonymized = self.anonymize_bin(addr, version)?;

        Ok(Self::format_ip(anonymized, version))
    }

    fn anonymize_bin(&mut self, addr: u128, version: u8) -> Result<u128, CryptoPAnError> {
        let pos_max = if version == 4 { 32 } else { 128 };
        let ext_addr = if version == 4 { addr << 96 } else { addr };

        let mut flip_array = Vec::new();
        for pos in 0..pos_max {
            let mask = !0u128 >> pos;
            let padded_addr = (self.padding_int & mask) | (ext_addr & !mask);
            let padded_bytes = self.to_array(padded_addr, 16);

            let block_size = Cipher::aes_128_ecb().block_size();
            let mut encrypted = vec![0u8; 16 + block_size];
            let mut cnt = self
                .cipher
                .update(&padded_bytes, &mut encrypted)
                .map_err(|_| CipherError::EncryptionUpdateFailed)?;
            cnt += self
                .cipher
                .finalize(&mut encrypted[cnt..])
                .map_err(|_| CipherError::EncryptionFinalizeFailed)?;
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

// test module
#[cfg(test)]
mod tests {
    use super::*;
    fn run_key_test(addr: &str, expected: &str) {
        // following key is the key used in the original crypto-pan source distribution code.
        let mut cp = CryptoPAn::new(&[
            21, 34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16, 216, 152, 143,
            131, 121, 121, 101, 39, 98, 87, 76, 45, 42, 132, 34, 2,
        ])
        .unwrap();
        let anonymized = cp.anonymize(addr).unwrap();
        assert_eq!(anonymized.to_string(), expected);
    }

    #[test]
    fn test_anonymize_ipv4_full_1() {
        run_key_test("128.11.68.132", "135.242.180.132");
    }

    #[test]
    fn test_anonymize_ipv4_full_2() {
        run_key_test("129.118.74.4", "134.136.186.123");
    }

    #[test]
    fn test_anonymize_ipv4_full_3() {
        run_key_test("130.132.252.244", "133.68.164.234");
    }

    #[test]
    fn test_anonymize_ipv4_full_4() {
        run_key_test("141.223.7.43", "141.167.8.160");
    }

    #[test]
    fn test_anonymize_ipv4_full_5() {
        run_key_test("141.233.145.108", "141.129.237.235");
    }

    #[test]
    fn test_anonymize_ipv4_full_6() {
        run_key_test("152.163.225.39", "151.140.114.167");
    }

    #[test]
    fn test_anonymize_ipv4_full_7() {
        run_key_test("156.29.3.236", "147.225.12.42");
    }

    #[test]
    fn test_anonymize_ipv4_full_8() {
        run_key_test("165.247.96.84", "162.9.99.234");
    }

    #[test]
    fn test_anonymize_ipv4_full_9() {
        run_key_test("166.107.77.190", "160.132.178.185");
    }

    #[test]
    fn test_anonymize_ipv4_full_10() {
        run_key_test("192.102.249.13", "252.138.62.131");
    }

    #[test]
    fn test_anonymize_ipv4_full_11() {
        run_key_test("192.215.32.125", "252.43.47.189");
    }

    #[test]
    fn test_anonymize_ipv4_full_12() {
        run_key_test("192.233.80.103", "252.25.108.8");
    }

    #[test]
    fn test_anonymize_ipv4_full_13() {
        run_key_test("192.41.57.43", "252.222.221.184");
    }

    #[test]
    fn test_anonymize_ipv4_full_14() {
        run_key_test("193.150.244.223", "253.169.52.216");
    }

    #[test]
    fn test_anonymize_ipv4_full_15() {
        run_key_test("195.205.63.100", "255.186.223.5");
    }

    #[test]
    fn test_anonymize_ipv4_full_16() {
        run_key_test("198.200.171.101", "249.199.68.213");
    }

    #[test]
    fn test_anonymize_ipv4_full_17() {
        run_key_test("198.26.132.101", "249.36.123.202");
    }

    #[test]
    fn test_anonymize_ipv4_full_18() {
        run_key_test("198.36.213.5", "249.7.21.132");
    }

    #[test]
    fn test_anonymize_ipv4_full_19() {
        run_key_test("198.51.77.238", "249.18.186.254");
    }

    #[test]
    fn test_anonymize_ipv4_full_20() {
        run_key_test("199.217.79.101", "248.38.184.213");
    }

    #[test]
    fn test_anonymize_ipv4_full_21() {
        run_key_test("202.49.198.20", "245.206.7.234");
    }

    #[test]
    fn test_anonymize_ipv4_full_22() {
        run_key_test("203.12.160.252", "244.248.163.4");
    }

    #[test]
    fn test_anonymize_ipv4_full_23() {
        run_key_test("204.184.162.189", "243.192.77.90");
    }

    #[test]
    fn test_anonymize_ipv4_full_24() {
        run_key_test("204.202.136.230", "243.178.4.198");
    }

    #[test]
    fn test_anonymize_ipv4_full_25() {
        run_key_test("204.29.20.4", "243.33.20.123");
    }

    #[test]
    fn test_anonymize_ipv4_full_26() {
        run_key_test("205.178.38.67", "242.108.198.51");
    }

    #[test]
    fn test_anonymize_ipv4_full_27() {
        run_key_test("205.188.147.153", "242.96.16.101");
    }

    #[test]
    fn test_anonymize_ipv4_full_28() {
        run_key_test("205.188.248.25", "242.96.88.27");
    }

    #[test]
    fn test_anonymize_ipv4_full_29() {
        run_key_test("205.245.121.43", "242.21.121.163");
    }

    #[test]
    fn test_anonymize_ipv4_full_30() {
        run_key_test("207.105.49.5", "241.118.205.138");
    }

    #[test]
    fn test_anonymize_ipv4_full_31() {
        run_key_test("207.135.65.238", "241.202.129.222");
    }

    #[test]
    fn test_anonymize_ipv4_full_32() {
        run_key_test("207.155.9.214", "241.220.250.22");
    }

    #[test]
    fn test_anonymize_ipv4_full_33() {
        run_key_test("207.188.7.45", "241.255.249.220");
    }

    #[test]
    fn test_anonymize_ipv4_full_34() {
        run_key_test("207.25.71.27", "241.33.119.156");
    }

    #[test]
    fn test_anonymize_ipv4_full_35() {
        run_key_test("207.33.151.131", "241.1.233.131");
    }

    #[test]
    fn test_anonymize_ipv4_full_36() {
        run_key_test("208.147.89.59", "227.237.98.191");
    }

    #[test]
    fn test_anonymize_ipv4_full_37() {
        run_key_test("208.234.120.210", "227.154.67.17");
    }

    #[test]
    fn test_anonymize_ipv4_full_38() {
        run_key_test("208.28.185.184", "227.39.94.90");
    }

    #[test]
    fn test_anonymize_ipv4_full_39() {
        run_key_test("208.52.56.122", "227.8.63.165");
    }

    #[test]
    fn test_anonymize_ipv4_full_40() {
        run_key_test("209.12.231.7", "226.243.167.8");
    }

    #[test]
    fn test_anonymize_ipv4_full_41() {
        run_key_test("209.238.72.3", "226.6.119.243");
    }

    #[test]
    fn test_anonymize_ipv4_full_42() {
        run_key_test("209.246.74.109", "226.22.124.76");
    }

    #[test]
    fn test_anonymize_ipv4_full_43() {
        run_key_test("209.68.60.238", "226.184.220.233");
    }

    #[test]
    fn test_anonymize_ipv4_full_44() {
        run_key_test("209.85.249.6", "226.170.70.6");
    }

    #[test]
    fn test_anonymize_ipv4_full_45() {
        run_key_test("212.120.124.31", "228.135.163.231");
    }

    #[test]
    fn test_anonymize_ipv4_full_46() {
        run_key_test("212.146.8.236", "228.19.4.234");
    }

    #[test]
    fn test_anonymize_ipv4_full_47() {
        run_key_test("212.186.227.154", "228.59.98.98");
    }

    #[test]
    fn test_anonymize_ipv4_full_48() {
        run_key_test("212.204.172.118", "228.71.195.169");
    }

    #[test]
    fn test_anonymize_ipv4_full_49() {
        run_key_test("212.206.130.201", "228.69.242.193");
    }

    #[test]
    fn test_anonymize_ipv4_full_50() {
        run_key_test("216.148.237.145", "235.84.194.111");
    }

    #[test]
    fn test_anonymize_ipv4_full_51() {
        run_key_test("216.157.30.252", "235.89.31.26");
    }

    #[test]
    fn test_anonymize_ipv4_full_52() {
        run_key_test("216.184.159.48", "235.96.225.78");
    }

    #[test]
    fn test_anonymize_ipv4_full_53() {
        run_key_test("216.227.10.221", "235.28.253.36");
    }

    #[test]
    fn test_anonymize_ipv4_full_54() {
        run_key_test("216.254.18.172", "235.7.16.162");
    }

    #[test]
    fn test_anonymize_ipv4_full_55() {
        run_key_test("216.32.132.250", "235.192.139.38");
    }

    #[test]
    fn test_anonymize_ipv4_full_56() {
        run_key_test("216.35.217.178", "235.195.157.81");
    }

    #[test]
    fn test_anonymize_ipv4_full_57() {
        run_key_test("24.0.250.221", "100.15.198.226");
    }

    #[test]
    fn test_anonymize_ipv4_full_58() {
        run_key_test("24.13.62.231", "100.2.192.247");
    }

    #[test]
    fn test_anonymize_ipv4_full_59() {
        run_key_test("24.14.213.138", "100.1.42.141");
    }

    #[test]
    fn test_anonymize_ipv4_full_60() {
        run_key_test("24.5.0.80", "100.9.15.210");
    }

    #[test]
    fn test_anonymize_ipv4_full_61() {
        run_key_test("24.7.198.88", "100.10.6.25");
    }

    #[test]
    fn test_anonymize_ipv4_full_62() {
        run_key_test("24.94.26.44", "100.88.228.35");
    }

    #[test]
    fn test_anonymize_ipv4_full_63() {
        run_key_test("38.15.67.68", "64.3.66.187");
    }

    #[test]
    fn test_anonymize_ipv4_full_64() {
        run_key_test("4.3.88.225", "124.60.155.63");
    }

    #[test]
    fn test_anonymize_ipv4_full_65() {
        run_key_test("63.14.55.111", "95.9.215.7");
    }

    #[test]
    fn test_anonymize_ipv4_full_66() {
        run_key_test("63.195.241.44", "95.179.238.44");
    }

    #[test]
    fn test_anonymize_ipv4_full_67() {
        run_key_test("63.97.7.140", "95.97.9.123");
    }

    #[test]
    fn test_anonymize_ipv4_full_68() {
        run_key_test("64.14.118.196", "0.255.183.58");
    }

    #[test]
    fn test_anonymize_ipv4_full_69() {
        run_key_test("64.34.154.117", "0.221.154.117");
    }

    #[test]
    fn test_anonymize_ipv4_full_70() {
        run_key_test("64.39.15.238", "0.219.7.41");
    }

    #[test]
    fn test_anonymize_ipv6_parcial() {
        run_key_test("::1", "78ff:f001:9fc0:20df:8380:b1f1:704:ed");
    }

    #[test]
    fn test_anonymize_ipv6_parcial2() {
        run_key_test("::2", "78ff:f001:9fc0:20df:8380:b1f1:704:ef");
    }

    #[test]
    fn test_anonymize_ipv6_parcial3() {
        run_key_test("::ffff", "78ff:f001:9fc0:20df:8380:b1f1:704:f838");
    }

    #[test]
    fn test_anonymize_ipv6_parcial4() {
        run_key_test("2001:db8::1", "4401:2bc:603f:d91d:27f:ff8e:e6f1:dc1e");
    }

    #[test]
    fn test_anonymize_ipv6_parcial5() {
        run_key_test("2001:db8::2", "4401:2bc:603f:d91d:27f:ff8e:e6f1:dc1c");
    }
}
