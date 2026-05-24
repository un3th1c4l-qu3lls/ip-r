//! IPv4

#[derive(Copy, Clone, Debug)]
pub struct Header {
    pub version: u8,         // 4 bits
    pub ihl: u8,             // 4 bits
    pub type_of_service: u8, // on newer systems, it is divided into 2 other fields.
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,            // 3 bits
    pub fragment_offset: u16, // 13 bits
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_address: u32,
    pub destination_address: u32,
}

impl Header {
    pub const PACKED_SIZE: usize = 20;

    pub fn from_bytes(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < Self::PACKED_SIZE {
            return Err("`Header` is only partial.");
        } // else if raw[0] >> 4 != 4 { return Err("Not an IPv4 header."); }
        Ok(Self {
            version: raw[0] >> 4, // 4 bits
            ihl: raw[0] & 0xF,    // 4 bits
            type_of_service: raw[1],
            total_length: u16::from_be_bytes(raw[2..4].try_into().unwrap()),
            identification: u16::from_be_bytes(raw[4..6].try_into().unwrap()),
            flags: raw[6] >> 5, // 3 bits
            fragment_offset: u16::from_be_bytes(raw[6..8].try_into().unwrap()) & 0x1FFF, // 13 bits
            time_to_live: raw[8],
            protocol: raw[9],
            header_checksum: u16::from_be_bytes(raw[10..12].try_into().unwrap()),
            source_address: u32::from_be_bytes(raw[12..16].try_into().unwrap()),
            destination_address: u32::from_be_bytes(raw[16..20].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::with_capacity(Self::PACKED_SIZE);
        if self.version > 0xF {
            return Err("IPv4 header `version` exceeds capacity.");
        } else if self.ihl > 0xF {
            return Err("`ihl` exceeds capacity.");
        } else if self.flags > 0x6 {
            return Err("`flags` exceed capacity.");
        } else if self.fragment_offset > 0x1FFF {
            return Err("`fragment_offset` exceeds capacity.");
        } // else if self.version != 4 { return Err("IPv4 header `version` mismatch."); }
        out.push((self.version & 0xF) << 4 | (self.ihl & 0xF));
        out.push(self.type_of_service);
        out.extend_from_slice(&self.total_length.to_be_bytes());
        out.extend_from_slice(&self.identification.to_be_bytes());
        out.extend_from_slice(
            &(((self.flags as u16) << 13) | (self.fragment_offset & 0x1FFF)).to_be_bytes(),
        );
        out.push(self.time_to_live);
        out.push(self.protocol);
        out.extend_from_slice(&self.header_checksum.to_be_bytes());
        out.extend_from_slice(&self.source_address.to_be_bytes());
        out.extend_from_slice(&self.destination_address.to_be_bytes());
        Ok(out)
    }

    pub fn control_flags(flags: u8) -> (bool, bool) {
        //! NOTE : Separates `Header.flags` into `(DF, MF)`
        ((flags >> 1) & 0x1 == 1, flags & 0x1 == 1) // Ok()
    }
}

pub fn checksum(words: &[u16]) -> u16 {
    let mut accumulator: u32 = 0;
    for word in words {
        accumulator += *word as u32; // word is a reference, ffs
    }
    while accumulator >> 16 != 0 {
        accumulator = (accumulator & 0xFFFF) + (accumulator >> 16);
    }
    !(accumulator as u16)
}

pub mod option {
    //! IPv4 Option
    pub fn from_bytes(raw: &[u8]) -> Result<(u8, &[u8]), &'static str> {
        if raw.len() < 1 {
            return Err("`option` invalid.");
        }
        let option: (u8, &[u8]) = match raw[0] {
            0 | 1 => (raw[0], &[]),
            _ => {
                if raw.len() < 2 {
                    return Err("`option` missing length byte.");
                }
                let option_length = raw[1];
                if raw.len() < option_length as usize {
                    return Err("`option` only partial.");
                }
                let option_data = &raw[2..option_length.into()];
                (raw[0], option_data)
            }
        };
        Ok(option)
    }

    pub fn to_bytes(tuple: (u8, &[u8])) -> Result<Vec<u8>, &'static str> {
        if tuple.1.len() > 0xfd {
            return Err("`option` length exceeded.");
        }
        let mut out =
            Vec::with_capacity(tuple.1.len() + if matches!(tuple.0, 0 | 1) { 1 } else { 2 });
        out.push(tuple.0);
        if tuple.0 > 1 {
            out.push(tuple.1.len() as u8 + 2);
            out.extend_from_slice(tuple.1);
        }
        Ok(out)
    }

    pub fn align(options: &mut Vec<(u8, &[u8])>) -> Result<(), &'static str> {
        //! `options` modified to align with double word boundaries. No `Header.ihl` check.
        //! Supposed that `options` ends with `option::eool`.
        let ihl = (*options)
            .iter()
            .try_fold(20usize, |acc, &(option_type, data)| {
                acc.checked_add(data.len() + if matches!(option_type, 0 | 1) { 1 } else { 2 })
            })
            .ok_or("Overflow while computing `ihl` value.")?;
        if ihl % 4 != 0 {
            (*options).resize(
                (*options).len() + (4 - (ihl as usize) % 4),
                self::nop::to_option().unwrap(),
            );
        }
        Ok(())
    }

    pub fn metadata(otype: u8) -> (bool, u8, u8) {
        //! Extracts `otype`'s fields, outputs `(copied, class, number)`.
        (otype >> 7 == 1, (otype >> 6) & 0x3, otype & 0x1f)
    }

    pub mod eool {
        //! End Of Option List
        pub const TYPE: u8 = 0x00;
        pub fn from_option(option: (u8, &[u8])) -> Result<(), &'static str> {
            if option.0 != self::TYPE {
                return Err("`eool` option type mismatch.");
            } else if option.1.len() != 0 {
                return Err("`eool` option data invalid.");
            }
            Ok(())
        }

        pub fn to_option() -> Result<(u8, &'static [u8]), &'static str> {
            Ok((self::TYPE, &[]))
        }
    }

    pub mod nop {
        //! No Operation
        pub const TYPE: u8 = 0x01;
        pub fn from_option(option: (u8, &[u8])) -> Result<(), &'static str> {
            if option.0 != self::TYPE {
                return Err("`nop` option type mismatch.");
            } else if option.1.len() != 0 {
                return Err("`nop` option data invalid.");
            }
            Ok(())
        }

        pub fn to_option() -> Result<(u8, &'static [u8]), &'static str> {
            Ok((self::TYPE, &[]))
        }
    }

    #[deprecated(note = "Obsolete since 1991. Considered historic.")]
    pub mod sec {
        //! Security
        pub const TYPE: u8 = 0x82;
        pub fn from_option<'a>(option: (u8, &'a [u8])) -> Result<(u8, &'a [u8]), &'static str> {
            if option.0 != self::TYPE {
                return Err("`sec` option type mismatch.");
            } else if option.1.len() < 1 {
                return Err("`sec` option data expected at least 1 byte.");
            }

            Ok((option.1[0], &option.1[1..]))
        }

        pub fn to_option(tuple: (u8, &[u8])) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(1 + tuple.1.len());
            out.push(tuple.0);
            out.extend_from_slice(tuple.1);
            Ok((self::TYPE, out))
        }

        pub fn is_continuous(blob: &[u8]) -> bool {
            for i in 0..blob.len() {
                if (blob[i] & 0x1 == 0x0 && i != blob.len() - 1)
                    || (i == blob.len() - 1 && blob[i] & 0x1 == 0x1)
                {
                    return false;
                }
            }
            true
        }
    }

    #[deprecated(note = "Obsolete since 1991. Considered historic.")]
    pub mod esec {
        //! Extended Security
        pub const TYPE: u8 = 0x85;
        pub fn from_option<'a>(option: (u8, &'a [u8])) -> Result<(u8, &'a [u8]), &'static str> {
            if option.0 != self::TYPE {
                return Err("`esec` option type mismatch.");
            } else if option.1.len() < 1 {
                return Err("`esec` option data expected at least 1 byte.");
            }
            Ok((option.1[0], &option.1[1..]))
        }

        pub fn to_option(tuple: (u8, &[u8])) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(1 + tuple.1.len());
            out.push(tuple.0);
            out.extend_from_slice(tuple.1);
            Ok((self::TYPE, out))
        }
    }

    #[deprecated(note = "RFC 7126 deprecated LSR due to security risks.")]
    pub mod lsr {
        //! Loose Source Route
        pub const TYPE: u8 = 0x83;
        pub fn from_option(option: (u8, &[u8])) -> Result<(u8, Vec<u32>), &'static str> {
            if option.0 != self::TYPE {
                return Err("`lsr` option type mismatch.");
            } else if option.1.len() % 4 != 1 {
                return Err("`lsr` option data invalid.");
            }
            let pointer: u8 = option.1[0];
            let mut route: Vec<u32> = Vec::<u32>::with_capacity((option.1.len() - 1) / 4);
            for i in 0..(option.1.len() - 1) / 4 {
                route.push(u32::from_be_bytes(
                    option.1[1 + 4 * i..1 + 4 * (i + 1)].try_into().unwrap(),
                ));
            }
            Ok((pointer, route))
        }

        pub fn to_option(tuple: (u8, Vec<u32>)) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(1 + 4 * tuple.1.len());
            out.push(tuple.0);
            for i in 0..tuple.1.len() {
                out.extend_from_slice(&tuple.1[i].to_be_bytes());
            }
            Ok((self::TYPE, out))
        }
    }

    #[deprecated(note = "RFC 7126 deprecated RR due to security risks.")]
    pub mod rr {
        //! Record Route
        pub const TYPE: u8 = 0x07;
        pub fn from_option(option: (u8, &[u8])) -> Result<(u8, Vec<u32>), &'static str> {
            if option.0 != self::TYPE {
                return Err("`rr` option type mismatch.");
            } else if option.1.len() % 4 != 1 {
                return Err("`rr` option data invalid.");
            }
            let pointer: u8 = option.1[0];
            let mut route: Vec<u32> = Vec::<u32>::with_capacity((option.1.len() - 1) / 4);
            for i in 0..(option.1.len() - 1) / 4 {
                route.push(u32::from_be_bytes(
                    option.1[1 + 4 * i..1 + 4 * (i + 1)].try_into().unwrap(),
                ));
            }
            Ok((pointer, route))
        }

        pub fn to_option(tuple: (u8, Vec<u32>)) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(1 + 4 * tuple.1.len());
            out.push(tuple.0);
            for i in 0..tuple.1.len() {
                out.extend_from_slice(&tuple.1[i].to_be_bytes());
            }
            Ok((self::TYPE, out))
        }
    }

    #[deprecated(note = "RFC 7126 deprecated SSR due to security risks.")]
    pub mod ssr {
        //! Strict Source Route
        pub const TYPE: u8 = 0x89;
        pub fn from_option(option: (u8, &[u8])) -> Result<(u8, Vec<u32>), &'static str> {
            if option.0 != self::TYPE {
                return Err("`ssr` option type mismatch.");
            } else if option.1.len() % 4 != 1 {
                return Err("`ssr` option data invalid.");
            }
            let pointer: u8 = option.1[0];
            let mut route: Vec<u32> = Vec::<u32>::with_capacity((option.1.len() - 1) / 4);
            for i in 0..(option.1.len() - 1) / 4 {
                route.push(u32::from_be_bytes(
                    option.1[1 + 4 * i..1 + 4 * (i + 1)].try_into().unwrap(),
                ));
            }
            Ok((pointer, route))
        }

        pub fn to_option(tuple: (u8, Vec<u32>)) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(1 + 4 * tuple.1.len());
            out.push(tuple.0);
            for i in 0..tuple.1.len() {
                out.extend_from_slice(&tuple.1[i].to_be_bytes());
            }
            Ok((self::TYPE, out))
        }
    }

    pub mod ts {
        //! Internet Timestamp
        pub const TYPE: u8 = 0x44;
        pub fn from_option(option: (u8, &[u8])) -> Result<(u8, u8, u8, Vec<u32>), &'static str> {
            if option.0 != self::TYPE {
                return Err("`ts` option type mismatch.");
            } else if option.1.len() % 4 != 2 {
                return Err("`ts` option data malformed.");
            } else if matches!(option.1[1] & 0xf, 1 | 3) && (option.1.len() / 4) % 2 != 0 {
                return Err("`ts` option data expected 4 byte value pairs.");
            }
            let blocks: Vec<u32> = option.1[2..]
                .chunks_exact(4)
                .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
                .collect();
            Ok((option.1[0], option.1[1] >> 4, option.1[1] & 0xf, blocks))
        }

        pub fn to_option(tuple: (u8, u8, u8, Vec<u32>)) -> Result<(u8, Vec<u8>), &'static str> {
            if tuple.1 > 0xf {
                return Err("`ts` option overflow field expected 4 bit value.");
            } else if tuple.2 > 0xf {
                return Err("`ts` option flag field expected 4 bit value.");
            }
            let mut out = Vec::<u8>::with_capacity(3 + 4 * tuple.3.len());
            out.push(tuple.0);
            out.push((tuple.1 << 4) | tuple.2);
            for block in tuple.3 {
                out.extend_from_slice(&block.to_be_bytes());
            }
            Ok((self::TYPE, out))
        }
    }

    pub mod cipso {
        //! Commercial IP Security Option
        pub const TYPE: u8 = 0x86;
        pub fn from_option<'a>(
            option: (u8, &'a [u8]),
        ) -> Result<(u32, Vec<(u8, &'a [u8])>), &'static str> {
            if option.0 != self::TYPE {
                return Err("`cipso` option type mismatch.");
            } else if option.1.len() < 4 {
                return Err("`cipso` option data expected at least 4 bytes.");
            }
            let doi = u32::from_be_bytes(option.1[..4].try_into().unwrap());
            let mut tags = Vec::<(u8, &'a [u8])>::new();
            let mut data = &option.1[4..];

            while !data.is_empty() {
                if data.len() < 2 {
                    return Err("`cipso` tag array is not valid.");
                }
                let r#type = data[0];
                let len = data[1] as usize;
                if len < 2 {
                    return Err("`cipso` tag length data not valid.");
                }
                if data.len() < len {
                    return Err("`cipso` tag data is incomplete.");
                }
                tags.push((r#type, &data[2..len]));
                data = &data[len..];
            }
            Ok((doi, tags))
        }

        pub fn to_option(tuple: (u32, Vec<(u8, &[u8])>)) -> Result<(u8, Vec<u8>), &'static str> {
            let olen: usize =
                4 + 2 * tuple.1.len() + tuple.1.iter().map(|(_, data)| data.len()).sum::<usize>();
            if tuple.1.iter().any(|(_, data)| data.len() > 0xfd) {
                return Err("`cipso` option tags too long.");
            }
            let mut out = Vec::<u8>::with_capacity(olen);
            out.extend_from_slice(&tuple.0.to_be_bytes());
            for (r#type, data) in tuple.1 {
                out.push(r#type);
                out.push(2 + data.len() as u8);
                out.extend_from_slice(data);
            }
            Ok((self::TYPE, out))
        }
    }

    #[deprecated(note = "RFC 6814 deprecated SID.")]
    pub mod sid {
        //! Stream ID
        pub const TYPE: u8 = 0x88;
        pub fn from_option(option: (u8, &[u8])) -> Result<u16, &'static str> {
            if option.0 != self::TYPE {
                return Err("`sid` option type mismatch.");
            } else if option.1.len() != 2 {
                return Err("`sid` option data expected exactly 2 bytes.");
            }
            Ok(u16::from_be_bytes(option.1[..2].try_into().unwrap()))
        }

        pub fn to_option(stream_id: u16) -> Result<(u8, Vec<u8>), &'static str> {
            Ok((self::TYPE, stream_id.to_be_bytes().to_vec()))
        }
    }

    pub mod rtralt {
        //! Router Alert
        pub const TYPE: u8 = 0x94;
        pub fn from_option(option: (u8, &[u8])) -> Result<u16, &'static str> {
            if option.0 != self::TYPE {
                return Err("`rtralt` option type mismatch.");
            } else if option.1.len() != 2 {
                return Err("`rtralt` option data expected 2 bytes.");
            }
            Ok(u16::from_be_bytes(option.1[..2].try_into().unwrap()))
        }

        pub fn to_option(value: u16) -> Result<(u8, Vec<u8>), &'static str> {
            Ok((self::TYPE, value.to_be_bytes().to_vec()))
        }
    }

    #[deprecated(note = "RFC 6814 obsoleted MTUP.")]
    pub mod mtup {
        //! MTU Probe
        pub const TYPE: u8 = 0x0B;
        pub fn from_option(option: (u8, &[u8])) -> Result<u16, &'static str> {
            if option.0 != self::TYPE {
                return Err("`mtup` option type mismatch.");
            } else if option.1.len() != 2 {
                return Err("`mtup` option data expected exactly 2 bytes.");
            }
            Ok(u16::from_be_bytes(option.1[..2].try_into().unwrap()))
        }

        pub fn to_option(mtu: u16) -> Result<(u8, Vec<u8>), &'static str> {
            Ok((self::TYPE, mtu.to_be_bytes().to_vec()))
        }
    }

    #[deprecated(note = "RFC 6814 obsoleted MTUR.")]
    pub mod mtur {
        //! MTU Reply
        pub const TYPE: u8 = 0x0C;
        pub fn from_option(option: (u8, &[u8])) -> Result<u16, &'static str> {
            if option.0 != self::TYPE {
                return Err("`mtur` option type mismatch.");
            } else if option.1.len() != 2 {
                return Err("`mtur` option data expected exactly 2 bytes.");
            }
            Ok(u16::from_be_bytes(option.1[..2].try_into().unwrap()))
        }

        pub fn to_option(mtu: u16) -> Result<(u8, Vec<u8>), &'static str> {
            Ok((self::TYPE, mtu.to_be_bytes().to_vec()))
        }
    }

    #[deprecated(note = "RFC 6814 deprecated EIP.")]
    pub mod eip {
        //! Extended Internet Protocol
        pub const TYPE: u8 = 0x91;
        pub fn from_option<'a>(option: (u8, &'a [u8])) -> Result<&'a [u8], &'static str> {
            if option.0 != self::TYPE {
                return Err("`eip` option type mismatch.");
            } else if option.1.len() == 0 {
                return Err("`eip` option data cannot be empty");
            }
            Ok(option.1)
        }

        pub fn to_option(extension: &[u8]) -> Result<(u8, &[u8]), &'static str> {
            Ok((self::TYPE, extension))
        }
    }

    #[deprecated(note = "RFC 6814 deprecated TR.")]
    pub mod tr {
        //! Traceroute
        pub const TYPE: u8 = 0x52;
        pub fn from_option(option: (u8, &[u8])) -> Result<(u16, u8, u8, u32), &'static str> {
            if option.0 != self::TYPE {
                return Err("`tr` option type mismatch.");
            } else if option.1.len() != 8 {
                return Err("`tr` option data expected exactly 8 bytes.");
            }
            Ok((
                u16::from_be_bytes(option.1[..2].try_into().unwrap()),
                option.1[2],
                option.1[3],
                u32::from_be_bytes(option.1[4..8].try_into().unwrap()),
            ))
        }

        pub fn to_option(tuple: (u16, u8, u8, u32)) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(8);
            out.extend_from_slice(&tuple.0.to_be_bytes());
            out.push(tuple.1);
            out.push(tuple.2);
            out.extend_from_slice(&tuple.3.to_be_bytes());
            Ok((self::TYPE, out))
        }
    }

    #[deprecated(note = "RFC 6814 deprecated SDB.")]
    pub mod sdb {
        //! Selective Directed Broadcast
        pub const TYPE: u8 = 0x95;
        pub fn from_option(option: (u8, &[u8])) -> Result<Vec<u32>, &'static str> {
            if option.0 != self::TYPE {
                return Err("`sdb` option type mismatch.");
            } else if option.1.len() == 0 {
                return Err("`sdb` option data cannot be empty.");
            } else if option.1.len() % 4 != 0 {
                return Err("`sdb` option data expected 4 bytes boundaries.");
            }
            let addresses: Vec<u32> = option
                .1
                .chunks_exact(4)
                .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
                .collect();
            Ok(addresses)
        }

        pub fn to_option(addresses: &[u32]) -> Result<(u8, Vec<u8>), &'static str> {
            if addresses.len() == 0 {
                return Err("`sdb` option data cannot be empty.");
            } else if addresses.len() > 9 {
                return Err("`sdb` option data supports 9 addresses at most.");
            }
            let mut out = Vec::<u8>::with_capacity(4 * addresses.len());
            for address in addresses {
                out.extend_from_slice(&address.to_be_bytes());
            }
            Ok((self::TYPE, out))
        }
    }

    #[deprecated(note = "RFC 6814 deprecated UMP.")]
    pub mod ump {
        //! Upstream Multicast Packet
        pub const TYPE: u8 = 0x98;
        pub fn from_option(option: (u8, &[u8])) -> Result<u32, &'static str> {
            if option.0 != self::TYPE {
                return Err("`ump` option type mismatch.");
            } else if option.1.len() != 4 {
                return Err("`ump` option data expected exactly 4 bytes.");
            }
            Ok(u32::from_be_bytes(option.1[..4].try_into().unwrap()))
        }

        pub fn to_option(address: u32) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(4);
            out.extend_from_slice(&address.to_be_bytes());
            Ok((self::TYPE, out))
        }
    }

    // RFC 4782
    pub mod qs {
        //! Quick-Start
        pub const TYPE: u8 = 0x19;
        pub fn from_option(option: (u8, &[u8])) -> Result<(u8, u8, u8, u32), &'static str> {
            if option.0 != self::TYPE {
                return Err("`qs` option type mismatch.");
            } else if option.1.len() != 6 {
                return Err("`qs` option data expected exactly 6 bytes.");
            }
            let function: u8 = option.1[0] >> 4;
            let rrr: u8 = option.1[0] & 0xf;
            let ttl: u8 = option.1[1];
            let nonce: u32 = u32::from_be_bytes(option.1[2..].try_into().unwrap()); // bits 1-0 reserved
            Ok((function, rrr, ttl, nonce))
        }

        pub fn to_option(tuple: (u8, u8, u8, u32)) -> Result<(u8, Vec<u8>), &'static str> {
            if tuple.0 > 0xf || tuple.1 > 0xf {
                return Err("`function`/`rrr` expected 4-bit values.");
            }
            let mut out = Vec::<u8>::with_capacity(6);
            out.push((tuple.0 << 4) | tuple.1);
            out.push(tuple.2);
            out.extend_from_slice(&tuple.3.to_be_bytes());
            Ok((self::TYPE, out))
        }

        pub fn bitrate_from_rrr(rrr: u8) -> Result<u32, &'static str> {
            if rrr > 0xf {
                return Err("`rrr` expected 4-bit value.");
            }
            Ok(40000u32 * (1u32 << rrr))
        }
    }

    #[deprecated(note = "RFC 6814 deprecated ADDEXT.")]
    pub mod addext {
        //! Address Extension
        pub const TYPE: u8 = 0x93;
        pub fn from_option(option: (u8, &[u8])) -> Result<(u32, u8, u32, u8), &'static str> {
            if option.0 != self::TYPE {
                return Err("`addext` option type mismatch.");
            } else if option.1.len() != 8 {
                return Err("`addext` option expected exactly 8 bytes.");
            }
            let mut buffer = [0u8; 4];
            buffer[1..4].copy_from_slice(&option.1[..3]);
            let source_ad_ipv7: u32 = u32::from_be_bytes(buffer);
            buffer[1..4].copy_from_slice(&option.1[4..7]);
            let destination_ad_ipv7: u32 = u32::from_be_bytes(buffer);
            Ok((
                source_ad_ipv7,
                option.1[3],
                destination_ad_ipv7,
                option.1[7],
            ))
        }

        pub fn to_option(tuple: (u32, u8, u32, u8)) -> Result<(u8, Vec<u8>), &'static str> {
            if tuple.0 > 0xffffff || tuple.2 > 0xffffff {
                return Err("`AD IPv7` is only 24-bits long.");
            }
            let mut out = Vec::<u8>::with_capacity(8);
            out.extend_from_slice(&tuple.0.to_be_bytes()[1..]);
            out.push(tuple.1);
            out.extend_from_slice(&tuple.2.to_be_bytes()[1..]);
            out.push(tuple.3);
            Ok((self::TYPE, out))
        }
    }

    // RFC 6814 (ZSU, FINN, ENCODE, VISA, IMITD, DPS) - "No other reference information has been found."
    pub mod zsu {
        // ZSu
        //! Experimental Measurement
        pub const TYPE: u8 = 0x0A;
        pub fn from_option(option: (u8, &[u8])) -> Result<&[u8], &'static str> {
            if option.0 != self::TYPE {
                return Err("`zsu` option type mismatch.");
            } else if option.1.len() == 0 {
                return Err("`zsu` option data cannot be empty.");
            }
            Ok(option.1)
        }

        pub fn to_option(blob: &[u8]) -> Result<(u8, &[u8]), &'static str> {
            if blob.len() == 0 {
                return Err("`zsu` option data cannot be empty.");
            }
            Ok((self::TYPE, blob))
        }
    }

    // Greg_Finn
    pub mod finn {
        //! Experimental Flow Control
        pub const TYPE: u8 = 0xCD;
        pub fn from_option(option: (u8, &[u8])) -> Result<&[u8], &'static str> {
            if option.0 != self::TYPE {
                return Err("`finn` option type mismatch.");
            } else if option.1.len() == 0 {
                return Err("`finn` option data cannot be empty.");
            }
            Ok(option.1)
        }

        pub fn to_option(blob: &[u8]) -> Result<(u8, &[u8]), &'static str> {
            if blob.len() == 0 {
                return Err("`finn` option data cannot be empty.");
            }
            Ok((self::TYPE, blob))
        }
    }

    // Deborah_Estrin
    #[deprecated(note = "RFC 6814 deprecated VISA.")]
    pub mod visa {
        //! Experimental Access Control
        pub const TYPE: u8 = 0x8E;
        pub fn from_option(option: (u8, &[u8])) -> Result<&[u8], &'static str> {
            if option.0 != self::TYPE {
                return Err("`visa` option type mismatch.");
            } else if option.1.len() == 0 {
                return Err("`visa` option data cannot be empty.");
            }
            Ok(option.1)
        }

        pub fn to_option(blob: &[u8]) -> Result<(u8, &[u8]), &'static str> {
            if blob.len() == 0 {
                return Err("`visa` option data cannot be empty.");
            }
            Ok((self::TYPE, blob))
        }
    }

    // VerSteeg
    #[deprecated(note = "RFC 6814 deprecated ENCODE.")]
    pub mod encode {
        //! ENCODE
        pub const TYPE: u8 = 0x0F;
        pub fn from_option(option: (u8, &[u8])) -> Result<&[u8], &'static str> {
            if option.0 != self::TYPE {
                return Err("`encode` option type mismatch.");
            } else if option.1.len() == 0 {
                return Err("`encode` option data cannot be empty.");
            }
            Ok(option.1)
        }

        pub fn to_option(blob: &[u8]) -> Result<(u8, &[u8]), &'static str> {
            if blob.len() == 0 {
                return Err("`encode` option data cannot be empty.");
            }
            Ok((self::TYPE, blob))
        }
    }

    // Lee
    pub mod imitd {
        //! IMI Traffic Descriptor
        pub const TYPE: u8 = 0x90;
        pub fn from_option(option: (u8, &[u8])) -> Result<&[u8], &'static str> {
            if option.0 != self::TYPE {
                return Err("`imitd` option type mismatch.");
            } else if option.1.len() == 0 {
                return Err("`imitd` option data cannot be empty.");
            }
            Ok(option.1)
        }

        pub fn to_option(blob: &[u8]) -> Result<(u8, &[u8]), &'static str> {
            if blob.len() == 0 {
                return Err("`imitd` option data cannot be empty.");
            }
            Ok((self::TYPE, blob))
        }
    }

    // Andy_Malis
    #[deprecated(note = "RFC 6814 deprecated DPS.")]
    pub mod dps {
        //! Dynamic Packet State
        pub const TYPE: u8 = 0x97;
        pub fn from_option(option: (u8, &[u8])) -> Result<&[u8], &'static str> {
            if option.0 != self::TYPE {
                return Err("`dps` option type mismatch.");
            } else if option.1.len() == 0 {
                return Err("`dps` option data cannot be empty.");
            }
            Ok(option.1)
        }

        pub fn to_option(blob: &[u8]) -> Result<(u8, &[u8]), &'static str> {
            if blob.len() == 0 {
                return Err("`dps` option data cannot be empty.");
            }
            Ok((self::TYPE, blob))
        }
    }

    // RFC 4727 - 0x1E, 0x5E, 0x9E, 0xDE - Experimental
}

pub mod datagram {
    //! IPv4 Datagram
    pub fn from_bytes(
        raw: &[u8],
    ) -> Result<(super::Header, Vec<(u8, &[u8])>, &[u8]), &'static str> {
        let header = super::Header::from_bytes(raw)?;
        if raw.len() < header.total_length as usize {
            return Err("`datagram` only partial.");
        }
        let data = &raw[4 * (header.ihl as usize)..header.total_length as usize];
        let mut options = Vec::<(u8, &[u8])>::new();
        let mut buffer = &raw[super::Header::PACKED_SIZE..4 * (header.ihl as usize)];
        loop {
            let option = super::option::from_bytes(buffer)?;
            options.push(option);
            let offset = match option.0 {
                0 | 1 => 1,
                _ => 2,
            };
            buffer = &buffer[option.1.len() + offset..];
            if option.0 == 0 {
                break;
            } else if buffer.is_empty() {
                return Err("`datagram` options not terminated.");
            }
        }
        Ok((header, options, data))
    }

    pub fn to_bytes(
        mut tuple: (super::Header, Vec<(u8, &[u8])>, &[u8]),
    ) -> Result<Vec<u8>, &'static str> {
        //! `options` (`tuple.1`) needs to be aligned, `Header.fragment_offset` kept as is.
        let ihl = tuple
            .1
            .iter()
            .try_fold(20usize, |acc, &(option_type, data)| {
                acc.checked_add(data.len() + if matches!(option_type, 0 | 1) { 1 } else { 2 })
            })
            .ok_or("Overflow while computing `ihl` value.")?
            / 4;
        tuple.0.ihl = u8::try_from(ihl).map_err(|_| "`ihl` cannot be cast to `u8`.")?;
        tuple.0.header_checksum = 0;
        let total_length = (4 * ihl)
            .checked_add(tuple.2.len())
            .ok_or("Overflow while computing `total_length` value.")?;
        tuple.0.total_length =
            u16::try_from(total_length).map_err(|_| "`total_length` exceeds word capacity.")?;
        let mut out = Vec::<u8>::with_capacity(total_length);
        out.append(&mut tuple.0.to_bytes()?);
        for option in tuple.1 {
            out.push(option.0);
            if option.0 > 1 {
                out.push(
                    u8::try_from(option.1.len() + 2).map_err(|_| "option `length` exceeded.")?,
                );
                out.extend_from_slice(option.1);
            }
        }
        let checksum = super::checksum(
            out[..4 * ihl]
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<u16>>()
                .as_slice(),
        );
        tuple.0.header_checksum = checksum;
        out[10] = (checksum >> 8) as u8;
        out[11] = (checksum & 0xff) as u8;
        out.extend_from_slice(tuple.2);
        Ok(out)
    }

    pub fn fragment<'a>(
        tuple: &mut (super::Header, Vec<(u8, &'a [u8])>, &'a [u8]),
        mtu: u16,
    ) -> Result<Option<(super::Header, Vec<(u8, &'a [u8])>, &'a [u8])>, &'static str> {
        //! `options` (`tuple.1`) needs to be aligned, `Header.fragment_offset` kept as is (initial value `0`).
        //! If another `datagram` created, returned as value, else `None`.
        //! Input `datagram` modified, sanitize output by calling `options::align()` and `datagram::to_be_bytes()`.
        //! Only the first `datagram` of `mtu` size, call on new again to fragment entirely.
        if (*tuple).0.total_length <= mtu {
            return Ok(None);
        } else if super::Header::control_flags((*tuple).0.flags).0 {
            return Err("`Header.flags`' DF = 1 : can't be fragmented.");
        }

        let nfb: u16 = mtu
            .checked_sub(4 * (tuple.0.ihl as u16))
            .ok_or("MTU too small to fit IPv4 header.")?
            / 8;
        if nfb == 0 {
            return Err("IPv4 datagram empty.");
        }
        (*tuple).0.flags = 0x1; // MF == 1
        (*tuple).0.total_length = ((*tuple).0.ihl as u16) * 4 + nfb * 8;

        let mut options = Vec::<(u8, &[u8])>::with_capacity(tuple.1.len());
        for option in &tuple.1 {
            if super::option::metadata((*option).0).0 {
                options.push(*option);
            }
        }
        let mut out: (super::Header, Vec<(u8, &[u8])>, &[u8]) =
            ((*tuple).0, options, &(*tuple).2[(nfb as usize) * 8..]);
        out.0.flags = 0; // indicates last fragment
        out.0.fragment_offset += nfb;
        tuple.2 = &tuple.2[..8 * (nfb as usize)];

        Ok(Some(out))
    }
}

pub mod net_addr {
    //! Internet Address
    pub fn from_str(mut cidr_block: &str) -> Result<(u32, u32), &'static str> {
        //! NOTE : Takes `cidr_block` (Classless Inter-Domain Routing), outputs adress and subnet mask.
        cidr_block = cidr_block.trim();
        let mut parts: Vec<&str> = cidr_block.split("/").collect();
        if parts.len() > 2 || parts.is_empty() {
            return Err("`cidr_block` not a valid CIDR block.");
        }

        // Subnet mask.
        let prefix: u8 = if parts.len() == 2 {
            parts[1]
                .parse::<u8>()
                .map_err(|_| "`prefix` bigger than `u8::MAX`.")?
        } else {
            32
        };
        if prefix > 32 {
            return Err("`prefix` range exceeded.");
        }

        // IP address.
        let mut ip_address: u32 = 0;
        parts = parts[0].split(".").collect();
        if parts.len() != 4 {
            return Err("IPv4 address malformed.");
        }
        for (i, part) in parts.iter().enumerate() {
            ip_address |= (part
                .parse::<u8>()
                .map_err(|_| "`part` bigger than `u8::MAX`.")? as u32)
                << (24 - 8 * i);
        }

        Ok((
            ip_address,
            if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            },
        ))
    }

    pub fn to_str(net_addr: (u32, u32)) -> Result<String, &'static str> {
        let prefix: u8 = net_addr.1.leading_ones() as u8;
        if net_addr.1
            != (if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            })
        {
            return Err("Non contiguous masks are deprecated.");
        }

        Ok(format!(
            "{}.{}.{}.{}{}",
            net_addr.0 >> 24,
            (net_addr.0 >> 16) & 0xff,
            (net_addr.0 >> 8) & 0xff,
            net_addr.0 & 0xff,
            if prefix != 32 {
                format!("/{}", prefix)
            } else {
                String::new()
            }
        ))
    }

    pub fn subnet(net_addr: (u32, u32)) -> u32 {
        //! subnet address : ip_address & subnet_mask
        net_addr.0 & net_addr.1
    }

    pub fn host(net_addr: (u32, u32)) -> u32 {
        //! host : ip_address & !subnet_mask
        net_addr.0 & !net_addr.1
    }

    pub fn broadcast(net_addr: (u32, u32)) -> u32 {
        //! broadcast address : ip_address | !subnet_mask
        net_addr.0 | !net_addr.1
    }
}
