#![allow(dead_code)]
#![allow(unused_variables)]

#[derive(Copy, Clone, Debug)]
pub struct Header {
	pub version: u8, // 4 bits
	pub ihl: u8, // 4 bits
	pub type_of_service: u8,
	pub total_length: u16,
	pub identification: u16,
	pub flags: u8, // 3 bits
	pub fragment_offset: u16, // 13 bits
	pub time_to_live: u8,
	pub protocol: u8,
	pub header_checksum: u16,
	pub source_address: u32,
	pub destination_address: u32
}

impl Header {
	pub const PACKED_SIZE: usize = 20;
	
	pub fn from_bytes(raw: &[u8]) -> Result<Self, &'static str> {
		if raw.len() < Self::PACKED_SIZE {
			return Err("`Header` is only partial.");
		} else if raw[0] >> 4 != 4 {
			return Err("Not an IPv4 header.");
		}
		Ok(Self {
			version: raw[0] >> 4, // 4 bits
			ihl: raw[0] & 0xF, // 4 bits
			type_of_service: raw[1],
			total_length: u16::from_be_bytes(raw[2..4].try_into().unwrap()),
			identification: u16::from_be_bytes(raw[4..6].try_into().unwrap()),
			flags: raw[6] >> 5, // 3 bits
			fragment_offset: u16::from_be_bytes(raw[6..8].try_into().unwrap()) & 0x1FFF, // 13 bits
			time_to_live: raw[8],
			protocol: raw[9],
			header_checksum: u16::from_be_bytes(raw[10..12].try_into().unwrap()),
			source_address: u32::from_be_bytes(raw[12..16].try_into().unwrap()),
			destination_address: u32::from_be_bytes(raw[16..20].try_into().unwrap())
		})
	}
	
	
	pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
		let mut out = Vec::with_capacity(Self::PACKED_SIZE);
		if self.version > 0xF || self.version != 4 {
			return Err("IPv4 header `version` should be 4.");
		} else if self.ihl > 0xF {
			return Err("`ihl` exceeds capacity.");
		} else if self.flags > 0x6 {
			return Err("`flags` exceed capacity.");
		} else if self.fragment_offset > 0x1FFF {
			return Err("`fragment_offset` exceeds capacity.");
		}
		out.push((self.version & 0xF) << 4 | (self.ihl & 0xF));
		out.push(self.type_of_service);
		out.extend_from_slice(&self.total_length.to_be_bytes());
		out.extend_from_slice(&self.identification.to_be_bytes());
		out.extend_from_slice(&(((self.flags as u16) << 13) | (self.fragment_offset & 0x1FFF)).to_be_bytes());
		out.push(self.time_to_live);
		out.push(self.protocol);
		out.extend_from_slice(&self.header_checksum.to_be_bytes());
		out.extend_from_slice(&self.source_address.to_be_bytes());
		out.extend_from_slice(&self.destination_address.to_be_bytes());
		Ok(out)
	}
	
	
	pub fn control_flags(flags: u8) -> (bool, bool) { // Result<(bool, bool), &'static str> {
		//! NOTE : Separates `Header.flags` into `(DF, MF)`
		// if flags > 3 {
			// return Err("`flags` uses reserved bits.");
		// }
		((flags >> 1) & 0x1 == 1, flags & 0x1 == 1) // Ok()
	}
}




/*
TODO : add parsing options data
*/

/*
eol, nop, sec, lsr, ssr, rr, sid, ts





*/




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
	pub fn from_bytes(raw: &[u8]) -> Result<(u8, &[u8]), &'static str> {
		if raw.len() < 1 {
			return Err("");
		}
		let option: (u8, &[u8]) = match raw[0] {
			0 | 1 => (raw[0], &[]),
			_ => {
				if raw.len() < 2 {
					return Err("");
				}
				let option_length = raw[1];
				if raw.len() < option_length as usize {
					return Err("");
				}
				let option_data = &raw[2..option_length.into()];
				(raw[0], option_data)
			},
		};
		Ok(option)
	}
	
	pub fn to_bytes(tuple: (u8, &[u8])) -> Result<Vec<u8>, &'static str> {
		if tuple.1.len() > 0xfd {
			return Err("`option` length exceeded.");
		}
		let mut out = Vec::with_capacity(tuple.1.len() + if matches!(tuple.0, 0 | 1) {1} else {2});
		out.push(tuple.0);
		if tuple.0 > 1 {
			out.push(tuple.1.len() as u8 + 2);
			out.extend_from_slice(tuple.1);
		}
		Ok(out)
	}
	
	pub fn align(options: &mut Vec<(u8, &[u8])>) -> Result<(), &'static str> {
		//! NOTE : It ensures the passed `options` will end on dword boundaries, doesn't check for `ihl` value.
		let ihl = (*options).iter().try_fold(20usize, |acc, &(option_type, data)| acc.checked_add(data.len() + if matches!(option_type, 0 | 1) {1} else {2})).ok_or("Overflow while computing `ihl` value.")?;
		if ihl % 4 != 0 {
			(*options).resize((*options).len() + (4 - (ihl as usize) % 4), (0, &[]));
		}
		Ok(())
	}
	
	
	pub fn extract_fields(option_type: u8) -> (bool, u8, u8) {
		//! NOTE : Extract `option_type`'s fields, outputs `(copied, class, number)`.
		(option_type >> 7 == 1, (option_type >> 6) & 0x3, option_type & 0x1f)
	}

}



pub mod datagram {
	pub fn from_bytes(raw: &[u8]) -> Result<(super::Header, Vec<(u8, &[u8])>, &[u8]), &'static str> {
		let header = super::Header::from_bytes(raw)?;
		if raw.len() < header.total_length as usize {
			return Err("datagram is only partial.");
		}
		let data = &raw[4 * (header.ihl as usize)..header.total_length as usize];
		let mut options = Vec::<(u8, &[u8])>::new();
		let mut buffer = &raw[super::Header::PACKED_SIZE..4 * (header.ihl as usize)];
		while !buffer.is_empty() {
			let option = super::option::from_bytes(buffer)?;
			options.push(option);
			let offset = match option.0 {
				0 | 1 => 1,
				_ => 2
			};
			buffer = &buffer[option.1.len() + offset..];
		}
		Ok((header, options, data))
	}
	
	pub fn to_bytes(mut tuple: (super::Header, Vec<(u8, &[u8])>, &[u8])) -> Result<Vec<u8>, &'static str> {
		//! NOTE : The user has to ensure the options are aligned with `option::align` and correct value for `Header.fragment_offset`.
		let ihl = tuple.1.iter().try_fold(20usize, |acc, &(option_type, data)| acc.checked_add(data.len() + if matches!(option_type, 0 | 1) {1} else {2})).ok_or("Overflow while computing `ihl` value.")? / 4;
		tuple.0.ihl = u8::try_from(ihl).map_err(|_| "`ihl` cannot be cast to `u8`.")?; // Should we pAN_ic ?
		tuple.0.header_checksum = 0;
		let total_length = (4 * ihl).checked_add(tuple.2.len()).ok_or("Overflow while computing `total_length` value.")?;
		tuple.0.total_length = u16::try_from(total_length).map_err(|_| "`total_length` exceeds word capacity.")?;
		let mut out = Vec::<u8>::with_capacity(total_length);
		out.append(&mut tuple.0.to_bytes()?);
		for option in tuple.1 {
			out.push(option.0);
			if option.0 > 1 {
				out.push(u8::try_from(option.1.len() + 2).map_err(|_| "option `length` exceeded.")?);
				out.extend_from_slice(option.1);
			}
		}
		let checksum = super::checksum(out[..4 * ihl].chunks_exact(2).map(|chunk| u16::from_be_bytes(chunk.try_into().unwrap())).collect::<Vec<u16>>().as_slice());
		tuple.0.header_checksum = checksum;
		out[10] = (checksum >> 8) as u8;
		out[11] = (checksum & 0xff) as u8;
		out.extend_from_slice(tuple.2);
		Ok(out)
	}
	
	
	pub fn fragment<'a>(tuple: &mut (super::Header, Vec<(u8, &'a [u8])>, &'a [u8]), mtu: u16) -> Result<Option<(super::Header, Vec<(u8, &'a [u8])>, &'a [u8])>, &'static str> {
		//! NOTE : The user has to ensure the options are aligned with `option::align`. Datagram already valid (through a call to `to_bytes` for instance, to set header fields).
		if (*tuple).0.total_length <= mtu {
			return Ok(None);
		} else if super::Header::control_flags((*tuple).0.flags).0 {
			return Err("`Header.flags`' DF = 1 : can't be fragmented.");
		}
		
		let nfb: u16 = mtu.checked_sub(4 * (tuple.0.ihl as u16)).ok_or("MTU too small to fit IPv4 header.")? / 8;
		if nfb == 0 {
			return Err("IPv4 datagram empty.");
		}
		(*tuple).0.flags = 0x1; // MF == 1
		(*tuple).0.total_length = ((*tuple).0.ihl as u16) * 4 + nfb * 8;
		
		let mut options = Vec::<(u8, &[u8])>::with_capacity(tuple.1.len());
		for option in &tuple.1 {
			if super::option::extract_fields((*option).0).0 {
				options.push(*option);
			}
		}
		let mut out: (super::Header, Vec<(u8, &[u8])>, &[u8]) = ((*tuple).0, options, &(*tuple).2[(nfb as usize) * 8..]);
		out.0.flags = 0; // indicates last fragment
		out.0.fragment_offset += nfb;
		tuple.2 = &tuple.2[..8 * (nfb as usize)];

		Ok(Some(out)) // !User must call `option::align` and `datagram::to_bytes` to correctly update the second datagram fields.
	}
}


pub mod net_addr {
	pub fn from_str(cidr_block: &str) -> Result<(u32, u32), &'static str> {
		//! NOTE : Takes `cidr_block` (Classless Inter-Domain Routing), outputs adress and subnet mask.
		
		let parts: Vec<&str> = cidr_block.split("/").collect();
		if parts.len() > 2 || parts.is_empty() {
			return Err("`cidr_block` not a valid CIDR block.");
		}
		
		// Subnet mask.
		let prefix: u8 = if parts.len() == 2 {parts[1].parse::<u8>().map_err(|_| "`prefix` bigger than `u8::MAX`.")?} else {32};
		if prefix > 32 {
			return Err("`prefix` range exceeded.");
		}
		
		// IP address.
		let mut ip_address: u32 = 0;
		for (i, part) in parts[0].split(".").enumerate() {
			ip_address |= (part.parse::<u8>().map_err(|_| "`part` bigger than `u8::MAX`.")? as u32) << (24 - 8 * i);
		}
		
		Ok((ip_address, if prefix == 0 {0} else {u32::MAX << (32 - prefix)}))
	}
	
	
	pub fn to_str(net_addr: (u32, u32)) -> Result<String, &'static str> {
		
		let prefix: u8 = net_addr.1.leading_ones() as u8;
		if net_addr.1 != (if prefix == 0 {0} else {u32::MAX << (32 - prefix)}) {
			return Err("Non contiguous masks are deprecated.");
		}
		
		Ok(format!("{}.{}.{}.{}{}", net_addr.0 >> 24, (net_addr.0 >> 16) & 0xff, (net_addr.0 >> 8) & 0xff, net_addr.0 & 0xff, if prefix != 32 {format!("/{}", prefix)} else {String::new()}))
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




// for options.
	// mod eol {
		// fn from_bytes(raw: &[u8]) -> Result<(u8, &[u8]), &'static str> {
			// check if first byte is actually a eol
			// then return 
			// Ok((0, &[]))
		// }
		
		// fn to_bytes() -> Vec<u8> {
			// let out = Vec::<u8>::new();
			
			// out
		// }
	// }
	
	/*
	
	Copy	Class	Number	Value	Option Name	Description
0	0	0	0	EOOL	End of Options List
0	0	1	1	NOP	No Operation
1	0	2	130	SEC	Security
1	0	3	131	LSR	Loose Source Route
0	2	4	68	TS	Time Stamp
1	0	5	133	E-SEC	Extended Security
1	0	6	134	CIPSO	Commercial Security
0	0	7	7	RR	Record Route
1	0	8	136	SID	Stream ID
1	0	9	137	SSR	Strict Source Route
0	0	10	10	ZSU	Experimental Measurement
0	0	11	11	MTUP	MTU Probe
0	0	12	12	MTUR	MTU Reply
1	2	13	205	FINN	Experimental Flow Control
1	0	14	142	VISA	Experimental Access Control
0	0	15	15	ENCODE	ENCODE (status unknown)
1	0	16	144	IMITD	IMI Traffic Descriptor
1	0	17	145	EIP	Extended Internet Protocol
0	2	18	82	TR	Traceroute
1	0	19	147	ADDEXT	Address Extension
1	0	20	148	RTRALT	Router Alert
1	0	21	149	SDB	Selective Directed Broadcast
1	0	22	150	NSAPA	NSAP Addresses
1	0	23	151	DPS	Dynamic Packet State
1	0	24	152	UMP	Upstream Multicast Packet
0	0	25	25	QS	Quick-Start
0	0	30	30	EXP	RFC3692-style Experiment
0	2	30	94	EXP	RFC3692-style Experiment
1	0	30	158	EXP	RFC3692-style Experiment
1	2	30	222	EXP	RFC3692-style Experiment

These options are not formally deprecated by the IETF and serve a specific purpose, but they are not guaranteed to pass through the Internet.
Option (Value)	Modern Usage & Status	Behavior
End of Options List (0)	Active, fundamental	Marks the end of the options list; all implementations must support it.
No Operation (1)	Active, fundamental	Used for padding; all implementations must support it.
Router Alert (148)	Actively Used (but often blocked)	Signals routers to inspect the packet (e.g., for RSVP, IGMP). Many networks drop these packets for security reasons.
Timestamp (68)	Not deprecated, but practically dead	Records timestamps from routers. It is rarely implemented in modern routers and is often blocked by firewalls.
⚠️ Officially Deprecated & Obsolete

The following options have been formally deprecated by RFC 6814 (2012) and should not be used. Some have been obsolete since as early as RFC 1122 (1989).

    136 - Stream ID (SID)

    142 - VISA (Experimental Access Control)

    15 - ENCODE

    145 - Extended Internet Protocol (EIP)

    82 - Traceroute (TR)

    147 - Address Extension (ADDEXT)

    149 - Selective Directed Broadcast (SDB)

    151 - Dynamic Packet State (DPS)

    152 - Upstream Multicast Packet (UMP)


	*/