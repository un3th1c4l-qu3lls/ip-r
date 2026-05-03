#![allow(dead_code)]
#![allow(unused_variables)]

struct Header {
	version: u8, // 4-bits
	traffic_class: u8, // 8-bits
	flow_label: u32, // 20-bits
	payload_length: u16,
	next_header: u8,
	hop_limit: u8,
	source_address: u128,
	destination_address: u128
}

impl Header {
	pub const PACKED_SIZE: usize = 40;
	
	fn from_bytes(raw: &[u8]) -> Result<Self, &'static str> {
		if raw.len() < Self::PACKED_SIZE {
			return Err("`Header` is only partial.");
		} else if raw[0] >> 4 != 6 {
			return Err("Not an IPv6 header.");
		}
		Ok(Self {
			version: raw[0] >> 4,
			traffic_class: ((raw[0] & 0xf) << 4) | (raw[1] >> 4),
			flow_label: ((raw[1] & 0xf) as u32) << 16 | (u16::from_be_bytes(raw[2..4].try_into().unwrap()) as u32),
			payload_length: u16::from_be_bytes(raw[4..6].try_into().unwrap()),
			next_header: raw[6],
			hop_limit: raw[7],
			source_address: u128::from_be_bytes(raw[8..24].try_into().unwrap()),
			destination_address: u128::from_be_bytes(raw[24..40].try_into().unwrap())
		})
	}
	
	fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
		if self.version != 6 {
			return Err("Incoherent"); // Version overflow ?
		} else if self.flow_label > 0xfffff {
			return Err(""); // flow label overflow ?
		}
		let mut out = Vec::with_capacity(Self::PACKED_SIZE);
		out.push((self.version << 4) | (self.traffic_class >> 4));
		out.push(((self.traffic_class & 0xf) << 4) | ((self.flow_label >> 16) as u8));
		out.extend_from_slice(&((self.flow_label & 0xffff) as u16).to_be_bytes());
		out.extend_from_slice(&self.payload_length.to_be_bytes());
		out.push(self.next_header);
		out.push(self.hop_limit);
		out.extend_from_slice(&self.source_address.to_be_bytes());
		out.extend_from_slice(&self.destination_address.to_be_bytes());
		Ok(out)
	}
}


/*
      IPv6 header
      Hop-by-Hop Options header
      Destination Options header (note 1)
      Routing header
      Fragment header
      Authentication header (note 2)
      Encapsulating Security Payload header (note 2)
      Destination Options header (note 3)
      Upper-Layer header
*/





mod extension {
	
	
	// Hop-by-Hop Options Header => 0
	// Routing Header => 43
	// Fragment Header => 44
	// Destination Options Header (Next Header = 60)
	// Authentication Header (AH) (Next Header = 51)
	// Mobility Header (Next Header = 135)
	
	
	fn from_bytes(raw: &[u8]) -> Result<(u8, &[u8]), &'static str> { //! size => 2 + tuple.1.len()
		if raw.len() < 0x8 {
			return Err(""); // Must be 8 bytes aligned, so least is 8 bytes, or 0, but then the function shouldnt be called.
		}
		let next_header = raw[0];
		let header_extension_length = raw[1];
		if raw.len() < 8 * (header_extension_length as usize + 1) {
			return Err("");
		}
		Ok((next_header, &raw[2..8 * (header_extension_length as usize + 1)]))
	}
	
	fn to_bytes(tuple: (u8, &[u8])) -> Result<Vec<u8>, &'static str> {
		if tuple.1.len() > 0x7fe {
			return Err(""); // Too much extension data.
		} else if tuple.1.len() % 8 != 6 {
			return Err(""); // Data must be 8-byte aligned.
		}
		let mut out = Vec::with_capacity(2 + tuple.1.len());
		out.push(tuple.0);
		out.push(((tuple.1.len() + 2) / 8 - 1) as u8);
		out.extend_from_slice(tuple.1);
		Ok(out)
	}
	
	
	/*
	Should add companion functions to like treat the different header types.
	To basically build the data field of specific option types.
	*/
	
	
	
	
	
	mod option { //! type (u8) : data_length (u8) : data (&[u8])
		fn from_bytes(raw: &[u8]) -> Result<(u8, &[u8]), &'static str> {
			if raw.len() < 1 {
				return Err("");
			}
			let option_type = raw[0];
			if option_type == 0 {
				return Ok((option_type, &[]));
			} else if raw.len() < 2 {
				return Err("");
			}
			let option_data_length = raw[1];
			if raw.len() < 2 + option_data_length as usize {
				return Err("");
			}
			Ok((option_type, &raw[2..option_data_length as usize + 2]))
		}
		
		
		fn to_bytes(tuple: (u8, &[u8])) -> Result<Vec<u8>, &'static str> {
			if tuple.1.len() > 0xff {
				return Err(""); // option data is too long
			}
			let mut out = Vec::with_capacity(2 + tuple.1.len());
			out.push(tuple.0);
			out.push(tuple.1.len().try_into().unwrap());
			out.extend_from_slice(tuple.1);
			Ok(out)
		}
		
		
		fn pad1() -> Vec<u8> {
			vec![0]
		}
		
		
		fn padn(n: u8) -> Result<Vec<u8>, &'static str> {
			if n < 2 {
				return Err(""); // option data would be too long
			}
			let mut out = vec![0; n.into()];
			out[0] = 1;
			out[1] = n - 2;
			Ok(out)
		}
		
		
		/**!
		00 - skip over this option and continue processing the header.
		01 - discard the packet.
		10 - discard the packet and, regardless of whether or not the
			packet's Destination Address was a multicast address, send an
			ICMP Parameter Problem, Code 2, message to the packet's
			Source Address, pointing to the unrecognized Option Type.
		11 - discard the packet and, only if the packet's Destination
			Address was not a multicast address, send an ICMP Parameter
			Problem, Code 2, message to the packet's Source Address,
			pointing to the unrecognized Option Type.
		*/
		fn behavior(option_type: u8) -> u8 {
			option_type >> 6
		}
		
		
		/**!
		0 - Option Data does not change en route
		1 - Option Data may change en route
		*/
		fn change(option_type: u8) -> bool {
			((option_type >> 5) & 0b001) != 0
		}
	}
	
	
	
	
}


mod datagram {
	
	fn from_bytes(raw: &[u8]) -> Result<(super::Header, Vec<(u8, &[u8])>, &[u8]), &'static str> {
		
		Err("Not implemented you fuck.")
	}
	
	fn to_bytes(tuple: (super::Header, Vec<(u8, &[u8])>, &[u8])) -> Result<Vec<u8>, &'static str> {
		
		Err("Not implemented fucks.")
	}
}


mod net_addr {
	
}







/*
=> create / parse packet from a buffer and return its components (ie. Header and extensions (as basically a Vec<> then said data))
=> add support for different option_types (i.e. parsing and building such options only the data, and the padding for instance).
=> add support for specific extensions.
=> add net_addr module.s
*/




/*

/*
Recommended orer of extension headers.
      IPv6 header
      Hop-by-Hop Options header
      Destination Options header (note 1)
      Routing header
      Fragment header
      Authentication header (note 2)
      Encapsulating Security Payload header (note 2)
      Destination Options header (note 3)
      Upper-Layer header

*/

*/
