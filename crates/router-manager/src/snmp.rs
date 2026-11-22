//! Minimal SNMP v2c GET client implemented directly on top of UDP + BER.
//!
//! Supports only the four OIDs used by the router manager. It is intentionally
//! narrow: no walks, no v3, no SETs.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

pub const OID_SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
pub const OID_SYS_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";
pub const OID_SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
pub const OID_SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpInfo {
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
    pub sys_name: Option<String>,
    pub sys_uptime_ticks: Option<u64>,
}

pub async fn query(ip: IpAddr, community: &str, timeout: Duration) -> Result<SnmpInfo> {
    let oids = [OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_UPTIME, OID_SYS_NAME];
    let request = build_get_request(0x4e5443, community, &oids)?;

    let bind: SocketAddr = if ip.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).await.context("bind SNMP UDP socket")?;
    socket
        .send_to(&request, SocketAddr::new(ip, 161))
        .await
        .with_context(|| format!("send SNMP GET to {ip}"))?;

    let mut buf = [0u8; 4096];
    let (n, _src) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .context("SNMP recv timeout")??;
    let response = &buf[..n];

    parse_get_response(response)
}

fn build_get_request(request_id: u32, community: &str, oids: &[&str]) -> Result<Vec<u8>> {
    let mut varbinds = Vec::new();
    for oid in oids {
        let oid_tlv = encode_oid(oid)?;
        let null = tlv(0x05, &[]);
        let mut vb = Vec::new();
        vb.extend(oid_tlv);
        vb.extend(null);
        varbinds.push(tlv(0x30, &vb));
    }
    let varbind_list = tlv(0x30, &varbinds.concat());

    let mut pdu_body = Vec::new();
    pdu_body.extend(encode_int(request_id as i64));
    pdu_body.extend(encode_int(0));
    pdu_body.extend(encode_int(0));
    pdu_body.extend(varbind_list);
    let pdu = tlv(0xA0, &pdu_body); // A0 = GetRequest

    let mut msg_body = Vec::new();
    msg_body.extend(encode_int(1)); // SNMPv2c
    msg_body.extend(tlv(0x04, community.as_bytes()));
    msg_body.extend(pdu);

    Ok(tlv(0x30, &msg_body))
}

fn parse_get_response(data: &[u8]) -> Result<SnmpInfo> {
    let mut outer = Ber::new(data);
    let (tag, body) = outer.read_tlv()?;
    if tag != 0x30 {
        bail!("SNMP response: outer not SEQUENCE");
    }
    let mut seq = Ber::new(body);

    // version
    let (_t, _v) = seq.read_tlv()?;
    // community
    let (_t, _v) = seq.read_tlv()?;
    // PDU (GetResponse tag 0xA2)
    let (pdu_tag, pdu_body) = seq.read_tlv()?;
    if pdu_tag != 0xA2 {
        bail!("SNMP response: unexpected PDU tag {pdu_tag:#x}");
    }

    let mut pdu = Ber::new(pdu_body);
    let (_t, _rid) = pdu.read_tlv()?;
    let (_t, err_status) = pdu.read_tlv()?;
    if !err_status.is_empty() && err_status.iter().any(|b| *b != 0) {
        bail!("SNMP error status in response");
    }
    let (_t, _err_idx) = pdu.read_tlv()?;
    let (vb_tag, vb_body) = pdu.read_tlv()?;
    if vb_tag != 0x30 {
        bail!("SNMP response: varbinds not SEQUENCE");
    }

    let mut info = SnmpInfo {
        sys_descr: None,
        sys_object_id: None,
        sys_name: None,
        sys_uptime_ticks: None,
    };

    let mut vbl = Ber::new(vb_body);
    while !vbl.is_empty() {
        let (one_tag, one_body) = vbl.read_tlv()?;
        if one_tag != 0x30 {
            break;
        }
        let mut one = Ber::new(one_body);
        let (oid_tag, oid_raw) = one.read_tlv()?;
        if oid_tag != 0x06 {
            break;
        }
        let oid = decode_oid(oid_raw);
        let (val_tag, val_raw) = one.read_tlv()?;

        match oid.as_str() {
            OID_SYS_DESCR => info.sys_descr = Some(decode_string_value(val_tag, val_raw)),
            OID_SYS_OBJECT_ID => info.sys_object_id = Some(decode_oid(val_raw)),
            OID_SYS_NAME => info.sys_name = Some(decode_string_value(val_tag, val_raw)),
            OID_SYS_UPTIME => info.sys_uptime_ticks = Some(decode_u64(val_tag, val_raw)),
            _ => {}
        }
    }

    Ok(info)
}

fn decode_string_value(tag: u8, data: &[u8]) -> String {
    if tag == 0x04 {
        String::from_utf8_lossy(data).to_string()
    } else {
        String::new()
    }
}

fn decode_u64(tag: u8, data: &[u8]) -> u64 {
    // Timeticks is tag 0x43.
    if tag == 0x43 || tag == 0x02 {
        let mut v: u64 = 0;
        for b in data {
            v = (v << 8) | (*b as u64);
        }
        v
    } else {
        0
    }
}

fn decode_oid(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut parts: Vec<u64> = Vec::new();
    let first = data[0] as u64;
    parts.push(first / 40);
    parts.push(first % 40);
    let mut acc: u64 = 0;
    let mut started = false;
    for &b in &data[1..] {
        acc = (acc << 7) | (b as u64 & 0x7f);
        started = true;
        if b & 0x80 == 0 {
            parts.push(acc);
            acc = 0;
            started = false;
        }
    }
    if started {
        parts.push(acc);
    }
    parts
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn encode_int(v: i64) -> Vec<u8> {
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0 {
        bytes.remove(0);
    }
    while bytes.len() > 1 && bytes[0] == 0xFF && (bytes[1] & 0x80) != 0 {
        bytes.remove(0);
    }
    tlv(0x02, &bytes)
}

fn encode_oid(oid: &str) -> Result<Vec<u8>> {
    let parts: Vec<u64> = oid
        .split('.')
        .map(|s| s.parse::<u64>())
        .collect::<Result<_, _>>()
        .context("parse OID")?;
    if parts.len() < 2 {
        bail!("OID needs at least two components");
    }
    let mut content = Vec::new();
    let first = parts[0] * 40 + parts[1];
    content.push(first as u8);
    for &p in &parts[2..] {
        let mut stack = Vec::new();
        let mut v = p;
        stack.push((v & 0x7f) as u8);
        v >>= 7;
        while v > 0 {
            stack.push(((v & 0x7f) | 0x80) as u8);
            v >>= 7;
        }
        stack.reverse();
        content.extend(stack);
    }
    Ok(tlv(0x06, &content))
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    out.extend(encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

struct Ber<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Ber<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        if self.pos >= self.data.len() {
            bail!("BER: eof");
        }
        let tag = self.data[self.pos];
        self.pos += 1;
        let len = self.read_length()?;
        if self.pos + len > self.data.len() {
            bail!("BER: overflow");
        }
        let content = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, content))
    }

    fn read_length(&mut self) -> Result<usize> {
        if self.pos >= self.data.len() {
            bail!("BER: eof at length");
        }
        let first = self.data[self.pos];
        self.pos += 1;
        if first < 0x80 {
            return Ok(first as usize);
        }
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            bail!("BER: unsupported length size {n}");
        }
        let mut len = 0usize;
        for _ in 0..n {
            if self.pos >= self.data.len() {
                bail!("BER: eof in long length");
            }
            len = (len << 8) | self.data[self.pos] as usize;
            self.pos += 1;
        }
        Ok(len)
    }
}

