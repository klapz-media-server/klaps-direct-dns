//! Authoritative DNS server for `BASE_DOMAIN` (e.g. klapz.direct). Everything is computed
//! on the fly, nothing stored, except the ACME TXT values:
//!
//!   192-168-1-12.<hash>.klapz.direct          A     192.168.1.12
//!   2001-db8--1.<hash>.klapz.direct           AAAA  2001:db8::1      ('-' = ':', '--' = '::')
//!   _acme-challenge.<hash>.klapz.direct       TXT   stored values (RAM cache / .bin)
//!   klapz.direct                              SOA, NS
//!   ns1.klapz.direct                          A/AAAA (glue, from config)
//!
//! Perf: UDP on N SO_REUSEPORT sockets (one per core, the kernel spreads packets across
//! them); A/AAAA answers involve no storage lookup and no disk access. Only TXT queries are
//! spawned onto a separate task (they may read the disk when the cache is cold).
//! TCP is supported too (required when a response doesn't fit in UDP).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, NS, SOA, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};

use crate::state::AppState;

const TTL_IP: u32 = 86_400; // an IP encoded in the name never changes
const TTL_TXT: u32 = 1; // challenges change on every issuance
const TTL_ZONE: u32 = 3_600;
const NEG_TTL: u32 = 60; // negative caching (SOA minimum)
const EDNS_PAYLOAD: u16 = 1232; // recommended size (DNS flag day 2020)

pub struct DnsConfig {
    pub listen: SocketAddr,
    /// Zone name servers, e.g. ["ns1.klapz.direct"].
    pub ns: Vec<String>,
    /// IP of each name server (same order), for glue records.
    pub ns_ips: Vec<IpAddr>,
}

/// Static zone records, built once at startup.
struct Zone {
    state: Arc<AppState>,
    base: String,
    soa: Record,
    ns: Vec<Record>,
    /// NS host names, lowercase, no trailing dot.
    ns_names: Vec<String>,
    /// (lowercase name without trailing dot, IP)
    glue: Vec<(String, IpAddr)>,
}

enum Answer {
    Records(Vec<Record>),
    NoData,
    NxDomain,
    Refused,
}

pub async fn serve(state: Arc<AppState>, cfg: DnsConfig) -> Result<()> {
    let base = state.cfg.base_domain.clone();
    let apex = Name::from_ascii(format!("{base}."))?;
    let first_ns = cfg.ns.first().cloned().unwrap_or_else(|| format!("ns1.{base}"));
    let soa = Record::from_rdata(
        apex.clone(),
        TTL_ZONE,
        RData::SOA(SOA::new(
            Name::from_ascii(format!("{first_ns}."))?,
            Name::from_ascii(format!("hostmaster.{base}."))?,
            1, 7_200, 3_600, 1_209_600, NEG_TTL,
        )),
    );
    let ns = cfg
        .ns
        .iter()
        .map(|n| Ok(Record::from_rdata(apex.clone(), TTL_ZONE, RData::NS(NS(Name::from_ascii(format!("{n}."))?)))))
        .collect::<Result<Vec<_>>>()?;
    let ns_names: Vec<String> = cfg.ns.iter().map(|n| n.to_ascii_lowercase()).collect();
    let glue = ns_names.iter().cloned().zip(cfg.ns_ips.iter().copied()).collect();
    let zone = Arc::new(Zone { state, base, soa, ns, ns_names, glue });

    // One UDP socket per core, all on the same port thanks to SO_REUSEPORT.
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    for _ in 0..workers {
        let sock = Arc::new(UdpSocket::from_std(reuseport_udp(cfg.listen)?)?);
        tokio::spawn(udp_loop(zone.clone(), sock));
    }
    let tcp = TcpListener::bind(cfg.listen).await.with_context(|| format!("bind TCP {}", cfg.listen))?;
    info!("DNS listening on {} (UDP ×{workers}, TCP) for {}", cfg.listen, zone.base);
    tcp_loop(zone, tcp).await
}

fn reuseport_udp(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_recv_buffer_size(4 << 20);
    sock.bind(&addr.into()).with_context(|| format!("bind UDP {addr} (port 53 needs root or CAP_NET_BIND_SERVICE)"))?;
    Ok(sock.into())
}

async fn udp_loop(zone: Arc<Zone>, sock: Arc<UdpSocket>) {
    let mut buf = [0u8; 4096];
    loop {
        let (len, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("UDP recv: {e}");
                continue;
            }
        };
        let Ok(req) = Message::from_vec(&buf[..len]) else { continue }; // unparseable packet: ignored
        let is_txt = req.queries.first().is_some_and(|q| matches!(q.query_type(), RecordType::TXT | RecordType::ANY));
        if is_txt {
            // May read the disk: don't block the loop.
            let (zone, sock) = (zone.clone(), sock.clone());
            tokio::spawn(async move {
                if let Some(out) = zone.respond(&req, true).await {
                    let _ = sock.send_to(&out, peer).await;
                }
            });
        } else if let Some(out) = zone.respond(&req, true).await {
            let _ = sock.send_to(&out, peer).await;
        }
    }
}

async fn tcp_loop(zone: Arc<Zone>, listener: TcpListener) -> Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let zone = zone.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let mut buf = vec![0u8; 65_535];
            // Length-prefixed (u16) messages, possibly several per connection.
            loop {
                let len = match tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_u16()).await {
                    Ok(Ok(l)) => l as usize,
                    _ => return,
                };
                if stream.read_exact(&mut buf[..len]).await.is_err() {
                    return;
                }
                let Ok(req) = Message::from_vec(&buf[..len]) else { return };
                let Some(out) = zone.respond(&req, false).await else { return };
                let mut framed = Vec::with_capacity(out.len() + 2);
                framed.extend_from_slice(&(out.len() as u16).to_be_bytes());
                framed.extend_from_slice(&out);
                if stream.write_all(&framed).await.is_err() {
                    return;
                }
            }
        });
    }
}

impl Zone {
    async fn respond(&self, req: &Message, udp: bool) -> Option<Vec<u8>> {
        if req.metadata.message_type != MessageType::Query {
            return None; // never answer a response
        }
        let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
        resp.metadata.authoritative = true;
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        if req.edns.is_some() {
            let mut edns = Edns::new();
            edns.set_max_payload(EDNS_PAYLOAD);
            resp.set_edns(edns);
        }

        let query = match (req.metadata.op_code, req.queries.as_slice()) {
            (OpCode::Query, [q]) if q.query_class() == DNSClass::IN => q.clone(),
            (OpCode::Query, _) => return finish(resp, ResponseCode::FormErr, udp, req),
            _ => return finish(resp, ResponseCode::NotImp, udp, req),
        };
        resp.add_query(query.clone());

        match self.resolve(&query).await {
            Answer::Records(records) => {
                // Glue: name server IPs in the additional section.
                if query.query_type() == RecordType::NS {
                    for rec in self.glue_records() {
                        resp.add_additional(rec);
                    }
                }
                resp.add_answers(records);
                finish(resp, ResponseCode::NoError, udp, req)
            }
            Answer::NoData => {
                resp.add_authority(self.soa.clone());
                finish(resp, ResponseCode::NoError, udp, req)
            }
            Answer::NxDomain => {
                resp.add_authority(self.soa.clone());
                finish(resp, ResponseCode::NXDomain, udp, req)
            }
            Answer::Refused => finish(resp, ResponseCode::Refused, udp, req),
        }
    }

    fn glue_records(&self) -> impl Iterator<Item = Record> + '_ {
        self.glue.iter().filter_map(|(name, ip)| {
            let name = Name::from_ascii(format!("{name}.")).ok()?;
            Some(ip_record(name, *ip, TTL_ZONE))
        })
    }

    async fn resolve(&self, q: &Query) -> Answer {
        let qtype = q.query_type();
        // Answer with the exact question name, case included: some resolvers randomize
        // the case ("0x20" technique) and check that it is echoed back.
        let qname = q.name();
        let lower = qname.to_ascii().to_ascii_lowercase();
        let name = lower.strip_suffix('.').unwrap_or(&lower);

        // Apex: klapz.direct
        if name == self.base {
            return match qtype {
                RecordType::SOA => Answer::Records(vec![self.soa.clone()]),
                RecordType::NS => Answer::Records(self.ns.clone()),
                _ => Answer::NoData,
            };
        }
        let Some(rel) = name.strip_suffix(self.base.as_str()).and_then(|r| r.strip_suffix('.')) else {
            return Answer::Refused; // outside our zone
        };

        // Name servers: ns1.klapz.direct
        if self.ns_names.iter().any(|n| n == name) {
            let recs: Vec<_> = self
                .glue
                .iter()
                .filter(|(n, ip)| n == name && matches_type(*ip, qtype))
                .map(|(_, ip)| ip_record(qname.clone(), *ip, TTL_ZONE))
                .collect();
            return if recs.is_empty() { Answer::NoData } else { Answer::Records(recs) };
        }

        // <label>.<hash> or <hash>
        let (label, hash) = match rel.rsplit_once('.') {
            Some((label, hash)) => (Some(label), hash),
            None => (None, rel),
        };
        if !self.state.hasher.is_valid(hash) {
            return Answer::NxDomain;
        }
        let Some(label) = label else {
            return Answer::NoData; // <hash>.klapz.direct exists but has no records
        };

        if label == "_acme-challenge" {
            if !matches!(qtype, RecordType::TXT | RecordType::ANY) {
                return Answer::NoData;
            }
            let values = match self.state.get(hash).await {
                Ok(e) => e.record.txt.clone(),
                Err(e) => {
                    warn!("TXT read for {hash}: {e:#}");
                    return Answer::NoData;
                }
            };
            if values.is_empty() {
                return Answer::NoData;
            }
            // One TXT record per value (2 for a wildcard + bare-domain certificate).
            return Answer::Records(
                values.into_iter().map(|v| Record::from_rdata(qname.clone(), TTL_TXT, RData::TXT(TXT::new(vec![v])))).collect(),
            );
        }

        match parse_ip_label(label) {
            Some(ip) if matches_type(ip, qtype) => Answer::Records(vec![ip_record(qname.clone(), ip, TTL_IP)]),
            Some(_) => Answer::NoData,
            None => Answer::NxDomain,
        }
    }
}

fn matches_type(ip: IpAddr, qtype: RecordType) -> bool {
    matches!((ip, qtype), (IpAddr::V4(_), RecordType::A | RecordType::ANY) | (IpAddr::V6(_), RecordType::AAAA | RecordType::ANY))
}

fn ip_record(name: Name, ip: IpAddr, ttl: u32) -> Record {
    match ip {
        IpAddr::V4(v4) => Record::from_rdata(name, ttl, RData::A(A(v4))),
        IpAddr::V6(v6) => Record::from_rdata(name, ttl, RData::AAAA(AAAA(v6))),
    }
}

/// `192-168-1-12` -> 192.168.1.12 ; `2001-db8--1` -> 2001:db8::1 ; sinon None.
pub fn parse_ip_label(label: &str) -> Option<IpAddr> {
    if label.is_empty() || label.len() > 63 || label.contains('.') {
        return None;
    }
    // IPv4: exactly 4 numbers separated by dashes.
    if label.bytes().all(|b| b.is_ascii_digit() || b == b'-') && label.bytes().filter(|&b| b == b'-').count() == 3 {
        if let Ok(v4) = label.replace('-', ".").parse::<Ipv4Addr>() {
            return Some(IpAddr::V4(v4));
        }
    }
    // IPv6: hex digits and dashes; "--" becomes "::" through the plain replacement.
    if label.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') && label.contains('-') {
        if let Ok(v6) = label.replace('-', ":").parse::<Ipv6Addr>() {
            return Some(IpAddr::V6(v6));
        }
    }
    None
}

/// Serializes the response; over UDP, truncates it (TC bit) if it exceeds what the client
/// accepts, so the client retries over TCP.
fn finish(mut resp: Message, code: ResponseCode, udp: bool, req: &Message) -> Option<Vec<u8>> {
    resp.metadata.response_code = code;
    let out = resp.to_vec().ok()?;
    if udp {
        let max = req.edns.as_ref().map_or(512, |e| e.max_payload().clamp(512, EDNS_PAYLOAD)) as usize;
        if out.len() > max {
            return resp.truncate().to_vec().ok();
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_label_decoding() {
        assert_eq!(parse_ip_label("192-168-1-12"), Some("192.168.1.12".parse().unwrap()));
        assert_eq!(parse_ip_label("10-0-0-1"), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(parse_ip_label("2001-db8--1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_ip_label("fe80--1"), Some("fe80::1".parse().unwrap()));
        assert_eq!(parse_ip_label("--1"), Some("::1".parse().unwrap()));
        assert_eq!(parse_ip_label("2001-0db8-0000-0000-0000-ff00-0042-8329"), Some("2001:db8::ff00:42:8329".parse().unwrap()));
        assert_eq!(parse_ip_label("256-1-1-1"), None);
        assert_eq!(parse_ip_label("1-2-3"), None);
        assert_eq!(parse_ip_label("www"), None);
        assert_eq!(parse_ip_label("abc"), None);
        assert_eq!(parse_ip_label(""), None);
    }
}
