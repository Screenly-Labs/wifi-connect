//! The wildcard DNS responder's answer policy.
//!
//! Pure: bytes in, bytes out. The socket lives in the parent module.
//!
//! Every name resolves to the portal's own address, which is what makes a
//! client's probe for `connectivitycheck.gstatic.com` land on us. The
//! interesting decisions here are all about what *not* to answer:
//!
//! * **AAAA gets NOERROR with an empty answer, never NXDOMAIN.** This is the
//!   single most important line in the file. NXDOMAIN means "this name does
//!   not exist *at all*", so a dual-stack client that asks for AAAA first
//!   will not then fall back to asking for A — and the portal simply never
//!   loads. Empty-NOERROR means "exists, has no v6 address", which is both
//!   true and what makes the fallback happen.
//! * The same applies to every other qtype. Modern Chrome and iOS query
//!   HTTPS (type 65) aggressively; answering it would advertise an HTTP/3
//!   service we do not run.
//! * A packet we could not parse gets no reply at all. Replying to garbage
//!   is a reflection/amplification vector.
//! * Exactly one question per query. Real stub resolvers never send more
//!   (RFC 9619 makes QDCOUNT=1 the rule for QUERY), and answering each of
//!   many packed questions would turn a small spoofed datagram into a
//!   several-times-larger reply aimed at someone else. More than one gets a
//!   bare FORMERR header — 12 bytes, never larger than what was sent.

use std::net::Ipv4Addr;

use simple_dns::{
    CLASS, OPCODE, Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, TYPE, rdata::A, rdata::RData,
};

/// TTL of 0: nothing should cache the hijack past the portal's lifetime.
/// A client that cached our answer for the real `captive.apple.com` after
/// joining the user's actual network would be a genuine bug.
const TTL: u32 = 0;

/// The classic non-EDNS UDP payload limit (RFC 1035 §4.2.1). We never set
/// TC, so a reply must never exceed this. With one echoed question (a name
/// is at most 255 bytes) and one compressed A record the reply tops out
/// well under it; the check in [`finish`] is a backstop, not a code path.
const MAX_REPLY: usize = 512;

/// Build the reply for one received datagram.
///
/// Returns `None` when the query should be dropped without a response.
pub fn respond(query: &[u8], gateway: Ipv4Addr) -> Option<Vec<u8>> {
    let packet = match Packet::parse(query) {
        Ok(p) => p,
        // Unparseable, truncated, or a compression-pointer loop: stay silent.
        Err(_) => return None,
    };

    // Never reply to a reply; that is how two resolvers end up in a loop.
    if packet.has_flags(PacketFlag::RESPONSE) {
        return None;
    }

    // Nothing to answer. Dropped rather than FORMERR'd: it costs nothing
    // to stay silent, and no legitimate client sends this.
    if packet.questions.is_empty() {
        return None;
    }

    let opcode = packet.opcode();
    let recursion_desired = packet.has_flags(PacketFlag::RECURSION_DESIRED);
    let questions: Vec<_> = packet.questions.clone();
    let id = packet.id();

    // `into_reply` swaps the header but keeps every section, so the
    // questions are already present and the answer/authority/additional
    // sections may carry whatever the sender put there. Clear those: we
    // echo the question and nothing else of theirs.
    let mut reply = packet.into_reply();
    reply.answers.clear();
    reply.name_servers.clear();
    reply.additional_records.clear();
    reply.set_id(id);
    reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    // RD is echoed back per RFC 1035. RA is deliberately left clear: we are
    // not a recursive resolver, and claiming to be invites clients to try
    // more exotic queries against us.
    if recursion_desired {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    reply.remove_flags(PacketFlag::RECURSION_AVAILABLE);
    // `into_reply` rebuilds the header, which is where simple-dns keeps a
    // parsed EDNS OPT record, so the client's OPT is already gone here and
    // we answer as a plain RFC 1035 server. That is also why the 512-byte
    // ceiling below is the right one: we never advertise a bigger buffer.
    debug_assert!(reply.opt().is_none());

    // More than one question: FORMERR, as RFC 9619 asks, rather than a
    // silent drop, so a confused-but-legitimate client fails fast instead of
    // timing out. The questions are not echoed — the reply is the bare
    // 12-byte header, so it can never be larger than the query that caused
    // it, and a spoofed source gains no amplification from us. Checked
    // before the opcode so the NOTIMP path cannot echo a packed question
    // list either.
    if questions.len() != 1 {
        reply.questions.clear();
        *reply.rcode_mut() = RCODE::FormatError;
        return finish(&reply);
    }

    // We only speak standard queries. UPDATE/NOTIFY get an honest NOTIMP.
    if opcode != OPCODE::StandardQuery {
        *reply.rcode_mut() = RCODE::NotImplemented;
        return finish(&reply);
    }

    for q in &questions {
        let is_internet = matches!(q.qclass, simple_dns::QCLASS::CLASS(CLASS::IN));
        let wants_a = matches!(q.qtype, QTYPE::TYPE(TYPE::A) | QTYPE::ANY);

        if is_internet && wants_a {
            reply.answers.push(ResourceRecord::new(
                q.qname.clone(),
                CLASS::IN,
                TTL,
                RData::A(A {
                    address: gateway.to_bits(),
                }),
            ));
        }
        // Everything else — AAAA, HTTPS/SVCB, TXT, MX, PTR, SRV — falls
        // through with no answer record. RCODE stays NoError, which is the
        // whole point.
    }

    finish(&reply)
}

/// Serialise a reply, refusing to send anything over [`MAX_REPLY`]. We do
/// not implement truncation (TC), so an oversized reply would be malformed
/// to a non-EDNS client; dropping is the honest failure. Unreachable with
/// one question and one A record, but cheap to guarantee.
fn finish(reply: &Packet<'_>) -> Option<Vec<u8>> {
    reply
        .build_bytes_vec_compressed()
        .ok()
        .filter(|bytes| bytes.len() <= MAX_REPLY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{Name, QCLASS, Question};

    const GW: Ipv4Addr = Ipv4Addr::new(192, 168, 42, 1);

    fn query(name: &str, qtype: QTYPE) -> Vec<u8> {
        query_with_rd(name, qtype, false)
    }

    fn query_with_rd(name: &str, qtype: QTYPE, recursion_desired: bool) -> Vec<u8> {
        let mut p = Packet::new_query(0x1234);
        if recursion_desired {
            p.set_flags(PacketFlag::RECURSION_DESIRED);
        }
        p.questions.push(Question::new(
            Name::new(name).unwrap(),
            qtype,
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        p.build_bytes_vec().unwrap()
    }

    fn parse(bytes: &[u8]) -> Packet<'_> {
        Packet::parse(bytes).unwrap()
    }

    #[test]
    fn a_query_resolves_to_the_gateway() {
        let out = respond(&query("captive.apple.com", QTYPE::TYPE(TYPE::A)), GW).unwrap();
        let reply = parse(&out);

        assert_eq!(reply.id(), 0x1234);
        assert!(reply.has_flags(PacketFlag::RESPONSE));
        assert!(reply.has_flags(PacketFlag::AUTHORITATIVE_ANSWER));
        assert_eq!(reply.rcode(), RCODE::NoError);
        assert_eq!(reply.questions.len(), 1);
        assert_eq!(reply.answers.len(), 1);

        match &reply.answers[0].rdata {
            RData::A(a) => assert_eq!(Ipv4Addr::from_bits(a.address), GW),
            other => panic!("expected an A record, got {other:?}"),
        }
        assert_eq!(reply.answers[0].ttl, 0, "the hijack must not be cached");
    }

    /// The regression that silently breaks iOS. If this ever becomes
    /// NXDOMAIN, dual-stack clients stop falling back to A and the portal
    /// never loads — with no error anywhere to explain it.
    #[test]
    fn aaaa_is_noerror_with_no_answers_not_nxdomain() {
        let out = respond(&query("captive.apple.com", QTYPE::TYPE(TYPE::AAAA)), GW).unwrap();
        let reply = parse(&out);

        assert_eq!(
            reply.rcode(),
            RCODE::NoError,
            "AAAA must be NOERROR, never NXDOMAIN"
        );
        assert!(reply.answers.is_empty());
        assert_eq!(reply.questions.len(), 1, "the question must be echoed");
    }

    #[test]
    fn https_type65_gets_an_empty_noerror() {
        let out = respond(&query("www.example.com", QTYPE::TYPE(TYPE::HTTPS)), GW).unwrap();
        let reply = parse(&out);
        assert_eq!(reply.rcode(), RCODE::NoError);
        assert!(reply.answers.is_empty());
    }

    #[test]
    fn other_qtypes_get_an_empty_noerror() {
        for qtype in [TYPE::TXT, TYPE::MX, TYPE::SRV, TYPE::PTR, TYPE::NS] {
            let out = respond(&query("example.com", QTYPE::TYPE(qtype)), GW).unwrap();
            let reply = parse(&out);
            assert_eq!(reply.rcode(), RCODE::NoError, "{qtype:?} should be NoError");
            assert!(reply.answers.is_empty(), "{qtype:?} should have no answers");
        }
    }

    #[test]
    fn every_name_resolves_to_us() {
        for name in [
            "connectivitycheck.gstatic.com",
            "www.msftconnecttest.com",
            "detectportal.firefox.com",
            "a.very.deeply.nested.name.example",
        ] {
            let out = respond(&query(name, QTYPE::TYPE(TYPE::A)), GW).unwrap();
            assert_eq!(parse(&out).answers.len(), 1, "{name} did not resolve");
        }
    }

    #[test]
    fn malformed_input_is_dropped_silently() {
        assert!(respond(&[], GW).is_none());
        assert!(respond(&[0xff; 3], GW).is_none());
        assert!(
            respond(&[0x00; 12], GW).is_none(),
            "header with no questions"
        );
    }

    /// A truncated packet claiming more questions than it carries must not
    /// panic or hang. This is the decompression-bomb shape.
    #[test]
    fn truncated_and_hostile_input_does_not_panic() {
        let mut bomb = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        bomb.extend_from_slice(&[0xc0, 0x0c]); // a pointer to itself
        let _ = respond(&bomb, GW);

        let valid = query("example.com", QTYPE::TYPE(TYPE::A));
        for cut in 0..valid.len() {
            let _ = respond(&valid[..cut], GW);
        }
    }

    #[test]
    fn a_response_packet_is_never_answered() {
        let q = query("example.com", QTYPE::TYPE(TYPE::A));
        let reply_bytes = respond(&q, GW).unwrap();
        assert!(
            respond(&reply_bytes, GW).is_none(),
            "answering a response would loop"
        );
    }

    #[test]
    fn recursion_desired_is_echoed_and_availability_is_not_claimed() {
        let with_rd = query_with_rd("example.com", QTYPE::TYPE(TYPE::A), true);
        let out = respond(&with_rd, GW).unwrap();
        let reply = parse(&out);
        assert!(
            reply.has_flags(PacketFlag::RECURSION_DESIRED),
            "RD must be echoed"
        );
        // Never claim recursion: we are not a resolver, and saying we are
        // invites clients to push more exotic queries at us.
        assert!(!reply.has_flags(PacketFlag::RECURSION_AVAILABLE));

        let without_rd = query_with_rd("example.com", QTYPE::TYPE(TYPE::A), false);
        let out = respond(&without_rd, GW).unwrap();
        let reply = parse(&out);
        assert!(!reply.has_flags(PacketFlag::RECURSION_DESIRED));
    }

    /// `into_reply` keeps every section of the incoming packet. A sender that
    /// stuffs records into the answer or additional sections must not see
    /// them reflected back as though we had asserted them.
    #[test]
    fn hostile_sections_are_not_reflected() {
        let mut p = Packet::new_query(7);
        p.questions.push(Question::new(
            Name::new("example.com").unwrap(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        p.answers.push(ResourceRecord::new(
            Name::new("evil.example").unwrap(),
            CLASS::IN,
            9999,
            RData::A(A {
                address: 0x0100007f,
            }),
        ));
        let bytes = p.build_bytes_vec().unwrap();

        let out = respond(&bytes, GW).unwrap();
        let reply = parse(&out);
        assert_eq!(reply.answers.len(), 1, "only our own answer should remain");
        match &reply.answers[0].rdata {
            RData::A(a) => assert_eq!(Ipv4Addr::from_bits(a.address), GW),
            other => panic!("unexpected rdata {other:?}"),
        }
        assert!(reply.name_servers.is_empty());
    }

    /// The amplification shape: a datagram packed with as many minimal
    /// questions as fit in 512 bytes (root name, type A — five bytes each).
    /// Answering each would emit a 16-byte A record per 5-byte question. It
    /// must instead get a bare FORMERR header, never larger than the query.
    #[test]
    fn packed_questions_get_a_bare_formerr_no_larger_than_the_query() {
        let count: u16 = 100;
        let mut q = vec![0xab, 0xcd, 0x01, 0x00]; // id, RD set
        q.extend_from_slice(&count.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
        for _ in 0..count {
            q.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // ".", A, IN
        }
        assert_eq!(q.len(), 512);

        let out = respond(&q, GW).expect("multi-question queries get FORMERR");
        assert!(
            out.len() <= q.len(),
            "reply ({}) larger than query ({})",
            out.len(),
            q.len()
        );
        assert_eq!(out.len(), 12, "FORMERR should be the bare header");

        let reply = parse(&out);
        assert_eq!(reply.id(), 0xabcd);
        assert!(reply.has_flags(PacketFlag::RESPONSE));
        assert_eq!(reply.rcode(), RCODE::FormatError);
        assert!(reply.questions.is_empty(), "questions must not be echoed");
        assert!(reply.answers.is_empty());
    }

    #[test]
    fn two_real_questions_are_formerr_not_answered() {
        let mut p = Packet::new_query(9);
        for name in ["captive.apple.com", "connectivitycheck.gstatic.com"] {
            p.questions.push(Question::new(
                Name::new(name).unwrap(),
                QTYPE::TYPE(TYPE::A),
                QCLASS::CLASS(CLASS::IN),
                false,
            ));
        }
        let q = p.build_bytes_vec().unwrap();

        let out = respond(&q, GW).unwrap();
        assert!(out.len() <= q.len());
        let reply = parse(&out);
        assert_eq!(reply.rcode(), RCODE::FormatError);
        assert!(reply.questions.is_empty());
        assert!(reply.answers.is_empty());
    }

    /// The question-count check runs before the opcode check, so the NOTIMP
    /// path cannot be used to get a packed question list echoed back.
    #[test]
    fn packed_questions_with_an_unsupported_opcode_are_not_echoed() {
        let mut q = vec![0x00, 0x01, 0x10, 0x00, 0x00, 0x03, 0, 0, 0, 0, 0, 0]; // opcode 2
        for _ in 0..3 {
            q.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        }
        let out = respond(&q, GW).unwrap();
        let reply = parse(&out);
        assert_eq!(reply.rcode(), RCODE::FormatError);
        assert!(reply.questions.is_empty());
    }

    /// Stub resolvers routinely attach an EDNS OPT record. It must not stop
    /// the single question being answered, and we must not echo it back:
    /// advertising a larger UDP buffer would undercut the 512-byte ceiling.
    #[test]
    fn an_edns_opt_record_is_tolerated_and_not_echoed() {
        let mut p = Packet::new_query(0x4242);
        p.questions.push(Question::new(
            Name::new("captive.apple.com").unwrap(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        *p.opt_mut() = Some(simple_dns::rdata::OPT {
            opt_codes: Vec::new(),
            udp_packet_size: 4096,
            version: 0,
        });
        let q = p.build_bytes_vec().unwrap();
        assert!(parse(&q).opt().is_some(), "test query must carry OPT");

        let out = respond(&q, GW).unwrap();
        let reply = parse(&out);
        assert_eq!(reply.rcode(), RCODE::NoError);
        assert_eq!(reply.questions.len(), 1);
        assert_eq!(reply.answers.len(), 1);
        assert!(reply.opt().is_none(), "OPT must not be echoed");
        assert!(reply.additional_records.is_empty());
    }

    /// The largest legal single-question reply — a maximum-length name,
    /// echoed and answered — must still fit the non-EDNS 512-byte limit,
    /// since we never set TC.
    #[test]
    fn the_largest_single_question_reply_fits_in_512_bytes() {
        // Four 62-byte labels: 4 * (1 + 62) + 1 = 253 bytes on the wire, near
        // the 255-byte ceiling (a fifth label would exceed it).
        let label = "a".repeat(62);
        let name = [label.as_str(); 4].join(".");
        for qtype in [QTYPE::TYPE(TYPE::A), QTYPE::ANY] {
            let out = respond(&query(&name, qtype), GW).expect("must be answered");
            assert!(out.len() <= MAX_REPLY, "{} bytes", out.len());
            assert_eq!(parse(&out).answers.len(), 1);
        }
    }
}
