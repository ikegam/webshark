#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Json;
    use axum::extract::State;
    use tokio::sync::{broadcast, mpsc};

    use crate::capture::build_capture_filter;
    use crate::handlers::set_filter_handler;
    use crate::types::{CaptureCommand, FilterConfig, PacketStats};
    use crate::utils::{parse_tshark_line, validate_tshark_filter};

    /// Build a tshark output line. Field order matches capture.rs:
    /// time|ip.src|ip.dst|ipv6.src|ipv6.dst|arp.src|arp.dst|protocols|len|
    /// tcp.srcport|tcp.dstport|udp.srcport|udp.dstport|tcp.flags|
    /// dns.qry.name|dns.a|dns.aaaa|tls.sni|http.host|eth.src|eth.dst|info
    const INFO: usize = 21;

    fn line(fields: &[(usize, &str)]) -> String {
        let mut cols = vec![""; 22];
        cols[0] = "1.0";
        for &(i, v) in fields {
            cols[i] = v;
        }
        cols.join("|")
    }

    #[test]
    fn test_parse_tshark_line_basic() {
        let l = line(&[
            (0, "1616161616.123"),
            (1, "192.168.0.1"),
            (2, "192.168.0.2"),
            (7, "eth:ip:tcp:tls"),
            (8, "60"),
            (9, "51000"),
            (10, "443"),
            (13, "0x0018"),
            (17, "example.com"),
            (19, "38:c6:ce:8a:79:ea"),
            (20, "32:01:02:44:1c:80"),
            (INFO, "Example"),
        ]);
        let packet = parse_tshark_line(&l).expect("packet parsed");
        assert_eq!(packet.src_ip, "192.168.0.1");
        assert_eq!(packet.dst_ip, "192.168.0.2");
        assert_eq!(packet.protocol, "TCP");
        assert_eq!(packet.sub_protocol.as_deref(), Some("TLS"));
        assert_eq!(packet.app, "tls");
        assert_eq!(packet.src_port, Some(51000));
        assert_eq!(packet.dst_port, Some(443));
        assert_eq!(packet.tcp_flags, Some(0x18));
        assert_eq!(packet.server_name.as_deref(), Some("example.com"));
        assert_eq!(packet.src_mac.as_deref(), Some("38:c6:ce:8a:79:ea"));
        assert_eq!(packet.dst_mac.as_deref(), Some("32:01:02:44:1c:80"));
        assert_eq!(packet.length, 60);
        assert_eq!(packet.info, "Example");
        assert!((packet.timestamp - 1616161616.123).abs() < 1e-6);
    }

    #[test]
    fn test_parse_tshark_line_info_with_pipe() {
        let l = line(&[
            (1, "192.168.0.1"),
            (2, "192.168.0.2"),
            (7, "eth:ip:tcp"),
            (8, "60"),
            (INFO, "Example|with|pipe"),
        ]);
        assert_eq!(parse_tshark_line(&l).unwrap().info, "Example|with|pipe");
    }

    #[test]
    fn test_parse_udp_ports_and_app() {
        let l = line(&[
            (1, "192.168.0.108"),
            (2, "192.168.0.1"),
            (7, "sll:ethertype:ip:udp:dns"),
            (8, "74"),
            (11, "53124"),
            (12, "53"),
            (14, "example.com"),
            (INFO, "Standard query"),
        ]);
        let packet = parse_tshark_line(&l).expect("packet parsed");
        assert_eq!(packet.protocol, "UDP");
        assert_eq!(packet.app, "dns");
        assert_eq!(packet.src_port, Some(53124));
        assert_eq!(packet.dst_port, Some(53));
        assert_eq!(packet.tcp_flags, None);
        // A query without answers carries no name mapping.
        assert_eq!(packet.dns_name, None);
        assert!(packet.dns_addrs.is_empty());
    }

    #[test]
    fn test_parse_dns_answers() {
        let l = line(&[
            (1, "192.168.0.1"),
            (2, "192.168.0.108"),
            (7, "eth:ethertype:ip:udp:dns"),
            (8, "120"),
            (11, "53"),
            (12, "53124"),
            (14, "www.example.com;www.example.com"),
            (15, "93.184.216.34;93.184.216.35"),
            (16, "2606:2800:220:1::1"),
            (INFO, "Standard query response"),
        ]);
        let p = parse_tshark_line(&l).unwrap();
        assert_eq!(p.dns_name.as_deref(), Some("www.example.com"));
        assert_eq!(
            p.dns_addrs,
            vec!["93.184.216.34", "93.184.216.35", "2606:2800:220:1::1"]
        );
    }

    #[test]
    fn test_parse_takes_outer_header_of_icmp_error() {
        let l = line(&[
            (1, "192.168.0.1;192.168.0.108"),
            (2, "192.168.0.108;8.8.8.8"),
            (7, "eth:ethertype:ip:icmp:ip:udp:dns"),
            (8, "98"),
            (11, ";53000"),
            (12, ";53"),
            (INFO, "Destination unreachable"),
        ]);
        let p = parse_tshark_line(&l).unwrap();
        assert_eq!(
            (p.src_ip.as_str(), p.dst_ip.as_str()),
            ("192.168.0.1", "192.168.0.108")
        );
        assert_eq!(p.protocol, "ICMP");
        assert_eq!(p.app, "icmp");
        assert_eq!((p.src_port, p.dst_port), (None, None));
    }

    #[test]
    fn test_parse_skips_generic_payload_layer() {
        let l = line(&[
            (1, "10.0.0.1"),
            (2, "10.0.0.2"),
            (7, "eth:ethertype:ip:udp:data"),
            (8, "100"),
            (11, "1000"),
            (12, "2000"),
        ]);
        assert_eq!(parse_tshark_line(&l).unwrap().app, "udp");
    }

    #[test]
    fn test_parse_ipv6_and_arp_fallback() {
        let v6 = line(&[
            (3, "fe80::1"),
            (4, "ff02::1"),
            (7, "eth:ethertype:ipv6:icmpv6"),
            (8, "86"),
        ]);
        let p = parse_tshark_line(&v6).unwrap();
        assert_eq!(
            (p.src_ip.as_str(), p.dst_ip.as_str()),
            ("fe80::1", "ff02::1")
        );
        assert_eq!(p.protocol, "ICMP");
        let arp = line(&[
            (5, "192.168.0.1"),
            (6, "192.168.0.5"),
            (7, "eth:ethertype:arp"),
            (8, "42"),
        ]);
        let p = parse_tshark_line(&arp).unwrap();
        assert_eq!(
            (p.src_ip.as_str(), p.dst_ip.as_str()),
            ("192.168.0.1", "192.168.0.5")
        );
        assert_eq!(p.protocol, "ARP");
    }

    #[test]
    fn test_parse_rejects_short_line() {
        assert!(parse_tshark_line("1.0|a|b|c").is_none());
    }

    #[test]
    fn test_validate_filter_allows_bpf_grouping() {
        assert!(validate_tshark_filter("tcp and (port 80 or port 443)"));
        assert!(validate_tshark_filter("net 192.168.0.0/24"));
        assert!(validate_tshark_filter("port 53"));
        assert!(validate_tshark_filter(""));
        assert!(!validate_tshark_filter("tcp; rm -rf /"));
        assert!(!validate_tshark_filter("$(id)"));
        assert!(!validate_tshark_filter(&"a".repeat(600)));
    }

    #[test]
    fn test_build_capture_filter_excludes_ui_port() {
        assert_eq!(build_capture_filter(None, 3000), "not tcp port 3000");
        assert_eq!(build_capture_filter(Some("  "), 3000), "not tcp port 3000");
        assert_eq!(
            build_capture_filter(Some("udp or icmp"), 8080),
            "(udp or icmp) and not tcp port 8080"
        );
    }

    #[test]
    fn test_lan_nets_exclude_wan_and_link_local() {
        use crate::utils::{parse_default_route_ifaces, parse_lan_nets};
        let routes =
            "default dev ppp0 scope link \ndefault via fe80::1 dev enp1s0 proto ra metric 1024\n";
        let wan = parse_default_route_ifaces(routes);
        assert_eq!(wan, vec!["ppp0", "enp1s0"]);
        let addrs = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever
2: enp1s0    inet6 2409:10:bec0:4200::1/64 metric 256 scope global dynamic mngtmpaddr \\ valid_lft 1sec
4: enp3s0    inet 192.168.0.1/24 brd 192.168.0.255 scope global enp3s0\\       valid_lft forever
4: enp3s0    inet6 2409:10:bec0:4201::1/64 metric 255 scope global dynamic mngtmpaddr \\ valid_lft 1sec
4: enp3s0    inet6 fe80::1/64 scope link \\       valid_lft forever
15: ppp0    inet 160.13.93.49 peer 203.180.20.91/32 scope global ppp0\\       valid_lft forever
";
        let nets: Vec<String> = parse_lan_nets(addrs, &wan)
            .into_iter()
            .map(|n| n.cidr)
            .collect();
        assert_eq!(nets, vec!["192.168.0.1/24", "2409:10:bec0:4201::1/64"]);
    }

    #[test]
    fn test_filter_compile_result_uses_output_not_exit_code() {
        use crate::handlers::filter_compile_result;
        let ok = "(000) ldh      [12]\n(001) jeq      #0x86dd          jt 2\tjf 8\n";
        assert!(filter_compile_result(ok, "Capturing on 'enp3s0'\n").is_ok());
        let err = "Capturing on 'enp3s0'\ndumpcap: Invalid capture filter \"tcp and (port 80 or\" for interface 'enp3s0'.\n\n\
That string isn't a valid capture filter (can't parse filter expression: syntax error).\n\
See the User's Guide for a description of the capture filter syntax.\n";
        let msg = filter_compile_result("", err).unwrap_err();
        assert!(msg.contains("Invalid capture filter"), "{msg}");
        assert!(!msg.contains("Capturing on"));
    }

    #[test]
    fn test_parse_all_addrs_includes_link_local() {
        use crate::utils::parse_all_addrs;
        let out = "2: enp1s0    inet6 fe80::3001:2ff:fe44:1c81/64 scope link \\ valid_lft forever\n\
4: enp3s0    inet 192.168.0.1/24 brd 192.168.0.255 scope global enp3s0\\ valid_lft forever\n\
15: ppp0    inet 160.13.93.49 peer 203.180.20.91/32 scope global ppp0\\ valid_lft forever\n";
        assert_eq!(
            parse_all_addrs(out),
            vec!["fe80::3001:2ff:fe44:1c81", "192.168.0.1", "160.13.93.49"]
        );
    }

    #[tokio::test]
    async fn test_set_filter_handler_updates_filter() {
        let stats = Arc::new(Mutex::new(PacketStats::default()));

        let filter = Arc::new(Mutex::new(FilterConfig {
            tshark_filter: None,
        }));
        let (tx, _) = broadcast::channel(1);
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

        let new_filter = FilterConfig {
            tshark_filter: Some("tcp".to_string()),
        };
        let state = State((stats, filter.clone(), tx, cmd_tx));
        let result = set_filter_handler(state, Json(new_filter.clone()))
            .await
            .expect("handler ok");

        assert_eq!(result.0.tshark_filter, Some("tcp".to_string()));
        assert_eq!(
            filter.lock().unwrap().tshark_filter,
            Some("tcp".to_string())
        );
        assert!(matches!(cmd_rx.try_recv(), Ok(CaptureCommand::Restart)));
    }
}
