#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::Json;
    use tokio::sync::{broadcast, mpsc};

    use crate::handlers::set_filter_handler;
    use crate::types::{CaptureCommand, FilterConfig, PacketStats};
    use crate::utils::parse_tshark_line;

    #[test]
    fn test_parse_tshark_line_basic() {
        let line = "1616161616.123|192.168.0.1|192.168.0.2|||||eth:ip:tcp:tls|60|Example";
        let packet = parse_tshark_line(line).expect("packet parsed");
        assert_eq!(packet.src_ip, "192.168.0.1");
        assert_eq!(packet.dst_ip, "192.168.0.2");
        assert_eq!(packet.protocol, "TCP");
        assert_eq!(packet.sub_protocol.as_deref(), Some("TLS"));
        assert_eq!(packet.length, 60);
        assert_eq!(packet.info, "Example");
    }

    #[test]
    fn test_parse_tshark_line_info_with_pipe() {
        let line = "1616161616.123|192.168.0.1|192.168.0.2|||||eth:ip:tcp|60|Example|with|pipe";
        let packet = parse_tshark_line(line).expect("packet parsed");
        assert_eq!(packet.info, "Example|with|pipe");
    }

    #[tokio::test]
    async fn test_set_filter_handler_updates_filter() {
        let stats = Arc::new(Mutex::new(PacketStats {
            total_packets: 0,
            protocols: HashMap::new(),
            top_sources: HashMap::new(),
            top_destinations: HashMap::new(),
        }));

        let filter = Arc::new(Mutex::new(FilterConfig { tshark_filter: None }));
        let (tx, _) = broadcast::channel(1);
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

        let new_filter = FilterConfig { tshark_filter: Some("tcp".to_string()) };
        let state = State((stats, filter.clone(), tx, cmd_tx));
        let result = set_filter_handler(state, Json(new_filter.clone()))
            .await
            .expect("handler ok");

        assert_eq!(result.0.tshark_filter, Some("tcp".to_string()));
        assert_eq!(filter.lock().unwrap().tshark_filter, Some("tcp".to_string()));
        assert!(matches!(cmd_rx.try_recv(), Ok(CaptureCommand::Restart)));
    }
}

