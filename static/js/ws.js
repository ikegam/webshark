function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = function() {
        console.log('WebSocket connection established');
        connectionStatusEl.textContent = 'Connected';
        statusText.textContent = 'Capturing packets...';
        statusDot.style.background = '#48bb78';
        isRunning = true;
    };

    ws.onmessage = async function(event) {
        let packets = [];

        if (typeof event.data === 'string') {
            const msg = JSON.parse(event.data);
            if (msg.type === 'ctx') {
                PROTOCOLS = msg.protocols;
                LOCAL_IPS = msg.local_ips || [];
                return;
            }
            packets = [msg];
        } else if (event.data instanceof Blob) {
            // Decompress data
            try {
                const arrayBuffer = await event.data.arrayBuffer();
                const decompressed = pako.inflate(new Uint8Array(arrayBuffer), { to: 'string' });
                packets = JSON.parse(decompressed);
            } catch (e) {
                console.error('Failed to decompress data:', e);
                return;
            }
        }

        // Add batch packets to queue
        packets.forEach(packet => {
            if (packet.proto !== undefined && PROTOCOLS.length) {
                packet.protocol = PROTOCOLS[packet.proto] || 'UNKNOWN';
            }
            if (packet.sub_proto === null) packet.sub_proto = undefined;
            packetQueue.push(packet);
            packetCount++;
        });

        totalPacketsEl.textContent = packetCount.toLocaleString();

        // Start queue processing
        if (!isProcessingQueue) {
            requestAnimationFrame(processPacketQueue);
        }
    };

    ws.onclose = function() {
        console.log('WebSocket connection closed');
        connectionStatusEl.textContent = 'Disconnected';
        statusText.textContent = 'Waiting...';
        statusDot.style.background = '#e53e3e';
        isRunning = false;
    };

    ws.onerror = function(error) {
        console.error('WebSocket error:', error);
        connectionStatusEl.textContent = 'Error';
        statusDot.style.background = '#ed8936';
    };
}

