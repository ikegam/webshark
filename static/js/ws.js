'use strict';

// WebSocket transport: connects, reconnects with backoff, decompresses gzip
// batches and hands packets to app.js (ingestBatch / setContext / noteDropped).

(function () {
    let ws = null;
    let retry = 0;
    // Batches are decompressed asynchronously; chain them so they are applied
    // in arrival order.
    let queue = Promise.resolve();

    async function gunzipJson(buf) {
        const stream = new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'));
        return JSON.parse(await new Response(stream).text());
    }

    function connect() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        setConnState('connecting', retry ? `再接続中…（${retry}回目）` : '接続中…');
        ws = new WebSocket(`${proto}//${location.host}/ws`);
        ws.binaryType = 'arraybuffer';

        ws.onopen = () => {
            retry = 0;
            setConnState('open', 'キャプチャ中');
        };

        ws.onmessage = (event) => {
            if (typeof event.data === 'string') {
                let msg;
                try { msg = JSON.parse(event.data); } catch { return; }
                if (msg.type === 'ctx') setContext(msg);
                else if (msg.type === 'dropped') noteDropped(msg.count || 0);
                return;
            }
            const buf = event.data;
            queue = queue
                .then(() => gunzipJson(buf))
                .then((packets) => ingestBatch(packets))
                .catch((e) => console.error('Failed to decode batch:', e));
        };

        ws.onclose = () => {
            ws = null;
            const delay = Math.min(30000, 1000 * 2 ** Math.min(retry, 5));
            retry++;
            setConnState('closed', `切断（${Math.round(delay / 1000)}秒後に再接続）`);
            setTimeout(connect, delay);
        };

        ws.onerror = () => { /* onclose follows and handles reconnection */ };
    }

    if (typeof DecompressionStream === 'undefined') {
        setConnState('closed', 'このブラウザは非対応です（DecompressionStream なし）');
        return;
    }
    connect();
})();
