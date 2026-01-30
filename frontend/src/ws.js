// Simple WebSocket client that forwards messages to a DOM event target
// Guard against multiple module executions (HMR) creating duplicate sockets.
const HOST = window.location.hostname || "localhost";
const PORT = 8000;
const WS_PATH = "/ws/alerts";

const createBus = () => {
  const target = new EventTarget();
  window.__IDS_WS_BUS = target;
  let ws = null;
  let reconnect = 1000;

  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${HOST}:${PORT}${WS_PATH}`;
    try {
      ws = new WebSocket(url);
      window.__IDS_WS_BUS.__ws = ws;
    } catch (e) {
      // schedule reconnect
      setTimeout(connect, reconnect);
      reconnect = Math.min(30000, reconnect * 2);
      return;
    }

    ws.onopen = () => {
      reconnect = 1000;
      target.dispatchEvent(new CustomEvent("status", { detail: "open" }));
    };
    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        target.dispatchEvent(new CustomEvent("alert", { detail: data }));
      } catch (e) {
        // ignore invalid messages
      }
    };
    ws.onclose = () => {
      target.dispatchEvent(new CustomEvent("status", { detail: "closed" }));
      // cleanup stored ws so a future module execution can reconnect
      if (window.__IDS_WS_BUS && window.__IDS_WS_BUS.__ws === ws) {
        delete window.__IDS_WS_BUS.__ws;
      }
      setTimeout(connect, reconnect);
      reconnect = Math.min(30000, reconnect * 2);
    };
    ws.onerror = () => {
      target.dispatchEvent(new CustomEvent("status", { detail: "error" }));
      try {
        ws.close();
      } catch (e) {}
    };
  }

  connect();
  return target;
};

const bus =
  window.__IDS_WS_BUS && window.__IDS_WS_BUS.__ws
    ? window.__IDS_WS_BUS
    : window.__IDS_WS_BUS
      ? window.__IDS_WS_BUS
      : createBus();

export default bus;
