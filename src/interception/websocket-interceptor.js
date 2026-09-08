// WebSocket support is observation-only. CDP has no fulfill/continue-style
// hook for a websocket frame — by the time Network.webSocketFrame{Sent,Received}
// fires, Chrome has already delivered the frame. See docs/CAPABILITIES.md row 15.
const framesByTab = new Map(); // tabId -> Map(requestId -> { url, frames: [] })
const MAX_FRAMES_PER_SOCKET = 500;

function getSocketMap(tabId) {
  if (!framesByTab.has(tabId)) framesByTab.set(tabId, new Map());
  return framesByTab.get(tabId);
}

export function handleEvent(tabId, method, params, emit) {
  const sockets = getSocketMap(tabId);

  if (method === "Network.webSocketCreated") {
    sockets.set(params.requestId, { url: params.url, frames: [] });
    emit({ type: "websocket-created", tabId, requestId: params.requestId, url: params.url });
    return;
  }

  const socket = sockets.get(params.requestId);
  if (!socket) return;

  const direction = method === "Network.webSocketFrameSent" ? "sent" : "received";
  const frame = {
    direction,
    time: Date.now(),
    opcode: params.response?.opcode,
    data: params.response?.payloadData ?? "",
  };
  socket.frames.push(frame);
  if (socket.frames.length > MAX_FRAMES_PER_SOCKET) socket.frames.shift();

  emit({ type: "websocket-frame", tabId, requestId: params.requestId, url: socket.url, frame });
}

export function getFrames(tabId, requestId) {
  return getSocketMap(tabId).get(requestId)?.frames ?? [];
}

export function getSockets(tabId) {
  return [...getSocketMap(tabId).entries()].map(([requestId, s]) => ({ requestId, url: s.url, frameCount: s.frames.length }));
}

export function clearTab(tabId) {
  framesByTab.delete(tabId);
}
