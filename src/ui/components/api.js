// Thin RPC client used by every UI surface (popup + side panel) to talk to
// the service worker. See src/background/service-worker.js for the handler
// table this calls into.
export function call(type, payload) {
  return chrome.runtime.sendMessage({ type, payload }).then((response) => {
    if (!response) throw new Error(`No response for "${type}" (service worker may be starting up — try again).`);
    if (!response.ok) throw new Error(response.error || `"${type}" failed`);
    return response.result;
  });
}

/** Subscribes to background-pushed events ("history:new-entry", "intercept:event"). */
export function onPush(callback) {
  const listener = (message) => {
    if (message?.type === "push") callback(message.event);
  };
  chrome.runtime.onMessage.addListener(listener);
  return () => chrome.runtime.onMessage.removeListener(listener);
}

export async function getCurrentTab() {
  return call("tabs:current");
}
