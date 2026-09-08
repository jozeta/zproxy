// Shared "save this text as a file" helper for export actions (History,
// Repeater). Side panel/popup pages are regular extension pages with a DOM,
// so URL.createObjectURL + chrome.downloads.download is the correct, direct
// path here (no third-party service, nothing leaves the machine).
export async function downloadText(filename, content, mimeType = "text/plain") {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  try {
    await chrome.downloads.download({ url, filename, saveAs: true });
  } finally {
    // Revoke once the download has been handed off; a short delay avoids
    // racing chrome.downloads reading the blob URL.
    setTimeout(() => URL.revokeObjectURL(url), 30_000);
  }
}
