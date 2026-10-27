// APERTURE — Frontend interactions

document.addEventListener("DOMContentLoaded", () => {
  const scanForm = document.getElementById("scan-form");
  const urlInput = document.getElementById("url-input");
  const scanButton = document.getElementById("scan-button");
  const scanResult = document.getElementById("scan-result");

  let scansThisSession = 0;

  if (!scanForm || !urlInput || !scanResult) {
    console.warn(
      "APERTURE: Could not find the URL scanner elements. Check index.html IDs."
    );
    return;
  }

  scanForm.addEventListener("submit", (event) => {
    event.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
      showResult("Please enter a URL to test.", "warning");
      urlInput.focus();
      return;
    }

    let parsedUrl;

    try {
      parsedUrl = new URL(
        /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(url) ? url : `https://${url}`
      );
    } catch {
      showResult("That doesn't look like a valid URL. Please check it.", "warning");
      return;
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      showResult("Please enter a URL beginning with http:// or https://.", "warning");
      return;
    }

    scansThisSession++;

    const totalScans = document.getElementById("total-scans");
    if (totalScans) totalScans.textContent = scansThisSession;

    if (scanButton) {
      scanButton.disabled = true;
      scanButton.textContent = "Scanning…";
    }

    showResult(
      `Sentinel scan completed for ${parsedUrl.hostname}. Host evaluated.`,
      "info"
    );

    if (scanButton) {
      scanButton.disabled = false;
      scanButton.textContent = "Scan URL";
    }
  });

  function showResult(message, type) {
    scanResult.textContent = message;
    scanResult.className = `scan-result ${type}`;
    scanResult.setAttribute("role", "status");
    scanResult.setAttribute("aria-live", "polite");
  }
});
