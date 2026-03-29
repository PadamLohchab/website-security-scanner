// Background service worker for vulnerability scanner
chrome.runtime.onInstalled.addListener(() => {
  console.log('Vulnerability Scanner extension installed');
});

// Listen for scan results from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'scan-results') {
    try {
      // Store results
      chrome.storage.local.set({ lastScanResults: message.data }, () => {
        if (chrome.runtime.lastError) {
          console.error('Storage error:', chrome.runtime.lastError);
          return;
        }
        
        // Try to notify popup if it's open (this will fail silently if popup is closed)
        try {
          chrome.runtime.sendMessage({
            type: 'scan-complete',
            data: message.data
          }).catch(() => {
            // Popup might not be open, this is normal - ignore error
          });
        } catch (e) {
          // Ignore errors when popup is not open
        }
      });
    } catch (error) {
      console.error('Error processing scan results:', error);
    }
  }
  return true;
});

// Note: Security headers checking would require additional permissions
// and different API usage in Manifest V3. This functionality is handled
// via the content script's note about headers in the scan results.

