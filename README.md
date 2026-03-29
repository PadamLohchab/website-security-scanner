# 🔒 Website Security & Analysis Scanner

A powerful Chrome browser extension that helps you analyze and assess the security of any website instantly — right from your browser toolbar.

---

## 📸 Overview

Website Security & Analysis Scanner is a Chrome extension that provides real-time security insights for any website you visit. It checks for SSL certificates, security headers, known vulnerabilities, cookies, and much more — all in one click.

---

## ✨ Features

- 🔐 **SSL/TLS Certificate Check** — Verifies if the site uses HTTPS and checks certificate validity
- 🛡️ **Security Headers Analysis** — Detects missing or misconfigured headers (CSP, X-Frame-Options, HSTS, etc.)
- 🍪 **Cookie Security Scan** — Flags cookies missing `Secure`, `HttpOnly`, or `SameSite` attributes
- 🌐 **WHOIS & Domain Info** — Displays domain registration and ownership details
- ⚠️ **Vulnerability Detection** — Identifies common web security issues
- 📊 **Security Score** — Gives the website an overall security rating
- 🧩 **Technology Detection** — Identifies frameworks, CMS, and libraries used on the site
- 📋 **Detailed Report View** — Clean popup UI with a breakdown of all findings

---

## 🚀 Installation

### Load Unpacked (Developer Mode)

1. Clone or download this repository:
   ```bash
   git clone https://github.com/your-username/website-security-scanner.git
   ```

2. Open Chrome and go to:
   ```
   chrome://extensions/
   ```

3. Enable **Developer Mode** (toggle in the top right corner)

4. Click **"Load unpacked"** and select the project folder

5. The extension icon will appear in your Chrome toolbar ✅

---

## 🛠️ How to Use

1. Visit any website you want to analyze
2. Click the 🔒 extension icon in the Chrome toolbar
3. The popup will display a full security report for the current site
4. Review the findings and security score

---

## 📁 Project Structure

```
website-security-scanner/
│
├── manifest.json        # Extension configuration
├── popup.html           # Extension UI
├── popup.js             # Main logic & security checks
├── content.js           # Content script (page interaction)
├── background.js        # Background service worker
├── styles.css           # Styling for the popup
├── icons/               # Extension icons (16x16, 48x48, 128x128)
└── README.md            # Project documentation
```

---

## 🔧 Technologies Used

- **HTML / CSS / JavaScript** — Core extension frontend
- **Chrome Extension API (Manifest V3)** — Browser integration
- **Fetch API** — External security data retrieval

---

## 📋 Permissions Used

| Permission | Reason |
|---|---|
| `activeTab` | To scan the currently open website |
| `scripting` | To inject content scripts for analysis |
| `storage` | To store scan history and settings |
| `host_permissions` | To fetch security data from external APIs |

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Make your changes and commit: `git commit -m "Add your feature"`
4. Push to your branch: `git push origin feature/your-feature-name`
5. Open a Pull Request

---

## 🐛 Known Issues / Limitations

- Some security headers may not be accessible due to browser CORS restrictions
- Real-time vulnerability checks depend on external API availability
- Extension works best on HTTPS websites

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

**Your Name**
- GitHub: [Padam Lohchab]([https://github.com/](https://github.com/PadamLohchab))

---

## ⭐ Show Your Support

If you find this extension useful, please consider giving it a ⭐ on GitHub — it helps a lot!
