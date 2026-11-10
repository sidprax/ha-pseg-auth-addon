# PSE&G Home Assistant Add-ons

Official Home Assistant Add-on repository for the [PSE&G Integration](https://github.com/sidprax/ha-pseg).

Provides companion services to automate portal authentication, Google reCAPTCHA challenges, and session renewals for the PSE&G integration.

Supports two automated modes:
- **Direct MyMeter Account (Recommended)**: Logs into `mysmartenergy.nj.pseg.com` directly using an invited secondary user. Zero 2FA/SMS code required.
- **Primary PSE&G Account**: Navigates Okta SSO with automated reCAPTCHA solving and one-time verification passcodes (SMS/Email OTP).

> [!NOTE]
> While this repository is named `ha-pseg-auth-addon` for compatibility with existing installations, the companion service is designed to support any public MyMeter platform instance. If you use a utility powered by MyMeter outside of New Jersey and are interested in testing automated sign-in, please [open an issue](https://github.com/sidprax/ha-pseg/issues) or comment on [#2](https://github.com/sidprax/ha-pseg/issues/2).

## Add-ons in this Repository

### [PSE&G Auth Companion](pseg_auth/)
Headless Chromium service that automates sign-in and handles OTP/reCAPTCHA challenges for the PSE&G integration.

---

## Installation & Deployment Options

### Option 1: Home Assistant OS / Supervised (Recommended)

Home Assistant will automatically pull the pre-built multi-architecture container (`amd64` and `aarch64`) from GitHub Container Registry (`ghcr.io`):

#### 1-Click Setup via My Home Assistant

[![Open your Home Assistant instance and show the add add-on repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fsidprax%2Fha-pseg-auth-addon)

#### Manual Add-on Store Setup

1. In Home Assistant, navigate to **Settings** > **Add-ons** > **Add-on Store**.
2. Click the three dots (top right corner) > **Repositories**.
3. Add this repository URL:
   ```text
   https://github.com/sidprax/ha-pseg-auth-addon
   ```
4. Click **Add**, then close the dialog.
5. In the Add-on Store, find **PSE&G Auth Companion**, click **Install**, and **Start**.
6. Turn on **Start on boot** and **Watchdog**.

---

### Option 2: Standalone Docker (Pre-Built Image)

If you run Home Assistant Container, Home Assistant Core, or want to host the companion auth service on a separate server or NAS:

```bash
docker run -d \
  --name pseg-auth \
  --restart unless-stopped \
  -p 8000:8000 \
  ghcr.io/sidprax/ha-pseg-auth:latest
```

---

### Option 3: Build Docker Image from Source

You can build the Docker container image locally from the included source code:

1. Clone this repository:
   ```bash
   git clone https://github.com/sidprax/ha-pseg-auth-addon.git
   cd ha-pseg-auth-addon/pseg_auth
   ```

2. Build the image:
   ```bash
   docker build -t my-pseg-auth:latest .
   ```

3. Run the container:
   ```bash
   docker run -d \
     --name pseg-auth \
     --restart unless-stopped \
     -p 8000:8000 \
     my-pseg-auth:latest
   ```

---

### Option 4: Run Directly with Python (Local Development)

If you wish to run the service directly without Docker:

1. Requirements:
   - Python 3.10+
   - Chromium and `chromedriver` installed and in your system `PATH`
   - `ffmpeg` and `flac` installed (required for audio challenge transcription)

2. Install dependencies:
   ```bash
   pip install -r pseg_auth/requirements.txt
   ```

3. Start the server:
   ```bash
   python pseg_auth/auth_server.py
   ```
   The service listens on `http://0.0.0.0:8000`.

---

## License

MIT
