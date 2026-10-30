import shutil
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
import speech_recognition as sr
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("pseg_auth_server")

PROFILE_DIR = os.environ.get("PSEG_PROFILE_DIR", "/data/browser_data")
PORT = int(os.environ.get("PORT", 8000))

active_driver = None

ALLOWED_RECAPTCHA_HOSTS = {
    "www.google.com",
    "google.com",
    "www.recaptcha.net",
    "recaptcha.net",
}


def is_safe_recaptcha_url(url: str) -> bool:
    """Ensure URL is HTTPS and points to an authorized Google reCAPTCHA host."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urllib.parse.urlparse(url.strip())
        if parsed.scheme.lower() != "https":
            return False
        hostname = (parsed.hostname or "").lower()
        return hostname in ALLOWED_RECAPTCHA_HOSTS
    except Exception:
        return False


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Ensure HTTP redirects stay strictly within authorized reCAPTCHA hostnames and HTTPS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_safe_recaptcha_url(newurl):
            raise urllib.error.HTTPError(
                newurl, code, f"Disallowed redirect to untrusted target: {newurl}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_recaptcha_audio(src: str, dest_path: str, max_bytes: int = 5 * 1024 * 1024) -> None:
    """Download audio challenge verifying every URL and redirect against SSRF rules."""
    if not is_safe_recaptcha_url(src):
        raise ValueError("audio-source src is missing or untrusted")

    opener = urllib.request.build_opener(SafeRedirectHandler())
    req = urllib.request.Request(
        src,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    )
    with opener.open(req, timeout=15) as resp:
        final_url = resp.geturl()
        if not is_safe_recaptcha_url(final_url):
            raise ValueError(f"Final redirect URL untrusted: {final_url}")

        downloaded = 0
        with open(dest_path, "wb") as out_f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > max_bytes:
                    raise ValueError("Audio challenge payload exceeded size limit")
                out_f.write(chunk)


def solve_recaptcha_if_present(driver):
    time.sleep(2)
    bframes = [f for f in driver.find_elements(By.TAG_NAME, 'iframe') if 'bframe' in (f.get_attribute('src') or '')]
    if not bframes:
        return
    logger.info("reCAPTCHA detected. Solving via audio challenge...")
    driver.switch_to.frame(bframes[0])
    try:
        audio_btn = driver.find_elements(By.ID, 'recaptcha-audio-button')
        if not audio_btn:
            raise Exception("recaptcha_blocked: Audio challenge button not available")
        audio_btn[0].click()
        time.sleep(3)

        body_text = driver.find_element(By.TAG_NAME, 'body').text
        if "automated queries" in body_text.lower() or "try again later" in body_text.lower():
            raise Exception("recaptcha_blocked: Google flagged automated queries and blocked audio challenge")

        audio_sources = driver.find_elements(By.ID, 'audio-source')
        if not audio_sources:
            raise Exception("recaptcha_blocked: Unable to locate audio-source (challenge throttled by Google)")

        src = audio_sources[0].get_attribute('src')
        if not src or not is_safe_recaptcha_url(src):
            raise Exception("recaptcha_blocked: audio-source src is missing or untrusted")

        with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as mp3_tmp:
            mp3_path = mp3_tmp.name
        wav_path = mp3_path.replace(".mp3", ".wav")

        try:
            download_recaptcha_audio(src, mp3_path)
            subprocess.run(
                ['ffmpeg', '-y', '-i', mp3_path, wav_path],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            r = sr.Recognizer()
            with sr.AudioFile(wav_path) as source:
                audio = r.record(source)
            text = r.recognize_google(audio)
            logger.info("Audio transcribed successfully")

            inp = driver.find_element(By.ID, 'audio-response')
            inp.send_keys(text)
            time.sleep(1)
            driver.find_element(By.ID, 'recaptcha-verify-button').click()
            time.sleep(3)
        finally:
            for temp_f in (mp3_path, wav_path):
                if temp_f and os.path.exists(temp_f):
                    try:
                        os.remove(temp_f)
                    except OSError:
                        pass
    finally:
        driver.switch_to.default_content()

def init_driver():
    os.makedirs(PROFILE_DIR, exist_ok=True)
    opts = Options()
    opts.add_argument('--headless=new')
    opts.add_argument('--no-sandbox')
    opts.add_argument('--disable-dev-shm-usage')
    opts.add_argument('--disable-gpu')
    opts.add_argument('--window-size=1280,800')
    opts.add_argument(f'--user-data-dir={PROFILE_DIR}')
    opts.add_argument('--disable-blink-features=AutomationControlled')
    opts.add_experimental_option('excludeSwitches', ['enable-automation'])
    opts.add_experimental_option('useAutomationExtension', False)
    opts.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')

    chrome_bin = (
        shutil.which("chromium-browser")
        or shutil.which("chromium")
        or "/usr/bin/chromium-browser"
    )
    opts.binary_location = chrome_bin

    chromedriver_bin = shutil.which("chromedriver") or "/usr/bin/chromedriver"
    service = Service(chromedriver_bin)

    d = webdriver.Chrome(service=service, options=opts)
    d.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
        'source': 'Object.defineProperty(navigator, "webdriver", {get: () => undefined});'
    })
    return d

class PsegAuthHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    def do_GET(self):
        if self.path == '/health':
            self._send_json(200, {"status": "healthy", "service": "pseg_auth_server"})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        global active_driver
        content_len_hdr = self.headers.get('Content-Length')
        try:
            length = int(content_len_hdr) if content_len_hdr else 0
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length header"})
            return

        if length < 0 or length > 65536:
            self._send_json(413, {"error": "Payload exceeds maximum allowed size of 64KB"})
            return

        body = self.rfile.read(length).decode('utf-8', errors='replace')
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}

        if self.path == '/login':
            username = data.get('username')
            password = data.get('password')
            mfa_method = data.get('mfa_method', 'sms').lower()
            dispatch_mfa = data.get('dispatch_mfa', False)
            auth_type = data.get('auth_type', 'auto').lower()

            if not username or not password:
                self._send_json(400, {"error": "username and password required"})
                return

            if active_driver:
                try:
                    active_driver.quit()
                except Exception:
                    pass
                active_driver = None

            try:
                # Direct MyMeter invited-user flow (No Okta, No 2FA OTP required)
                if auth_type == 'mymeter':
                    logger.info("Starting Direct MyMeter login for user %s (no 2FA required)...", username)
                    driver = init_driver()
                    active_driver = driver

                    driver.get("https://mysmartenergy.nj.pseg.com/")
                    time.sleep(3)
                    logger.info("Page loaded. Current URL: %s (Title: %s)", driver.current_url, driver.title)

                    # Check if already authenticated (only if Dashboard reached and login inputs absent)
                    email_inputs = driver.find_elements(By.ID, "LoginEmail")
                    if not email_inputs and "Dashboard" in driver.current_url:
                        logger.info("Already authenticated! Capturing cookies directly.")
                        cookies = driver.get_cookies()
                        cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies if 'pseg.com' in c.get('domain', '')])
                        driver.quit()
                        active_driver = None
                        self._send_json(200, {"success": True, "cookies": cookie_str})
                        return

                    # Wait for login inputs if not immediately available
                    for _ in range(10):
                        if email_inputs and driver.find_elements(By.ID, "LoginPassword"):
                            break
                        time.sleep(1)
                        email_inputs = driver.find_elements(By.ID, "LoginEmail")

                    pass_inputs = driver.find_elements(By.ID, "LoginPassword")
                    if not email_inputs or not pass_inputs:
                        raise Exception("MyMeter login inputs (#LoginEmail, #LoginPassword) not found on page")

                    email_inputs[0].clear()
                    email_inputs[0].send_keys(username)
                    time.sleep(0.5)

                    pass_inputs[0].clear()
                    pass_inputs[0].send_keys(password)
                    time.sleep(0.5)

                    # Ensure 'Remember Me' is enabled for persistent cookies
                    rem_inputs = driver.find_elements(By.ID, "RememberMe")
                    if rem_inputs:
                        try:
                            if not rem_inputs[0].is_selected():
                                rem_inputs[0].click()
                        except Exception:
                            driver.execute_script("arguments[0].checked = true;", rem_inputs[0])

                    login_btn = driver.find_elements(By.CSS_SELECTOR, ".loginBtn")
                    if login_btn:
                        login_btn[0].click()
                    time.sleep(3)

                    solve_recaptcha_if_present(driver)

                    # Wait up to 25 seconds for dashboard navigation
                    for _ in range(25):
                        if "Dashboard" in driver.current_url:
                            break
                        solve_recaptcha_if_present(driver)
                        error_els = driver.find_elements(By.CSS_SELECTOR, ".error, [data-valmsg-for='LoginErrorMessage']")
                        if error_els and error_els[0].text.strip():
                            raise Exception(f"MyMeter login error: {error_els[0].text.strip()}")
                        time.sleep(1)

                    cookies = driver.get_cookies()
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies if 'pseg.com' in c.get('domain', '')])
                    if "Dashboard" in driver.current_url and "MM_SID" in cookie_str:
                        logger.info("MyMeter direct login successful! Cookies captured.")
                        driver.quit()
                        active_driver = None
                        self._send_json(200, {"success": True, "cookies": cookie_str})
                        return

                    error_els = driver.find_elements(By.CSS_SELECTOR, ".error, [data-valmsg-for='LoginErrorMessage']")
                    err_text = error_els[0].text if error_els and error_els[0].text else "MyMeter direct login failed to reach Dashboard"
                    raise Exception(err_text)

                # Standard PSE&G Okta SSO flow
                logger.info(
                    "Starting Okta SSO login for user %s with MFA %s (dispatch_mfa=%s)...",
                    username,
                    mfa_method,
                    dispatch_mfa,
                )
                driver = init_driver()
                active_driver = driver

                driver.get("https://mysmartenergy.nj.pseg.com/Saml/okta-prod/SignIn")
                time.sleep(4)
                logger.info("Page loaded. Current URL: %s (Title: %s)", driver.current_url, driver.title)

                # Check if already authenticated and redirected directly
                if "mysmartenergy.nj.pseg.com" in driver.current_url and "SignIn" not in driver.current_url:
                    logger.info("Already authenticated! Capturing cookies directly.")
                    cookies = driver.get_cookies()
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies if 'pseg.com' in c.get('domain', '')])
                    driver.quit()
                    active_driver = None
                    self._send_json(200, {"success": True, "cookies": cookie_str})
                    return

                # Enter username
                user_inputs = driver.find_elements(By.CSS_SELECTOR, "input[name='identifier']")
                if user_inputs:
                    user_inputs[0].clear()
                    user_inputs[0].send_keys(username)
                    time.sleep(1)
                    user_inputs[0].send_keys(Keys.ENTER)
                    time.sleep(4)
                    solve_recaptcha_if_present(driver)

                # Enter password
                for _ in range(15):
                    pass_inputs = driver.find_elements(By.CSS_SELECTOR, "input[name='credentials.passcode']")
                    if pass_inputs:
                        break
                    time.sleep(1)
                else:
                    raise Exception("Password field not found")

                pass_inputs[0].send_keys(password)
                time.sleep(1)
                pass_inputs[0].send_keys(Keys.ENTER)
                time.sleep(6)

                # Check if redirected directly
                if "mysmartenergy.nj.pseg.com" in driver.current_url and "SignIn" not in driver.current_url:
                    cookies = driver.get_cookies()
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies if 'pseg.com' in c.get('domain', '')])
                    driver.quit()
                    active_driver = None
                    self._send_json(200, {"success": True, "cookies": cookie_str})
                    return

                # Check if MFA selection is presented
                phone_btns = driver.find_elements(By.CSS_SELECTOR, "a[aria-label*='Select Phone'], button[aria-label*='Select Phone']")
                email_btns = driver.find_elements(By.CSS_SELECTOR, "a[aria-label*='Select Email'], button[aria-label*='Select Email']")

                if phone_btns or email_btns:
                    if not dispatch_mfa:
                        logger.info("MFA required, but dispatch_mfa=False (background poll). Closing session without sending code.")
                        driver.quit()
                        active_driver = None
                        self._send_json(200, {"success": False, "mfa_required": True, "dispatched": False})
                        return

                    if mfa_method == 'email':
                        if email_btns:
                            logger.info("Selecting Email MFA...")
                            email_btns[0].click()
                            time.sleep(4)
                        send_email_btns = driver.find_elements(
                            By.CSS_SELECTOR,
                            "input[value*='Send'], input[value*='send'], button[data-type='save'], button[type='submit'], input[type='submit'], a[aria-label*='Send']"
                        )
                        if send_email_btns:
                            logger.info("Clicking Send Email button...")
                            send_email_btns[0].click()
                            time.sleep(4)
                    elif phone_btns:
                        logger.info("Selecting Phone MFA...")
                        phone_btns[0].click()
                        time.sleep(4)
                        sms_btns = driver.find_elements(By.CSS_SELECTOR, "a[aria-label*='SMS'], button[aria-label*='SMS'], input[value*='SMS']")
                        if sms_btns:
                            sms_btns[0].click()
                            time.sleep(4)

                    logger.info("MFA dispatched! Waiting for code...")
                    self._send_json(200, {"success": False, "mfa_required": True, "dispatched": True})
                    return

                # Check if already on passcode prompt
                passcode_candidates = driver.find_elements(
                    By.CSS_SELECTOR,
                    "input[name='credentials.passcode'], input[type='tel'], input[name='passcode'], input[name='answer'], input[autocomplete='one-time-code']"
                )
                passcode_inputs = [inp for inp in passcode_candidates if inp.is_displayed() and inp.is_enabled()]
                if passcode_inputs:
                    if not dispatch_mfa:
                        logger.info("MFA challenge active, but dispatch_mfa=False. Closing session without dispatch.")
                        driver.quit()
                        active_driver = None
                        self._send_json(200, {"success": False, "mfa_required": True, "dispatched": False})
                        return
                    logger.info("MFA prompt ready. Waiting for code...")
                    self._send_json(200, {"success": False, "mfa_required": True, "dispatched": True})
                    return
            except Exception as e:
                curr_url = getattr(active_driver, 'current_url', 'unknown')
                logger.error("Login failed at URL %s: %s", curr_url, e)
                err_msg = str(e)
                if active_driver:
                    try:
                        active_driver.quit()
                    except Exception:
                        pass
                    active_driver = None
                logger.debug("Active driver closed after login failure")
                status_code = 403 if "recaptcha_blocked" in err_msg else 500
                self._send_json(status_code, {
                    "error": err_msg,
                    "recaptcha_blocked": "recaptcha_blocked" in err_msg
                })

        elif self.path == '/login/mfa':
            code = data.get('code', '').strip()
            if not active_driver:
                self._send_json(400, {"error": "No active login session. Call /login first."})
                return
            if not code:
                self._send_json(400, {"error": "code required"})
                return

            try:
                driver = active_driver
                candidates = driver.find_elements(
                    By.CSS_SELECTOR,
                    "input[name='credentials.passcode'], input[type='tel'], input[name='passcode'], input[name='answer'], input[autocomplete='one-time-code']"
                )
                passcode_inputs = [inp for inp in candidates if inp.is_displayed() and inp.is_enabled()]
                if not passcode_inputs:
                    text_candidates = driver.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='tel'], input:not([type='hidden'])")
                    passcode_inputs = [inp for inp in text_candidates if inp.is_displayed() and inp.is_enabled()]

                if not passcode_inputs:
                    raise Exception("Visible OTP input field not found on page")

                target_input = passcode_inputs[0]
                logger.info("Entering OTP verification code into visible input...")
                driver.execute_script("arguments[0].scrollIntoView(true);", target_input)
                time.sleep(0.5)
                try:
                    target_input.clear()
                except Exception:
                    target_input.send_keys(Keys.CONTROL + "a", Keys.BACKSPACE)

                target_input.send_keys(code)
                time.sleep(1)
                target_input.send_keys(Keys.ENTER)

                # Also click submit/verify button if present
                verify_btns = [
                    b for b in driver.find_elements(
                        By.CSS_SELECTOR,
                        "input[value*='Verify'], button[data-type='save'], input[data-type='save'], button[type='submit'], input[type='submit']"
                    )
                    if b.is_displayed() and b.is_enabled()
                ]
                if verify_btns:
                    try:
                        verify_btns[0].click()
                    except Exception:
                        pass

                for _ in range(25):
                    time.sleep(1)
                    if "mysmartenergy.nj.pseg.com" in driver.current_url and "SignIn" not in driver.current_url:
                        logger.info("SAML redirect complete!")
                        break
                else:
                    raise Exception("Timed out waiting for portal redirect after OTP")

                cookies = driver.get_cookies()
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies if 'pseg.com' in c.get('domain', '')])
                driver.quit()
                active_driver = None
                self._send_json(200, {"success": True, "cookies": cookie_str})
            except Exception as e:
                logger.error("MFA completion failed: %s", e)
                if active_driver:
                    try:
                        active_driver.quit()
                    except Exception:
                        pass
                    active_driver = None
                self._send_json(500, {"error": str(e)})
        else:
            self._send_json(404, {"error": "Not found"})

if __name__ == '__main__':
    logger.info("Starting PSEG Auth Server on port %d...", PORT)
    server = HTTPServer(('0.0.0.0', PORT), PsegAuthHandler)
    server.serve_forever()
