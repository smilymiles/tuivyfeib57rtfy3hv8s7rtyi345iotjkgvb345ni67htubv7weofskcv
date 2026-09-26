import os, time, json, base64, secrets, hashlib, hmac, logging, uuid, re
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, g
import requests
import jwt as pyjwt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("watertag-api")

class Config:
    META_APP_ID          = os.environ.get("META_APP_ID", "")
    META_APP_SECRET      = os.environ.get("META_APP_SECRET", "")
    OCULUS_ACCESS_TOKEN  = os.environ.get("OCULUS_ACCESS_TOKEN", "")
    JWT_SECRET           = os.environ.get("JWT_SECRET", secrets.token_hex(32))
    NONCE_SIGNING_KEY    = os.environ.get("NONCE_SIGNING_KEY", secrets.token_hex(32))
    PHOTON_REALTIME_ID   = os.environ.get("PHOTON_REALTIME_ID", "")
    PHOTON_VOICE_ID      = os.environ.get("PHOTON_VOICE_ID", "")
    PLAYFAB_TITLE_ID     = os.environ.get("PLAYFAB_TITLE_ID", "")
    PLAYFAB_SECRET_KEY   = os.environ.get("PLAYFAB_SECRET_KEY", "")
    GAME_VERSION         = os.environ.get("GAME_VERSION", "1.0.0")
    ENVIRONMENT          = os.environ.get("ENVIRONMENT", "production")
    CORS_ORIGIN          = os.environ.get("CORS_ORIGIN", "*")
    CACHE_TTL            = int(os.environ.get("CACHE_TTL", "300"))
    RATE_LIMIT_REQUESTS  = int(os.environ.get("RATE_LIMIT_REQUESTS", "60"))
    RATE_LIMIT_WINDOW    = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))

config = Config()

META_GRAPH_BASE = "https://graph.oculus.com"
NONCE_BYTE_LENGTH = 32
NONCE_MAX_AGE = 300
ATTESTATION_TIMESTAMP_TOLERANCE = 300
TOKEN_EXPIRY_HOURS = 24

app = Flask(__name__)

_rate_limit_store = {}

def check_rate_limit(client_id):
    if not config.RATE_LIMIT_REQUESTS:
        return True
    now = time.time()
    window_start = now - config.RATE_LIMIT_WINDOW
    if client_id not in _rate_limit_store:
        _rate_limit_store[client_id] = []
    _rate_limit_store[client_id] = [t for t in _rate_limit_store[client_id] if t > window_start]
    if len(_rate_limit_store[client_id]) >= config.RATE_LIMIT_REQUESTS:
        return False
    _rate_limit_store[client_id].append(now)
    if len(_rate_limit_store) > 10000:
        old_keys = [k for k, v in _rate_limit_store.items() if not v or v[-1] < window_start]
        for k in old_keys:
            del _rate_limit_store[k]
    return True

@app.after_request
def cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = config.CORS_ORIGIN
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

def require_json(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == "POST":
            if not request.is_json:
                return jsonify({"success": False, "code": "INVALID_CONTENT_TYPE", "message": "Request must be application/json"}), 415
            g.body = request.get_json(silent=True) or {}
        return f(*args, **kwargs)
    return wrapper

def make_error(code, message, http_status=400):
    return jsonify({"success": False, "code": code, "message": message}), http_status

def make_success(data=None, message="Success"):
    resp = {"success": True, "message": message}
    if data is not None:
        resp["data"] = data
    return jsonify(resp), 200

def now_ts():
    return int(time.time())

def generate_challenge_nonce():
    raw = secrets.token_bytes(NONCE_BYTE_LENGTH)
    b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return b64

def sign_nonce(nonce, expiry=None):
    if expiry is None:
        expiry = now_ts() + NONCE_MAX_AGE
    payload = f"{nonce}:{expiry}"
    sig = hmac.new(config.NONCE_SIGNING_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

def verify_signed_nonce(signed):
    try:
        decoded = base64.urlsafe_b64decode(signed + "==").decode()
        parts = decoded.split(":")
        if len(parts) < 3:
            return None
        nonce = ":".join(parts[:-2])
        expiry = int(parts[-2])
        sig = parts[-1]
        expected = hmac.new(config.NONCE_SIGNING_KEY.encode(), f"{nonce}:{expiry}".encode(), hashlib.sha256).hexdigest()[:16]
        if sig != expected:
            return None
        if now_ts() > expiry:
            return None
        return nonce
    except Exception as e:
        logger.warning(f"Nonce verification failed: {e}")
        return None

def create_auth_token(uid, extra=None):
    payload = {"uid": str(uid), "iat": now_ts(), "exp": now_ts() + TOKEN_EXPIRY_HOURS * 3600, "type": "auth"}
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, config.JWT_SECRET, algorithm="HS256")

def verify_token(token):
    try:
        return pyjwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        return None
    except Exception:
        return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return make_error("MISSING_TOKEN", "Missing or invalid Authorization header", 401)
        token = auth[7:]
        payload = verify_token(token)
        if not payload:
            return make_error("INVALID_TOKEN", "Token is invalid or expired", 401)
        g.uid = payload.get("uid")
        g.token_payload = payload
        if not check_rate_limit(g.uid or request.remote_addr):
            return make_error("RATE_LIMITED", "Too many requests. Please try again later.", 429)
        return f(*args, **kwargs)
    return wrapper

def verify_oculus_nonce(user_id, nonce):
    access_token = config.OCULUS_ACCESS_TOKEN
    if not access_token:
        access_token = f"{config.META_APP_ID}|{config.META_APP_SECRET}"
    url = f"{META_GRAPH_BASE}/user_nonce_validate?user_id={user_id}&nonce={nonce}&access_token={access_token}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        logger.error(f"Oculus nonce verify failed: {e}")
        return None

def verify_attestation_token(attestation_token):
    access_token = config.OCULUS_ACCESS_TOKEN
    if not access_token:
        access_token = f"OC|{config.META_APP_ID}|{config.META_APP_SECRET}"
    url = f"{META_GRAPH_BASE}/platform_integrity/verify?token={attestation_token}&access_token={access_token}"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        logger.error(f"Attestation verify failed: {e}")
        return None

def parse_attestation_claims(verify_result):
    data = verify_result.get("data", [])
    if not data:
        return None, None
    entry = data[0]
    message = entry.get("message", "")
    claims_b64 = entry.get("claims", "")
    if message != "success" or not claims_b64:
        return message, None
    try:
        padded = claims_b64 + "=" * (4 - len(claims_b64) % 4)
        claims_json = base64.urlsafe_b64decode(padded).decode()
        claims = json.loads(claims_json)
        return message, claims
    except Exception as e:
        logger.error(f"Failed to decode claims: {e}")
        return message, None

def playfab_login(oculus_user_id, oculus_username=None):
    if not config.PLAYFAB_TITLE_ID or not config.PLAYFAB_SECRET_KEY:
        return make_error("PLAYFAB_NOT_CONFIGURED", "PlayFab is not configured on the server", 500)
    custom_id = f"sul_oculus_{oculus_user_id}"
    url = f"https://{config.PLAYFAB_TITLE_ID}.playfabapi.com/Client/LoginWithCustomID"
    headers = {
        "Content-Type": "application/json",
        "X-Authorization": config.PLAYFAB_SECRET_KEY
    }
    body = {
        "CustomId": custom_id,
        "CreateAccount": True,
        "TitleId": config.PLAYFAB_TITLE_ID
    }
    if oculus_username:
        body["DisplayName"] = re.sub(r'[^\w\s.-]', '', oculus_username)[:25]
    try:
        r = requests.post(url, json=body, headers=headers, timeout=15)
        r.raise_for_status()
        result = r.json()
        if result.get("code") != 200:
            return None, result.get("errorMessage", "PlayFab login failed")
        data = result.get("data", {})
        return {
            "sessionTicket": data.get("SessionTicket"),
            "playFabId": data.get("PlayFabId"),
            "newlyCreated": data.get("NewlyCreated", False),
            "lastLogin": data.get("LastLoginTime", "")
        }, None
    except requests.RequestException as e:
        logger.error(f"PlayFab login failed: {e}")
        return None, str(e)

def playfab_update_user_data(playfab_id, data_dict, session_ticket=None):
    if not config.PLAYFAB_TITLE_ID or not config.PLAYFAB_SECRET_KEY:
        return None
    url = f"https://{config.PLAYFAB_TITLE_ID}.playfabapi.com/Server/UpdateUserReadOnlyData"
    headers = {
        "Content-Type": "application/json",
        "X-SecretKey": config.PLAYFAB_SECRET_KEY
    }
    body = {
        "PlayFabId": playfab_id,
        "Data": data_dict
    }
    try:
        r = requests.post(url, json=body, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        logger.warning(f"PlayFab update data failed: {e}")
        return None

def build_photon_auth_data(oculus_id, oculus_nonce, display_name):
    return {
        "oculusId": oculus_id,
        "nonce": oculus_nonce,
        "displayName": display_name,
        "appVersion": config.GAME_VERSION,
        "photonRealtimeAppId": config.PHOTON_REALTIME_ID,
        "photonVoiceAppId": config.PHOTON_VOICE_ID
    }

class Validators:
    @staticmethod
    def non_empty_string(val, field_name):
        if not val or not isinstance(val, str) or not val.strip():
            return f"{field_name} is required and must be a non-empty string"
        return None

    @staticmethod
    def valid_attestation_token(val):
        err = Validators.non_empty_string(val, "attestationToken")
        if err:
            return err
        if len(val) < 50:
            return "attestationToken appears to be too short"
        return None

@app.route("/", methods=["GET"])
def home():
    return make_success({
        "status": "online",
        "game": "WaterTag",
        "version": config.GAME_VERSION,
        "environment": config.ENVIRONMENT,
        "features": {
            "oculusAuth": bool(config.META_APP_ID),
            "attestation": bool(config.META_APP_ID),
            "photonRealtime": bool(config.PHOTON_REALTIME_ID),
            "photonVoice": bool(config.PHOTON_VOICE_ID),
            "playfab": bool(config.PLAYFAB_TITLE_ID)
        }
    })

@app.route("/health", methods=["GET"])
def health():
    return make_success({
        "timestamp": now_ts(),
        "uptime": time.time() - app._start_time if hasattr(app, "_start_time") else 0
    })

app._start_time = time.time()

@app.route("/auth/oculus", methods=["POST"])
@require_json
def auth_oculus():
    body = g.body
    user_id = body.get("userId") or body.get("user_id") or body.get("uid")
    nonce = body.get("nonce")
    display_name = body.get("displayName", "Unknown Player")

    err = Validators.non_empty_string(user_id, "userId")
    if not err:
        err = Validators.non_empty_string(nonce, "nonce")
    if err:
        return make_error("VALIDATION_ERROR", err, 400)

    if not config.META_APP_ID or not config.META_APP_SECRET:
        return make_error("SERVER_NOT_CONFIGURED", "Meta OAuth is not configured on the server", 500)

    result = verify_oculus_nonce(user_id, nonce)
    if result is None:
        return make_error("UPSTREAM_ERROR", "Failed to reach Meta authentication servers", 502)

    if not result.get("is_valid", False):
        return make_error("INVALID_PROOF", "Oculus proof is invalid. Make sure the nonce matches the user ID.", 401)

    token = create_auth_token(user_id, {"provider": "oculus", "displayName": display_name})
    return make_success({
        "token": token,
        "userId": user_id,
        "displayName": display_name,
        "expiresIn": TOKEN_EXPIRY_HOURS * 3600
    }, "Oculus identity verified")

@app.route("/challenge-nonce", methods=["GET"])
@require_auth
def get_challenge_nonce():
    raw_nonce = generate_challenge_nonce()
    signed = sign_nonce(raw_nonce)
    return make_success({
        "challengeNonce": raw_nonce,
        "signedNonce": signed,
        "expiresIn": NONCE_MAX_AGE
    }, "Challenge nonce generated")

@app.route("/verify-attestation", methods=["POST"])
@require_json
@require_auth
def verify_attestation():
    body = g.body
    attestation_token = body.get("attestationToken") or body.get("attestation_token")
    signed_nonce = body.get("signedNonce") or body.get("signed_nonce")
    expected_nonce = body.get("expectedNonce") or body.get("expected_nonce")

    err = Validators.valid_attestation_token(attestation_token)
    if err:
        return make_error("VALIDATION_ERROR", err, 400)

    if not config.META_APP_ID or not config.META_APP_SECRET:
        return make_error("SERVER_NOT_CONFIGURED", "Attestation API is not configured", 500)

    if signed_nonce:
        challenge_nonce = verify_signed_nonce(signed_nonce)
        if not challenge_nonce:
            return make_error("NONCE_INVALID", "The signed nonce is invalid or has expired", 401)
        if expected_nonce and challenge_nonce != expected_nonce:
            return make_error("NONCE_MISMATCH", "Challenge nonce mismatch", 401)

    result = verify_attestation_token(attestation_token)
    if result is None:
        return make_error("UPSTREAM_ERROR", "Failed to reach Meta Attestation servers", 502)

    message, claims = parse_attestation_claims(result)

    if message != "success":
        return make_error("ATTESTATION_FAILED", f"Attestation verification failed: {message}", 401)

    if not claims:
        return make_error("INVALID_CLAIMS", "Could not parse attestation claims", 500)

    request_details = claims.get("request_details", {})
    app_state = claims.get("app_state", {})
    device_state = claims.get("device_state", {})
    device_ban = claims.get("device_ban", {})

    if signed_nonce and challenge_nonce:
        claim_nonce = request_details.get("nonce", "")
        if claim_nonce != challenge_nonce:
            return make_error("NONCE_MISMATCH", "Replay attack detected: nonce in claim does not match", 401)

    claim_ts = request_details.get("timestamp", 0)
    if abs(now_ts() - claim_ts) > ATTESTATION_TIMESTAMP_TOLERANCE:
        logger.warning(f"Attestation timestamp drift: claim={claim_ts}, server={now_ts()}")

    claim_exp = request_details.get("exp", 0)
    if now_ts() > claim_exp:
        return make_error("TOKEN_EXPIRED", "Attestation token has expired", 401)

    playback_token = create_auth_token(g.uid, {
        "type": "attested",
        "appIntegrity": app_state.get("app_integrity_state", "Unknown"),
        "deviceIntegrity": device_state.get("device_integrity_state", "Unknown"),
        "timestamp": now_ts()
    })

    response_data = {
        "token": playback_token,
        "attestationPassed": True,
        "appIntegrity": app_state.get("app_integrity_state", "NotEvaluated"),
        "deviceIntegrity": device_state.get("device_integrity_state", "NotTrusted"),
        "packageId": app_state.get("package_id", ""),
        "uniqueId": device_state.get("unique_id", ""),
        "isBanned": device_ban.get("is_banned", False),
        "banRemainingTime": device_ban.get("remaining_ban_time", 0),
        "photonRealtimeAppId": config.PHOTON_REALTIME_ID,
        "photonVoiceAppId": config.PHOTON_VOICE_ID,
        "playfabTitleId": config.PLAYFAB_TITLE_ID,
        "gameVersion": config.GAME_VERSION
    }

    if device_ban.get("is_banned"):
        response_data["banActive"] = True
        response_data["banMessage"] = "This device has been banned"

    logger.info(f"Attestation passed for uid={g.uid} device={device_state.get('device_integrity_state')} app={app_state.get('app_integrity_state')}")

    return make_success(response_data, "Attestation verified successfully")

@app.route("/full-auth", methods=["POST"])
@require_json
def full_auth():
    body = g.body
    oculus_user_id = body.get("userId") or body.get("user_id")
    oculus_nonce = body.get("nonce")
    attestation_token = body.get("attestationToken") or body.get("attestation_token")
    display_name = body.get("displayName", "WaterTag Player")

    if not oculus_user_id or not oculus_nonce:
        return make_error("VALIDATION_ERROR", "userId and nonce are required", 400)

    if not config.META_APP_ID or not config.META_APP_SECRET:
        return make_error("SERVER_NOT_CONFIGURED", "Meta API is not configured", 500)

    oculus_result = verify_oculus_nonce(oculus_user_id, oculus_nonce)
    if oculus_result is None:
        return make_error("UPSTREAM_ERROR", "Failed to reach Meta authentication servers", 502)
    if not oculus_result.get("is_valid", False):
        return make_error("INVALID_PROOF", "Oculus proof is invalid", 401)

    if attestation_token:
        attest_result = verify_attestation_token(attestation_token)
        if attest_result is None:
            return make_error("UPSTREAM_ERROR", "Failed to reach Meta Attestation servers", 502)
        message, claims = parse_attestation_claims(attest_result)
        if message != "success":
            return make_error("ATTESTATION_FAILED", f"Attestation failed: {message}", 401)
        app_state = claims.get("app_state", {}) if claims else {}
        device_state = claims.get("device_state", {}) if claims else {}
        device_ban = claims.get("device_ban", {}) if claims else {}
        app_integrity = app_state.get("app_integrity_state", "NotEvaluated")
        device_integrity = device_state.get("device_integrity_state", "NotTrusted")
        unique_id = device_state.get("unique_id", "")
        is_banned = device_ban.get("is_banned", False)
    else:
        attest_result = None
        app_integrity = "NotProvided"
        device_integrity = "NotProvided"
        unique_id = ""
        is_banned = False

    playfab_result = None
    playfab_error = None
    if config.PLAYFAB_TITLE_ID and config.PLAYFAB_SECRET_KEY:
        playfab_result, playfab_error = playfab_login(oculus_user_id, display_name)

    session_token = create_auth_token(oculus_user_id, {
        "type": "full_auth",
        "attested": attestation_token is not None,
        "appIntegrity": app_integrity,
        "deviceIntegrity": device_integrity
    })

    response_data = {
        "token": session_token,
        "userId": oculus_user_id,
        "displayName": display_name,
        "oculusVerified": True,
        "attestationProvided": attestation_token is not None,
        "attestationPassed": attestation_token is not None and attest_result is not None,
        "appIntegrity": app_integrity,
        "deviceIntegrity": device_integrity,
        "uniqueId": unique_id,
        "isBanned": is_banned,
        "photonRealtimeAppId": config.PHOTON_REALTIME_ID,
        "photonVoiceAppId": config.PHOTON_VOICE_ID,
        "gameVersion": config.GAME_VERSION
    }

    if playfab_result:
        response_data["playFab"] = playfab_result
    if playfab_error:
        response_data["playFabError"] = playfab_error

    if is_banned:
        response_data["banActive"] = True
        response_data["banMessage"] = "This device is banned from this application"

    return make_success(response_data, "Full authentication completed")

@app.route("/photon-auth", methods=["POST"])
@require_json
@require_auth
def photon_auth():
    body = g.body
    display_name = body.get("displayName", "WaterTag Player")
    oculus_id = g.uid

    if not config.PHOTON_REALTIME_ID:
        return make_error("PHOTON_NOT_CONFIGURED", "Photon Realtime is not configured on the server", 500)

    auth_data = build_photon_auth_data(oculus_id, "", display_name)

    return make_success(auth_data, "Photon authentication data ready")

@app.route("/playfab-auth", methods=["POST"])
@require_json
@require_auth
def playfab_auth():
    body = g.body
    display_name = body.get("displayName", "WaterTag Player")

    if not config.PLAYFAB_TITLE_ID or not config.PLAYFAB_SECRET_KEY:
        return make_error("PLAYFAB_NOT_CONFIGURED", "PlayFab is not configured on the server", 500)

    result, error = playfab_login(g.uid, display_name)
    if error:
        return make_error("PLAYFAB_LOGIN_FAILED", f"PlayFab login failed: {error}", 502)

    return make_success(result, "PlayFab login successful")

@app.route("/auth/status", methods=["GET"])
@require_auth
def auth_status():
    extra = {}
    if hasattr(g, 'token_payload') and g.token_payload:
        extra = {k: v for k, v in g.token_payload.items() if k not in ('iat', 'exp')}
    return make_success({
        "authenticated": True,
        "uid": g.uid,
        "tokenType": g.token_payload.get("type", "unknown") if hasattr(g, 'token_payload') else "unknown",
        "timestamp": now_ts()
    }, "Token is valid")

@app.route("/ping", methods=["GET"])
def ping():
    return make_success({
        "pong": True,
        "timestamp": now_ts()
    }, "Pong")

@app.errorhandler(404)
def not_found(e):
    return make_error("NOT_FOUND", "Endpoint does not exist", 404)

@app.errorhandler(405)
def method_not_allowed(e):
    return make_error("METHOD_NOT_ALLOWED", f"Method {request.method} not allowed", 405)

@app.errorhandler(500)
def server_error(e):
    logger.exception("Unhandled server error")
    return make_error("INTERNAL_ERROR", "An unexpected error occurred", 500)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting WaterTag Auth API on port {port}")
    logger.info(f"Features: Oculus={'OK' if config.META_APP_ID else 'MISSING'} Attestation={'OK' if config.META_APP_SECRET else 'MISSING'} Photon={'OK' if config.PHOTON_REALTIME_ID else 'MISSING'} PlayFab={'OK' if config.PLAYFAB_TITLE_ID else 'MISSING'}")
    app.run(host="0.0.0.0", port=port, debug=config.ENVIRONMENT == "development")
