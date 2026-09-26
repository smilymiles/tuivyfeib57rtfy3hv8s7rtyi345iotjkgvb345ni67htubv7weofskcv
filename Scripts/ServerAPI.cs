using UnityEngine;
using UnityEngine.Networking;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace SUL
{
    [Serializable]
    public class ApiResponse
    {
        public bool success;
        public string message;
        public string code;
    }

    [Serializable]
    public class StatusResponse : ApiResponse
    {
        public StatusData data;
    }

    [Serializable]
    public class StatusData
    {
        public string status;
        public string game;
        public string version;
        public string environment;
        public FeatureData features;
    }

    [Serializable]
    public class FeatureData
    {
        public bool oculusAuth;
        public bool attestation;
        public bool photonRealtime;
        public bool photonVoice;
        public bool playfab;
    }

    [Serializable]
    public class OculusAuthResponse : ApiResponse
    {
        public OculusAuthData data;
    }

    [Serializable]
    public class OculusAuthData
    {
        public string token;
        public string userId;
        public string displayName;
        public int expiresIn;
    }

    [Serializable]
    public class ChallengeNonceResponse : ApiResponse
    {
        public ChallengeNonceData data;
    }

    [Serializable]
    public class ChallengeNonceData
    {
        public string challengeNonce;
        public string signedNonce;
        public int expiresIn;
    }

    [Serializable]
    public class AttestationResponse : ApiResponse
    {
        public AttestationData data;
    }

    [Serializable]
    public class AttestationData
    {
        public string token;
        public bool attestationPassed;
        public string appIntegrity;
        public string deviceIntegrity;
        public string packageId;
        public string uniqueId;
        public bool isBanned;
        public int banRemainingTime;
        public string photonRealtimeAppId;
        public string photonVoiceAppId;
        public string playfabTitleId;
        public string gameVersion;
        public bool banActive;
        public string banMessage;
    }

    [Serializable]
    public class FullAuthResponse : ApiResponse
    {
        public FullAuthData data;
    }

    [Serializable]
    public class FullAuthData
    {
        public string token;
        public string userId;
        public string displayName;
        public bool oculusVerified;
        public bool attestationProvided;
        public bool attestationPassed;
        public string appIntegrity;
        public string deviceIntegrity;
        public string uniqueId;
        public bool isBanned;
        public string photonRealtimeAppId;
        public string photonVoiceAppId;
        public string gameVersion;
        public bool banActive;
        public string banMessage;
        public PlayFabResult playFab;
        public string playFabError;
    }

    [Serializable]
    public class PlayFabResult
    {
        public string sessionTicket;
        public string playFabId;
        public bool newlyCreated;
        public string lastLogin;
    }

    [Serializable]
    public class PhotonAuthResponse : ApiResponse
    {
        public PhotonAuthData data;
    }

    [Serializable]
    public class PhotonAuthData
    {
        public string oculusId;
        public string nonce;
        public string displayName;
        public string appVersion;
        public string photonRealtimeAppId;
        public string photonVoiceAppId;
    }

    [Serializable]
    public class AuthStatusResponse : ApiResponse
    {
        public AuthStatusData data;
    }

    [Serializable]
    public class AuthStatusData
    {
        public bool authenticated;
        public string uid;
        public string tokenType;
        public long timestamp;
    }

    public class ServerAPI : MonoBehaviour
    {
        [Header("Server Configuration")]
        [SerializeField] private string serverUrl = "https://your-project.vercel.app";
        [SerializeField] private int requestTimeout = 30;
        [SerializeField] private int maxRetries = 3;
        [SerializeField] private bool enableLogging = false;

        private string _authToken;
        private int _consecutiveFailures;
        private float _lastRequestTime;
        private static ServerAPI _instance;

        public static ServerAPI Instance
        {
            get
            {
                if (_instance == null)
                {
                    GameObject go = new GameObject("ServerAPI");
                    DontDestroyOnLoad(go);
                    _instance = go.AddComponent<ServerAPI>();
                }
                return _instance;
            }
        }

        public string AuthToken => _authToken;
        public string ServerUrl => serverUrl;
        public bool IsAuthenticated => !string.IsNullOrEmpty(_authToken);

        public event Action<string> OnTokenUpdated;
        public event Action OnTokenCleared;

        void Awake()
        {
            if (_instance != null && _instance != this)
            {
                Destroy(gameObject);
                return;
            }
            _instance = this;
            DontDestroyOnLoad(gameObject);
        }

        public void SetServerUrl(string url)
        {
            serverUrl = url.TrimEnd('/');
        }

        public void SetRequestTimeout(int timeout)
        {
            requestTimeout = timeout;
        }

        public void SetAuthToken(string token)
        {
            _authToken = token;
            OnTokenUpdated?.Invoke(token);
        }

        public void ClearAuthToken()
        {
            _authToken = null;
            _consecutiveFailures = 0;
            OnTokenCleared?.Invoke();
        }

        private string BuildJsonBody(Dictionary<string, object> dict)
        {
            var sb = new StringBuilder();
            sb.Append('{');
            bool first = true;
            foreach (var kvp in dict)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(kvp.Key).Append("\":");
                if (kvp.Value == null)
                {
                    sb.Append("null");
                }
                else if (kvp.Value is string s)
                {
                    sb.Append('"').Append(EscapeJson(s)).Append('"');
                }
                else if (kvp.Value is bool b)
                {
                    sb.Append(b ? "true" : "false");
                }
                else if (kvp.Value is int || kvp.Value is long || kvp.Value is float || kvp.Value is double)
                {
                    sb.Append(kvp.Value.ToString());
                }
                else
                {
                    sb.Append('"').Append(EscapeJson(kvp.Value.ToString())).Append('"');
                }
            }
            sb.Append('}');
            return sb.ToString();
        }

        private string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\")
                    .Replace("\"", "\\\"")
                    .Replace("\n", "\\n")
                    .Replace("\r", "\\r")
                    .Replace("\t", "\\t");
        }

        public IEnumerator GetStatus(Action<StatusResponse> onSuccess, Action<string> onError)
        {
            yield return GetRequest("/", onSuccess, onError);
        }

        public IEnumerator GetHealth(Action<ApiResponse> onSuccess, Action<string> onError)
        {
            yield return GetRequest("/health", onSuccess, onError);
        }

        public IEnumerator AuthenticateOculus(string userId, string nonce, string displayName, Action<OculusAuthResponse> onSuccess, Action<string> onError)
        {
            var body = new Dictionary<string, object>
            {
                { "userId", userId },
                { "nonce", nonce },
                { "displayName", displayName ?? "WaterTag Player" }
            };
            yield return PostRequest("/auth/oculus", body, onSuccess, onError);
        }

        public IEnumerator GetChallengeNonce(Action<ChallengeNonceResponse> onSuccess, Action<string> onError)
        {
            yield return GetAuthenticatedRequest("/challenge-nonce", onSuccess, onError);
        }

        public IEnumerator VerifyAttestation(string attestationToken, string signedNonce, string expectedNonce, Action<AttestationResponse> onSuccess, Action<string> onError)
        {
            var body = new Dictionary<string, object>
            {
                { "attestationToken", attestationToken },
                { "signedNonce", signedNonce ?? "" },
                { "expectedNonce", expectedNonce ?? "" }
            };
            yield return PostAuthenticatedRequest("/verify-attestation", body, onSuccess, onError);
        }

        public IEnumerator FullAuth(string userId, string nonce, string attestationToken, string displayName, Action<FullAuthResponse> onSuccess, Action<string> onError)
        {
            var body = new Dictionary<string, object>
            {
                { "userId", userId },
                { "nonce", nonce },
                { "displayName", displayName ?? "WaterTag Player" }
            };
            if (!string.IsNullOrEmpty(attestationToken))
            {
                body["attestationToken"] = attestationToken;
            }
            yield return PostRequest("/full-auth", body, onSuccess, onError);
        }

        public IEnumerator GetPhotonAuth(string displayName, Action<PhotonAuthResponse> onSuccess, Action<string> onError)
        {
            var body = new Dictionary<string, object>
            {
                { "displayName", displayName ?? "WaterTag Player" }
            };
            yield return PostAuthenticatedRequest("/photon-auth", body, onSuccess, onError);
        }

        public IEnumerator LoginPlayFab(string displayName, Action<ApiResponse> onSuccess, Action<string> onError)
        {
            var body = new Dictionary<string, object>
            {
                { "displayName", displayName ?? "WaterTag Player" }
            };
            yield return PostAuthenticatedRequest("/playfab-auth", body, onSuccess, onError);
        }

        public IEnumerator CheckAuthStatus(Action<AuthStatusResponse> onSuccess, Action<string> onError)
        {
            yield return GetAuthenticatedRequest("/auth/status", onSuccess, onError);
        }

        public IEnumerator GetAuthStatus(Action<AuthStatusResponse> onSuccess, Action<string> onError)
        {
            yield return GetAuthenticatedRequest("/auth/status", onSuccess, onError);
        }

        private IEnumerator SendRequest<T>(string method, string endpoint, string bodyJson, bool authenticated, Action<T> onSuccess, Action<string> onError) where T : ApiResponse
        {
            if (authenticated && string.IsNullOrEmpty(_authToken))
            {
                onError?.Invoke("AUTH_REQUIRED: Authenticate first");
                yield break;
            }

            string url = serverUrl + endpoint;
            using (UnityWebRequest req = new UnityWebRequest(url, method))
            {
                if (!string.IsNullOrEmpty(bodyJson))
                {
                    byte[] bodyRaw = Encoding.UTF8.GetBytes(bodyJson);
                    req.uploadHandler = new UploadHandlerRaw(bodyRaw);
                }
                req.downloadHandler = new DownloadHandlerBuffer();
                req.SetRequestHeader("Accept", "application/json");
                if (!string.IsNullOrEmpty(bodyJson))
                {
                    req.SetRequestHeader("Content-Type", "application/json");
                }
                if (authenticated)
                {
                    req.SetRequestHeader("Authorization", "Bearer " + _authToken);
                }
                req.timeout = requestTimeout;
                _lastRequestTime = Time.time;
                yield return req.SendWebRequest();

                if (req.result == UnityWebRequest.Result.Success)
                {
                    try
                    {
                        string text = req.downloadHandler.text;
                        T response = JsonUtility.FromJson<T>(text);
                        _consecutiveFailures = 0;
                        onSuccess?.Invoke(response);
                    }
                    catch (Exception e)
                    {
                        _consecutiveFailures++;
                        onError?.Invoke("Parse error: " + e.Message + " | Raw: " + req.downloadHandler.text);
                    }
                }
                else
                {
                    _consecutiveFailures++;
                    string errorMsg = "HTTP " + (int)req.responseCode + ": " + req.error;
                    if (req.responseCode == 401 && authenticated)
                    {
                        ClearAuthToken();
                        errorMsg = "AUTH_EXPIRED:" + errorMsg;
                    }
                    else if (req.responseCode == 429)
                    {
                        errorMsg = "RATE_LIMITED:" + errorMsg;
                    }
                    else if (req.responseCode == 502 || req.responseCode == 503)
                    {
                        errorMsg = "SERVER_ERROR:" + errorMsg;
                    }
                    if (req.downloadHandler != null && !string.IsNullOrEmpty(req.downloadHandler.text))
                    {
                        errorMsg += " | " + req.downloadHandler.text;
                    }
                    onError?.Invoke(errorMsg);
                }
            }
        }

        private IEnumerator GetRequest<T>(string endpoint, Action<T> onSuccess, Action<string> onError) where T : ApiResponse
        {
            yield return SendRequest<T>("GET", endpoint, null, false, onSuccess, onError);
        }

        private IEnumerator PostRequest<T>(string endpoint, Dictionary<string, object> body, Action<T> onSuccess, Action<string> onError) where T : ApiResponse
        {
            string json = BuildJsonBody(body);
            yield return SendRequest<T>("POST", endpoint, json, false, onSuccess, onError);
        }

        private IEnumerator GetAuthenticatedRequest<T>(string endpoint, Action<T> onSuccess, Action<string> onError) where T : ApiResponse
        {
            yield return SendRequest<T>("GET", endpoint, null, true, onSuccess, onError);
        }

        private IEnumerator PostAuthenticatedRequest<T>(string endpoint, Dictionary<string, object> body, Action<T> onSuccess, Action<string> onError) where T : ApiResponse
        {
            string json = BuildJsonBody(body);
            yield return SendRequest<T>("POST", endpoint, json, true, onSuccess, onError);
        }
    }
}
