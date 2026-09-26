using UnityEngine;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Photon.Pun;
using GorillaNetworking;
using Application = UnityEngine.Application;

#if OCULUS_PLATFORM
using Oculus.Platform;
using Oculus.Platform.Models;
#endif

namespace SUL
{
    public enum AuthState
    {
        Uninitialized,
        InitializingOculus,
        OculusReady,
        GettingOculusCredentials,
        OculusCredentialsReady,
        AuthenticatingWithServer,
        ServerAuthenticated,
        GettingChallengeNonce,
        ChallengeNonceReady,
        RequestingAttestation,
        AttestationTokenReady,
        VerifyingAttestation,
        AttestationVerified,
        ConnectingPhoton,
        PhotonConnected,
        LoggingIntoPlayFab,
        PlayFabLoggedIn,
        FullAuthComplete,
        Error,
        Banned,
        Cancelled,
        WaitingForNetwork,
        NetworkRestored,
        ReconnectingPhoton,
        ReconnectingPlayFab,
        RefreshingToken,
        TokenRefreshed,
        PerformingHealthCheck,
        HealthCheckComplete,
        SyncingPlayerData,
        PlayerDataSynced,
        CheckingEntitlement,
        EntitlementChecked,
        RequestingDeviceInfo,
        DeviceInfoCollected,
        ValidatingEnvironment,
        EnvironmentValidated,
        PerformingVersionCheck,
        VersionCheckComplete,
        RateLimitWaiting,
        RateLimitComplete
    }

    public enum AuthSubState
    {
        None,
        WaitingForOculusInit,
        WaitingForEntitlement,
        WaitingForUserInfo,
        WaitingForUserProof,
        WaitingForServerAuth,
        WaitingForChallengeNonce,
        WaitingForAttestationRequest,
        WaitingForAttestationVerify,
        WaitingForPhotonConnect,
        WaitingForPlayFabLogin,
        WaitingForTokenRefresh,
        WaitingForHealthCheck,
        WaitingForDataSync,
        WaitingForRetryBackoff,
        WaitingForNetworkRecovery,
        WaitingForRateLimit
    }

    public enum AuthErrorType
    {
        None,
        OculusInitFailed,
        OculusEntitlementFailed,
        OculusUserNotFound,
        OculusProofFailed,
        OculusTimeout,
        ServerUnreachable,
        ServerAuthFailed,
        ServerTokenExpired,
        ChallengeNonceFailed,
        AttestationApiUnavailable,
        AttestationTokenInvalid,
        AttestationVerificationFailed,
        AttestationTimeout,
        PhotonConfigMissing,
        PhotonConnectionFailed,
        PhotonTimeout,
        PlayFabConfigMissing,
        PlayFabLoginFailed,
        PlayFabServerError,
        NetworkUnavailable,
        NetworkTimeout,
        DeviceBanned,
        InvalidConfiguration,
        RateLimited,
        VersionMismatch,
        Unknown
    }

    [Serializable]
    public class AuthConfiguration
    {
        [Header("Server Configuration")]
        public string serverUrl = "https://your-project.vercel.app";
        public int serverRequestTimeout = 30;
        public int maxServerRetries = 3;
        public float retryBackoffBaseDelay = 1f;
        public float retryBackoffMaxDelay = 30f;
        public bool enableServerHealthCheck = true;
        public float healthCheckInterval = 60f;

        [Header("Photon Configuration")]
        public string photonRealtimeAppId = "";
        public string photonVoiceAppId = "";
        public string photonGameVersion = "1.0.0";
        public int photonConnectionTimeout = 20;
        public bool photonAutoJoinLobby = true;
        public bool photonCreateRoomIfNotExists = true;
        public int photonMaxPlayersPerRoom = 10;
        public string photonDefaultRoomName = "default";
        public bool photonEnableVoice = true;

        [Header("PlayFab Configuration")]
        public string playfabTitleId = "";
        public string playfabCustomIdPrefix = "sul_oculus_";
        public bool playfabAutoCreateAccount = true;
        public bool playfabEnableDataSync = true;
        public bool playfabEnableStatistics = true;
        public float playfabDataSyncInterval = 120f;

        [Header("Authentication Options")]
        public string displayName = "WaterTag Player";
        public bool enableAttestation = true;
        public bool enablePhoton = true;
        public bool enablePlayFab = true;
        public bool cacheTokens = true;
        public int maxAuthRetries = 3;
        public float authTimeoutMultiplier = 1f;
        public bool requireEntitlementCheck = true;
        public bool enableDeviceBanCheck = true;
        public bool enableVersionCheck = true;
        public string minimumGameVersion = "1.0.0";
        public bool enableEnvironmentValidation = true;

        [Header("Token Management")]
        public int tokenExpiryBufferSeconds = 300;
        public bool enableTokenAutoRefresh = true;
        public float tokenRefreshCheckInterval = 30f;
        public int maxConcurrentTokenRefreshes = 1;

        [Header("Network Settings")]
        public bool enableNetworkMonitoring = true;
        public float networkCheckInterval = 5f;
        public int networkFailureThreshold = 3;
        public int networkRecoveryMaxRetries = 5;
        public float networkRecoveryBackoffBase = 2f;
        public int maxNetworkRecoveryTimeSeconds = 120;

        [Header("Rate Limiting")]
        public bool enableRateLimiting = true;
        public int maxRequestsPerMinute = 60;
        public int rateLimitMaxRetries = 3;
        public float rateLimitBackoffBase = 5f;

        [Header("Analytics")]
        public bool enableAnalytics = true;
        public bool enablePerformanceTracking = true;
        public bool enableDetailedLogging = false;
        public bool enableEventHistory = true;
        public int maxEventHistoryEntries = 100;

        [Header("Editor / Development")]
        public bool skipOculusInitInEditor = true;
        public string editorOverrideUserId = "1234567890";
        public string editorOverrideNonce = "test-nonce-abc123";
        public bool editorSimulateAttestation = true;
        public bool editorSimulatePhoton = false;
        public bool editorSimulatePlayFab = false;
        public float editorSimulatedLatency = 0.1f;
        public bool editorEnableAdvancedDebug = false;

        [Header("Security")]
        public bool enableNonceValidation = true;
        public bool enableReplayAttackProtection = true;
        public int maxNonceAgeSeconds = 300;
        public bool enableTimestampValidation = true;
        public int timestampToleranceSeconds = 300;

        [Header("Performance")]
        public bool enableAsyncOperations = true;
        public int maxConcurrentOperations = 3;
        public bool useObjectPooling = true;
        public int objectPoolInitialSize = 10;

        [Header("Device Information")]
        public bool collectDeviceInfo = true;
        public bool collectAppInfo = true;
        public bool collectNetworkInfo = true;
        public bool sendDeviceInfoToServer = true;

        [Header("Session Management")]
        public bool enableSessionPersistence = true;
        public float sessionTimeoutMinutes = 60f;
        public bool enableCrossSessionCaching = true;
        public int maxCachedSessions = 5;

        [Header("Ban Management")]
        public bool enableLocalBanCache = true;
        public int banCacheDurationHours = 24;
        public bool enableBanWebhook = false;
        public string banWebhookUrl = "";
    }

    [Serializable]
    public class DeviceInformation
    {
        public string deviceModel;
        public string devicePlatform;
        public string deviceOperatingSystem;
        public string deviceLanguage;
        public string deviceUniqueIdentifier;
        public string graphicsDeviceName;
        public string graphicsDeviceVersion;
        public string graphicsDeviceType;
        public int graphicsMemorySize;
        public int systemMemorySize;
        public int processorCount;
        public string processorType;
        public bool isEditor;
        public bool isMobile;
        public bool isVRDevice;
        public string vrDeviceName;
        public string batteryStatus;
        public float batteryLevel;
        public string networkType;
        public string networkReachability;
        public string appVersion;
        public string appBundleIdentifier;
        public string appInstallMode;
        public bool isAppLabBuild;
        public bool isSignedBuild;
        public float screenDpi;
        public int screenWidth;
        public int screenHeight;
        public string operatingSystemFamily;
    }

    [Serializable]
    public class NetworkQualityMetrics
    {
        public float averagePingMs;
        public float lastPingMs;
        public float minPingMs;
        public float maxPingMs;
        public float packetLossPercent;
        public float jitterMs;
        public int successfulRequests;
        public int failedRequests;
        public float successRate;
        public int consecutiveFailures;
        public int totalRequests;
        public float lastCheckedTimestamp;
        public string currentNetworkStatus;
        public bool isNetworkStable;
        public float uptimeSeconds;
        public int disconnectionCount;
        public string networkType;
        public string networkReachability;
    }

    [Serializable]
    public class AuthenticationEvent
    {
        public float timestamp;
        public AuthState state;
        public string description;
        public bool isError;
        public string errorCode;
        public float duration;
    }

    [Serializable]
    public class CachedSessionData
    {
        public string oculusUserId;
        public string serverAuthToken;
        public string attestationServerToken;
        public string photonRealtimeAppId;
        public string photonVoiceAppId;
        public string playfabTitleId;
        public string displayName;
        public float lastAuthenticatedTimestamp;
        public float tokenExpiryTimestamp;
        public string sessionId;
        public int authenticationCount;
    }

    public class MetaAuth : MonoBehaviour
    {
        [Header("Configuration")]
        [SerializeField] private AuthConfiguration config = new AuthConfiguration();

        [Header("Runtime State")]
        [SerializeField] private AuthState currentState = AuthState.Uninitialized;
        [SerializeField] private AuthSubState currentSubState = AuthSubState.None;
        [SerializeField] private AuthErrorType lastErrorType = AuthErrorType.None;
        [SerializeField] private string lastError = "";

        private string _oculusUserId;
        private string _oculusNonce;
        private string _serverAuthToken;
        private string _challengeNonce;
        private string _signedNonce;
        private string _attestationToken;
        private string _attestationServerToken;
        private int _retryCount;
        private int _authenticationCount;
        private int _networkFailureCount;
        private int _rateLimitHitCount;
        private ServerAPI _serverAPI;
        private bool _isProcessing;
        private bool _isInitialized;
        private bool _isDestroyed;
        private float _authStartTime;
        private float _lastProgressUpdate;
        private float _lastHealthCheckTime;
        private float _lastNetworkCheckTime;
        private float _lastTokenRefreshCheckTime;
        private float _lastDataSyncTime;
        private string _sessionId;
        private string _deviceUniqueId;
        private string _appVersion;
        private DeviceInformation _deviceInfo;
        private NetworkQualityMetrics _networkMetrics;
        private List<AuthenticationEvent> _eventHistory;
        private List<CachedSessionData> _cachedSessions;
        private Dictionary<string, string> _localBanCache;
        private Dictionary<string, float> _rateLimitTracker;
        private Queue<Action> _pendingOperations;
        private HashSet<string> _processedNonces;
        private Coroutine _authCoroutine;
        private Coroutine _healthCheckCoroutine;
        private Coroutine _networkMonitorCoroutine;
        private Coroutine _tokenRefreshCoroutine;

        private static MetaAuth _instance;
        public static MetaAuth Instance
        {
            get
            {
                if (_instance == null)
                {
                    GameObject go = new GameObject("MetaAuth");
                    DontDestroyOnLoad(go);
                    _instance = go.AddComponent<MetaAuth>();
                }
                return _instance;
            }
        }

        public AuthState CurrentState => currentState;
        public AuthSubState CurrentSubState => currentSubState;
        public AuthErrorType LastErrorType => lastErrorType;
        public string LastError => lastError;
        public string OculusUserId => _oculusUserId;
        public string OculusNonce => _oculusNonce;
        public string ServerAuthToken => _serverAuthToken;
        public string ChallengeNonce => _challengeNonce;
        public string SignedNonce => _signedNonce;
        public string AttestationToken => _attestationToken;
        public string AttestationServerToken => _attestationServerToken;
        public bool IsAuthenticated => currentState == AuthState.FullAuthComplete;
        public bool IsBanned => currentState == AuthState.Banned;
        public bool IsProcessing => _isProcessing;
        public bool IsInitialized => _isInitialized;
        public AuthConfiguration Config => config;
        public int AuthenticationCount => _authenticationCount;
        public string SessionId => _sessionId;
        public DeviceInformation DeviceInfo => _deviceInfo;
        public NetworkQualityMetrics NetworkMetrics => _networkMetrics;
        public List<AuthenticationEvent> EventHistory => _eventHistory;
        public int RetryCount => _retryCount;

        public event Action<AuthState> OnStateChanged;
        public event Action<AuthSubState> OnSubStateChanged;
        public event Action<AuthErrorType, string> OnError;
        public event Action OnAuthenticationComplete;
        public event Action OnBanned;
        public event Action<float> OnProgress;
        public event Action<string> OnLogMessage;
        public event Action<DeviceInformation> OnDeviceInfoCollected;
        public event Action<NetworkQualityMetrics> OnNetworkMetricsUpdated;
        public event Action<string> OnTokenRefreshed;
        public event Action<string> OnTokenExpired;
        public event Action OnNetworkLost;
        public event Action OnNetworkRestored;
        public event Action<string, float> OnRateLimitHit;
        public event Action<string> OnSessionCreated;
        public event Action<string> OnSessionExpired;
        public event Action<string> OnBanDetected;
        public event Action<CachedSessionData> OnSessionRestored;
        public event Action<string> OnVersionMismatch;
        public event Action OnEntitlementConfirmed;
        public event Action<string> OnEntitlementFailed;
        public event Action OnHealthCheckPassed;
        public event Action<string> OnHealthCheckFailed;
        public event Action<float> OnConnectionQualityChanged;
        public event Action<string> OnServerMessage;
        public event Action<Dictionary<string, object>> OnServerConfigUpdated;
        public event Action OnAuthenticationReset;
        public event Action OnRateLimitLifted;

        void Awake()
        {
            if (_instance != null && _instance != this)
            {
                Destroy(gameObject);
                return;
            }
            _instance = this;
            DontDestroyOnLoad(gameObject);
            _eventHistory = new List<AuthenticationEvent>();
            _cachedSessions = new List<CachedSessionData>();
            _localBanCache = new Dictionary<string, string>();
            _rateLimitTracker = new Dictionary<string, float>();
            _pendingOperations = new Queue<Action>();
            _processedNonces = new HashSet<string>();
            _networkMetrics = new NetworkQualityMetrics();
            _sessionId = Guid.NewGuid().ToString("N");
            RecordEvent(AuthState.Uninitialized, "MetaAuth system awake");
        }

        void Start()
        {
            Initialize();
        }

        void Update()
        {
            if (!_isInitialized || _isDestroyed)
            {
                return;
            }
            if (config.enableNetworkMonitoring)
            {
                float currentTime = Time.time;
                if (currentTime - _lastNetworkCheckTime >= config.networkCheckInterval)
                {
                    _lastNetworkCheckTime = currentTime;
                    CheckNetworkStatus();
                }
            }
            if (config.enableTokenAutoRefresh && IsAuthenticated)
            {
                float currentTime = Time.time;
                if (currentTime - _lastTokenRefreshCheckTime >= config.tokenRefreshCheckInterval)
                {
                    _lastTokenRefreshCheckTime = currentTime;
                    CheckTokenExpiry();
                }
            }
            if (config.enableServerHealthCheck && IsAuthenticated)
            {
                float currentTime = Time.time;
                if (currentTime - _lastHealthCheckTime >= config.healthCheckInterval)
                {
                    _lastHealthCheckTime = currentTime;
                    if (_healthCheckCoroutine == null)
                    {
                        _healthCheckCoroutine = StartCoroutine(PerformHealthCheck());
                    }
                }
            }
            if (config.playfabEnableDataSync && IsAuthenticated && config.enablePlayFab)
            {
                float currentTime = Time.time;
                if (currentTime - _lastDataSyncTime >= config.playfabDataSyncInterval)
                {
                    _lastDataSyncTime = currentTime;
                    StartCoroutine(SyncPlayerData());
                }
            }
            ProcessPendingOperations();
        }

        void OnDestroy()
        {
            _isDestroyed = true;
            StopAllCoroutines();
            if (_serverAPI != null)
            {
                _serverAPI.OnTokenUpdated -= OnServerTokenUpdated;
                _serverAPI.OnTokenCleared -= OnServerTokenCleared;
            }
            RecordEvent(currentState, "MetaAuth system destroyed");
        }

        void OnApplicationQuit()
        {
            _isDestroyed = true;
            CancelAuthentication();
            SaveCachedSessions();
        }

        void OnApplicationPause(bool pauseStatus)
        {
            if (pauseStatus)
            {
                if (config.enableAnalytics)
                {
                    RecordEvent(currentState, "Application paused");
                }
            }
            else
            {
                if (config.enableAnalytics)
                {
                    RecordEvent(currentState, "Application resumed");
                }
                if (IsAuthenticated && config.enableTokenAutoRefresh)
                {
                    CheckTokenExpiry();
                }
            }
        }

        public void Initialize()
        {
            if (_isInitialized)
            {
                Log("[MetaAuth] Already initialized");
                return;
            }
            Log("[MetaAuth] Initializing MetaAuth system");
            RecordEvent(AuthState.Uninitialized, "Initialization started");
            SetState(AuthState.InitializingOculus);
            _deviceUniqueId = SystemInfo.deviceUniqueIdentifier;
            _appVersion = Application.version;
            if (string.IsNullOrEmpty(_appVersion))
            {
                _appVersion = config.minimumGameVersion;
            }
            if (_serverAPI == null)
            {
                _serverAPI = ServerAPI.Instance;
                _serverAPI.SetServerUrl(config.serverUrl);
                _serverAPI.SetRequestTimeout(config.serverRequestTimeout);
                _serverAPI.OnTokenUpdated += OnServerTokenUpdated;
                _serverAPI.OnTokenCleared += OnServerTokenCleared;
            }
            if (config.collectDeviceInfo)
            {
                CollectDeviceInformation();
            }
            if (config.cacheTokens && config.enableCrossSessionCaching)
            {
                LoadCachedSessions();
            }
            if (config.enableLocalBanCache)
            {
                LoadLocalBanCache();
            }
            StartCoroutine(InitializeServerConnection());
        }

        private IEnumerator InitializeServerConnection()
        {
            Log("[MetaAuth] Establishing server connection");
            SetSubState(AuthSubState.WaitingForServerAuth);
            bool serverReachable = false;
            string serverGameName = "";
            string serverVersion = "";
            bool serverFeaturesOculus = false;
            bool serverFeaturesAttestation = false;
            bool serverFeaturesPhoton = false;
            bool serverFeaturesPlayFab = false;

            _serverAPI.GetStatus(
                (response) =>
                {
                    if (response.success)
                    {
                        serverReachable = true;
                        serverGameName = response.data.game;
                        serverVersion = response.data.version;
                        serverFeaturesOculus = response.data.features.oculusAuth;
                        serverFeaturesAttestation = response.data.features.attestation;
                        serverFeaturesPhoton = response.data.features.photonRealtime;
                        serverFeaturesPlayFab = response.data.features.playfab;
                        Log($"[MetaAuth] Server online: {serverGameName} v{serverVersion}");
                        Log($"[MetaAuth] Server features - Oculus:{serverFeaturesOculus} Attestation:{serverFeaturesAttestation} Photon:{serverFeaturesPhoton} PlayFab:{serverFeaturesPlayFab}");
                        if (!string.IsNullOrEmpty(response.data.features.photonRealtime.ToString()))
                        {
                        }
                        if (response.data.features.playfab)
                        {
                            if (string.IsNullOrEmpty(config.playfabTitleId))
                            {
                            }
                        }
                        if (config.enableVersionCheck)
                        {
                            PerformVersionValidation(serverVersion);
                        }
                    }
                    else
                    {
                        LogWarning($"[MetaAuth] Server status check returned: {response.message}");
                    }
                },
                (error) =>
                {
                    LogWarning($"[MetaAuth] Server unreachable during init: {error}");
                    if (config.enableServerHealthCheck)
                    {
                        StartCoroutine(RetryServerConnection());
                    }
                }
            );

            float initTimeout = 10f;
            float initElapsed = 0f;
            while (!serverReachable && initElapsed < initTimeout)
            {
                initElapsed += Time.deltaTime;
                yield return null;
            }

            if (!serverReachable)
            {
                LogWarning("[MetaAuth] Server not reachable during initialization");
                if (_cachedSessions.Count > 0)
                {
                    CachedSessionData lastSession = _cachedSessions[_cachedSessions.Count - 1];
                    if (Time.time - lastSession.lastAuthenticatedTimestamp < config.sessionTimeoutMinutes * 60f)
                    {
                        Log("[MetaAuth] Restoring cached session");
                        RestoreCachedSession(lastSession);
                        OnSessionRestored?.Invoke(lastSession);
                    }
                }
            }

            _isInitialized = true;
            SetState(AuthState.OculusReady);
            RecordEvent(AuthState.OculusReady, "Initialization complete");
            Log("[MetaAuth] Initialization complete");
        }

        private IEnumerator RetryServerConnection()
        {
            int retryAttempts = 0;
            int maxRetries = 3;
            while (retryAttempts < maxRetries && !_isDestroyed)
            {
                retryAttempts++;
                Log($"[MetaAuth] Retrying server connection (attempt {retryAttempts}/{maxRetries})");
                yield return new WaitForSeconds(2f * retryAttempts);
                bool connected = false;
                _serverAPI.GetStatus(
                    (response) =>
                    {
                        if (response.success)
                        {
                            connected = true;
                            Log("[MetaAuth] Server connection restored");
                        }
                    },
                    (error) =>
                    {
                        LogWarning($"[MetaAuth] Retry {retryAttempts} failed: {error}");
                    }
                );
                float retryTimeout = 5f;
                float retryElapsed = 0f;
                while (!connected && retryElapsed < retryTimeout)
                {
                    retryElapsed += Time.deltaTime;
                    yield return null;
                }
                if (connected)
                {
                    yield break;
                }
            }
            LogWarning("[MetaAuth] Server connection retries exhausted");
        }

        private void PerformVersionValidation(string serverVersion)
        {
            if (string.IsNullOrEmpty(serverVersion))
            {
                return;
            }
            string clientVersion = _appVersion;
            if (string.IsNullOrEmpty(clientVersion))
            {
                clientVersion = config.minimumGameVersion;
            }
            if (VersionStringToInt(clientVersion) < VersionStringToInt(config.minimumGameVersion))
            {
                LogWarning($"[MetaAuth] Client version {clientVersion} is below minimum {config.minimumGameVersion}");
                OnVersionMismatch?.Invoke($"Client version {clientVersion} is too old. Minimum: {config.minimumGameVersion}");
            }
        }

        private int VersionStringToInt(string version)
        {
            if (string.IsNullOrEmpty(version))
            {
                return 0;
            }
            string[] parts = version.Split('.');
            int result = 0;
            int multiplier = 1000000;
            for (int i = 0; i < parts.Length && i < 4; i++)
            {
                int partValue = 0;
                int.TryParse(parts[i], out partValue);
                result += partValue * multiplier;
                multiplier /= 1000;
            }
            return result;
        }

        public void StartAuthentication()
        {
            if (_isProcessing)
            {
                LogWarning("[MetaAuth] Authentication already in progress");
                return;
            }
            if (!_isInitialized)
            {
                LogWarning("[MetaAuth] System not initialized, initializing first");
                Initialize();
            }
            if (IsAuthenticated)
            {
                Log("[MetaAuth] Already authenticated, refreshing token");
                StartCoroutine(RefreshAuthentication());
                return;
            }
            if (currentState == AuthState.Banned)
            {
                LogError("[MetaAuth] Cannot authenticate, device is banned");
                OnError?.Invoke(AuthErrorType.DeviceBanned, "Device is banned from this application");
                return;
            }
            _authStartTime = Time.time;
            _retryCount = 0;
            _authenticationCount++;
            lastError = "";
            lastErrorType = AuthErrorType.None;
            _sessionId = Guid.NewGuid().ToString("N");
            RecordEvent(AuthState.Uninitialized, "Authentication started");
            _authCoroutine = StartCoroutine(AuthenticationCoroutine());
        }

        public void CancelAuthentication()
        {
            if (_authCoroutine != null)
            {
                StopCoroutine(_authCoroutine);
                _authCoroutine = null;
            }
            if (_healthCheckCoroutine != null)
            {
                StopCoroutine(_healthCheckCoroutine);
                _healthCheckCoroutine = null;
            }
            _isProcessing = false;
            SetSubState(AuthSubState.None);
            SetState(AuthState.Cancelled);
            RecordEvent(AuthState.Cancelled, "Authentication cancelled by user");
            Log("[MetaAuth] Authentication cancelled by user");
        }

        public void ResetAuthentication()
        {
            if (_authCoroutine != null)
            {
                StopCoroutine(_authCoroutine);
                _authCoroutine = null;
            }
            if (_healthCheckCoroutine != null)
            {
                StopCoroutine(_healthCheckCoroutine);
                _healthCheckCoroutine = null;
            }
            if (_networkMonitorCoroutine != null)
            {
                StopCoroutine(_networkMonitorCoroutine);
                _networkMonitorCoroutine = null;
            }
            if (_tokenRefreshCoroutine != null)
            {
                StopCoroutine(_tokenRefreshCoroutine);
                _tokenRefreshCoroutine = null;
            }
            _isProcessing = false;
            _oculusUserId = null;
            _oculusNonce = null;
            _serverAuthToken = null;
            _challengeNonce = null;
            _signedNonce = null;
            _attestationToken = null;
            _attestationServerToken = null;
            _retryCount = 0;
            _networkFailureCount = 0;
            _rateLimitHitCount = 0;
            lastError = "";
            lastErrorType = AuthErrorType.None;
            currentSubState = AuthSubState.None;
            if (_serverAPI != null)
            {
                _serverAPI.ClearAuthToken();
            }
            SetState(AuthState.OculusReady);
            RecordEvent(AuthState.OculusReady, "Authentication state reset");
            OnAuthenticationReset?.Invoke();
            Log("[MetaAuth] Authentication state reset");
        }

        private IEnumerator RefreshAuthentication()
        {
            _isProcessing = true;
            Log("[MetaAuth] Refreshing authentication");
            SetSubState(AuthSubState.WaitingForTokenRefresh);
            if (_serverAPI != null && !string.IsNullOrEmpty(_serverAuthToken))
            {
                bool statusValid = false;
                _serverAPI.CheckAuthStatus(
                    (response) =>
                    {
                        if (response.success && response.data.authenticated)
                        {
                            statusValid = true;
                        }
                    },
                    (error) =>
                    {
                        LogWarning($"[MetaAuth] Token status check failed: {error}");
                    }
                );
                float statusTimeout = 5f;
                float statusElapsed = 0f;
                while (!statusValid && statusElapsed < statusTimeout)
                {
                    statusElapsed += Time.deltaTime;
                    yield return null;
                }
                if (statusValid)
                {
                    Log("[MetaAuth] Token still valid, skipping full re-auth");
                    SetSubState(AuthSubState.None);
                    _isProcessing = false;
                    yield break;
                }
            }
            Log("[MetaAuth] Token expired, performing full re-authentication");
            SetSubState(AuthSubState.None);
            _isProcessing = false;
            StartAuthentication();
        }

        public void SetConfiguration(AuthConfiguration newConfig)
        {
            if (newConfig == null)
            {
                LogWarning("[MetaAuth] Cannot set null configuration");
                return;
            }
            config.serverUrl = newConfig.serverUrl;
            config.serverRequestTimeout = newConfig.serverRequestTimeout;
            config.maxServerRetries = newConfig.maxServerRetries;
            config.retryBackoffBaseDelay = newConfig.retryBackoffBaseDelay;
            config.retryBackoffMaxDelay = newConfig.retryBackoffMaxDelay;
            config.enableServerHealthCheck = newConfig.enableServerHealthCheck;
            config.healthCheckInterval = newConfig.healthCheckInterval;
            config.photonRealtimeAppId = newConfig.photonRealtimeAppId;
            config.photonVoiceAppId = newConfig.photonVoiceAppId;
            config.photonGameVersion = newConfig.photonGameVersion;
            config.photonConnectionTimeout = newConfig.photonConnectionTimeout;
            config.photonAutoJoinLobby = newConfig.photonAutoJoinLobby;
            config.photonCreateRoomIfNotExists = newConfig.photonCreateRoomIfNotExists;
            config.photonMaxPlayersPerRoom = newConfig.photonMaxPlayersPerRoom;
            config.photonDefaultRoomName = newConfig.photonDefaultRoomName;
            config.photonEnableVoice = newConfig.photonEnableVoice;
            config.playfabTitleId = newConfig.playfabTitleId;
            config.playfabCustomIdPrefix = newConfig.playfabCustomIdPrefix;
            config.playfabAutoCreateAccount = newConfig.playfabAutoCreateAccount;
            config.playfabEnableDataSync = newConfig.playfabEnableDataSync;
            config.playfabEnableStatistics = newConfig.playfabEnableStatistics;
            config.playfabDataSyncInterval = newConfig.playfabDataSyncInterval;
            config.displayName = newConfig.displayName;
            config.enableAttestation = newConfig.enableAttestation;
            config.enablePhoton = newConfig.enablePhoton;
            config.enablePlayFab = newConfig.enablePlayFab;
            config.cacheTokens = newConfig.cacheTokens;
            config.maxAuthRetries = newConfig.maxAuthRetries;
            config.authTimeoutMultiplier = newConfig.authTimeoutMultiplier;
            config.requireEntitlementCheck = newConfig.requireEntitlementCheck;
            config.enableDeviceBanCheck = newConfig.enableDeviceBanCheck;
            config.enableVersionCheck = newConfig.enableVersionCheck;
            config.minimumGameVersion = newConfig.minimumGameVersion;
            config.enableEnvironmentValidation = newConfig.enableEnvironmentValidation;
            config.tokenExpiryBufferSeconds = newConfig.tokenExpiryBufferSeconds;
            config.enableTokenAutoRefresh = newConfig.enableTokenAutoRefresh;
            config.tokenRefreshCheckInterval = newConfig.tokenRefreshCheckInterval;
            config.maxConcurrentTokenRefreshes = newConfig.maxConcurrentTokenRefreshes;
            config.enableNetworkMonitoring = newConfig.enableNetworkMonitoring;
            config.networkCheckInterval = newConfig.networkCheckInterval;
            config.networkFailureThreshold = newConfig.networkFailureThreshold;
            config.networkRecoveryMaxRetries = newConfig.networkRecoveryMaxRetries;
            config.networkRecoveryBackoffBase = newConfig.networkRecoveryBackoffBase;
            config.maxNetworkRecoveryTimeSeconds = newConfig.maxNetworkRecoveryTimeSeconds;
            config.enableRateLimiting = newConfig.enableRateLimiting;
            config.maxRequestsPerMinute = newConfig.maxRequestsPerMinute;
            config.rateLimitMaxRetries = newConfig.rateLimitMaxRetries;
            config.rateLimitBackoffBase = newConfig.rateLimitBackoffBase;
            config.enableAnalytics = newConfig.enableAnalytics;
            config.enablePerformanceTracking = newConfig.enablePerformanceTracking;
            config.enableDetailedLogging = newConfig.enableDetailedLogging;
            config.enableEventHistory = newConfig.enableEventHistory;
            config.maxEventHistoryEntries = newConfig.maxEventHistoryEntries;
            config.skipOculusInitInEditor = newConfig.skipOculusInitInEditor;
            config.editorOverrideUserId = newConfig.editorOverrideUserId;
            config.editorOverrideNonce = newConfig.editorOverrideNonce;
            config.editorSimulateAttestation = newConfig.editorSimulateAttestation;
            config.editorSimulatePhoton = newConfig.editorSimulatePhoton;
            config.editorSimulatePlayFab = newConfig.editorSimulatePlayFab;
            config.editorSimulatedLatency = newConfig.editorSimulatedLatency;
            config.editorEnableAdvancedDebug = newConfig.editorEnableAdvancedDebug;
            config.enableNonceValidation = newConfig.enableNonceValidation;
            config.enableReplayAttackProtection = newConfig.enableReplayAttackProtection;
            config.maxNonceAgeSeconds = newConfig.maxNonceAgeSeconds;
            config.enableTimestampValidation = newConfig.enableTimestampValidation;
            config.timestampToleranceSeconds = newConfig.timestampToleranceSeconds;
            config.enableAsyncOperations = newConfig.enableAsyncOperations;
            config.maxConcurrentOperations = newConfig.maxConcurrentOperations;
            config.useObjectPooling = newConfig.useObjectPooling;
            config.objectPoolInitialSize = newConfig.objectPoolInitialSize;
            config.collectDeviceInfo = newConfig.collectDeviceInfo;
            config.collectAppInfo = newConfig.collectAppInfo;
            config.collectNetworkInfo = newConfig.collectNetworkInfo;
            config.sendDeviceInfoToServer = newConfig.sendDeviceInfoToServer;
            config.enableSessionPersistence = newConfig.enableSessionPersistence;
            config.sessionTimeoutMinutes = newConfig.sessionTimeoutMinutes;
            config.enableCrossSessionCaching = newConfig.enableCrossSessionCaching;
            config.maxCachedSessions = newConfig.maxCachedSessions;
            config.enableLocalBanCache = newConfig.enableLocalBanCache;
            config.banCacheDurationHours = newConfig.banCacheDurationHours;
            config.enableBanWebhook = newConfig.enableBanWebhook;
            config.banWebhookUrl = newConfig.banWebhookUrl;
            if (_serverAPI != null)
            {
                _serverAPI.SetServerUrl(config.serverUrl);
                _serverAPI.SetRequestTimeout(config.serverRequestTimeout);
            }
            Log("[MetaAuth] Configuration updated");
        }

        public void UpdateConfigurationField(string fieldName, object value)
        {
            if (string.IsNullOrEmpty(fieldName))
            {
                return;
            }
            switch (fieldName)
            {
                case "serverUrl":
                    config.serverUrl = value.ToString();
                    if (_serverAPI != null)
                    {
                        _serverAPI.SetServerUrl(config.serverUrl);
                    }
                    break;
                case "serverRequestTimeout":
                    config.serverRequestTimeout = Convert.ToInt32(value);
                    if (_serverAPI != null)
                    {
                        _serverAPI.SetRequestTimeout(config.serverRequestTimeout);
                    }
                    break;
                case "maxServerRetries":
                    config.maxServerRetries = Convert.ToInt32(value);
                    break;
                case "retryBackoffBaseDelay":
                    config.retryBackoffBaseDelay = Convert.ToSingle(value);
                    break;
                case "retryBackoffMaxDelay":
                    config.retryBackoffMaxDelay = Convert.ToSingle(value);
                    break;
                case "enableServerHealthCheck":
                    config.enableServerHealthCheck = Convert.ToBoolean(value);
                    break;
                case "healthCheckInterval":
                    config.healthCheckInterval = Convert.ToSingle(value);
                    break;
                case "photonRealtimeAppId":
                    config.photonRealtimeAppId = value.ToString();
                    break;
                case "photonVoiceAppId":
                    config.photonVoiceAppId = value.ToString();
                    break;
                case "photonGameVersion":
                    config.photonGameVersion = value.ToString();
                    break;
                case "photonConnectionTimeout":
                    config.photonConnectionTimeout = Convert.ToInt32(value);
                    break;
                case "photonAutoJoinLobby":
                    config.photonAutoJoinLobby = Convert.ToBoolean(value);
                    break;
                case "photonCreateRoomIfNotExists":
                    config.photonCreateRoomIfNotExists = Convert.ToBoolean(value);
                    break;
                case "photonMaxPlayersPerRoom":
                    config.photonMaxPlayersPerRoom = Convert.ToInt32(value);
                    break;
                case "photonDefaultRoomName":
                    config.photonDefaultRoomName = value.ToString();
                    break;
                case "photonEnableVoice":
                    config.photonEnableVoice = Convert.ToBoolean(value);
                    break;
                case "playfabTitleId":
                    config.playfabTitleId = value.ToString();
                    break;
                case "playfabCustomIdPrefix":
                    config.playfabCustomIdPrefix = value.ToString();
                    break;
                case "playfabAutoCreateAccount":
                    config.playfabAutoCreateAccount = Convert.ToBoolean(value);
                    break;
                case "playfabEnableDataSync":
                    config.playfabEnableDataSync = Convert.ToBoolean(value);
                    break;
                case "playfabEnableStatistics":
                    config.playfabEnableStatistics = Convert.ToBoolean(value);
                    break;
                case "playfabDataSyncInterval":
                    config.playfabDataSyncInterval = Convert.ToSingle(value);
                    break;
                case "displayName":
                    config.displayName = SanitizeDisplayName(value.ToString());
                    break;
                case "enableAttestation":
                    config.enableAttestation = Convert.ToBoolean(value);
                    break;
                case "enablePhoton":
                    config.enablePhoton = Convert.ToBoolean(value);
                    break;
                case "enablePlayFab":
                    config.enablePlayFab = Convert.ToBoolean(value);
                    break;
                case "cacheTokens":
                    config.cacheTokens = Convert.ToBoolean(value);
                    break;
                case "maxAuthRetries":
                    config.maxAuthRetries = Convert.ToInt32(value);
                    break;
                case "enableNetworkMonitoring":
                    config.enableNetworkMonitoring = Convert.ToBoolean(value);
                    break;
                case "enableAnalytics":
                    config.enableAnalytics = Convert.ToBoolean(value);
                    break;
                case "enableDetailedLogging":
                    config.enableDetailedLogging = Convert.ToBoolean(value);
                    break;
                case "collectDeviceInfo":
                    config.collectDeviceInfo = Convert.ToBoolean(value);
                    break;
                case "sendDeviceInfoToServer":
                    config.sendDeviceInfoToServer = Convert.ToBoolean(value);
                    break;
                default:
                    LogWarning($"[MetaAuth] Unknown configuration field: {fieldName}");
                    break;
            }
            Log($"[MetaAuth] Configuration field '{fieldName}' updated to: {value}");
        }

        public bool IsFeatureEnabled(string featureName)
        {
            switch (featureName.ToLowerInvariant())
            {
                case "attestation":
                    return config.enableAttestation;
                case "photon":
                    return config.enablePhoton;
                case "playfab":
                    return config.enablePlayFab;
                case "voice":
                    return config.photonEnableVoice;
                case "analytics":
                    return config.enableAnalytics;
                case "healthcheck":
                    return config.enableServerHealthCheck;
                case "networkmonitor":
                    return config.enableNetworkMonitoring;
                case "autorefresh":
                    return config.enableTokenAutoRefresh;
                case "datasync":
                    return config.playfabEnableDataSync;
                case "ratelimiting":
                    return config.enableRateLimiting;
                case "bancheck":
                    return config.enableDeviceBanCheck;
                case "versioncheck":
                    return config.enableVersionCheck;
                case "sessionpersistence":
                    return config.enableSessionPersistence;
                case "crosssessioncaching":
                    return config.enableCrossSessionCaching;
                default:
                    return false;
            }
        }

        private void CollectDeviceInformation()
        {
            _deviceInfo = new DeviceInformation();
            _deviceInfo.deviceModel = SystemInfo.deviceModel;
            _deviceInfo.devicePlatform = Application.platform.ToString();
            _deviceInfo.deviceOperatingSystem = SystemInfo.operatingSystem;
            _deviceInfo.deviceLanguage = Application.systemLanguage.ToString();
            _deviceInfo.deviceUniqueIdentifier = SystemInfo.deviceUniqueIdentifier;
            _deviceInfo.graphicsDeviceName = SystemInfo.graphicsDeviceName;
            _deviceInfo.graphicsDeviceVersion = SystemInfo.graphicsDeviceVersion;
            _deviceInfo.graphicsDeviceType = SystemInfo.graphicsDeviceType.ToString();
            _deviceInfo.graphicsMemorySize = SystemInfo.graphicsMemorySize;
            _deviceInfo.systemMemorySize = SystemInfo.systemMemorySize;
            _deviceInfo.processorCount = SystemInfo.processorCount;
            _deviceInfo.processorType = SystemInfo.processorType;
            _deviceInfo.isEditor = Application.isEditor;
            _deviceInfo.isMobile = Application.isMobilePlatform;
            _deviceInfo.isVRDevice = UnityEngine.XR.XRSettings.isDeviceActive;
            if (_deviceInfo.isVRDevice)
            {
                _deviceInfo.vrDeviceName = UnityEngine.XR.XRSettings.loadedDeviceName;
            }
            _deviceInfo.batteryStatus = SystemInfo.batteryStatus.ToString();
            _deviceInfo.batteryLevel = SystemInfo.batteryLevel;
            _deviceInfo.networkType = Application.internetReachability.ToString();
            _deviceInfo.networkReachability = Application.internetReachability.ToString();
            _deviceInfo.appVersion = Application.version;
            _deviceInfo.appBundleIdentifier = Application.identifier;
            _deviceInfo.screenDpi = Screen.dpi;
            _deviceInfo.screenWidth = Screen.width;
            _deviceInfo.screenHeight = Screen.height;
            _deviceInfo.operatingSystemFamily = SystemInfo.operatingSystemFamily.ToString();
            Log($"[MetaAuth] Device info collected: {_deviceInfo.deviceModel} ({_deviceInfo.devicePlatform})");
            OnDeviceInfoCollected?.Invoke(_deviceInfo);
        }

        public string GetDeviceInfoSummary()
        {
            if (_deviceInfo == null)
            {
                return "Device info not collected";
            }
            StringBuilder sb = new StringBuilder();
            sb.Append("Device: ").AppendLine(_deviceInfo.deviceModel);
            sb.Append("Platform: ").AppendLine(_deviceInfo.devicePlatform);
            sb.Append("OS: ").AppendLine(_deviceInfo.deviceOperatingSystem);
            sb.Append("Processor: ").AppendLine(_deviceInfo.processorType);
            sb.Append("RAM: ").Append(_deviceInfo.systemMemorySize).AppendLine(" MB");
            sb.Append("VRAM: ").Append(_deviceInfo.graphicsMemorySize).AppendLine(" MB");
            sb.Append("GPU: ").AppendLine(_deviceInfo.graphicsDeviceName);
            sb.Append("Screen: ").Append(_deviceInfo.screenWidth).Append("x").AppendLine(_deviceInfo.screenHeight.ToString());
            sb.Append("VR: ").AppendLine(_deviceInfo.isVRDevice ? _deviceInfo.vrDeviceName : "No");
            sb.Append("App: ").Append(_deviceInfo.appBundleIdentifier).Append(" v").AppendLine(_deviceInfo.appVersion);
            return sb.ToString();
        }

        public Dictionary<string, object> GetDeviceInfoDictionary()
        {
            Dictionary<string, object> dict = new Dictionary<string, object>();
            if (_deviceInfo == null)
            {
                return dict;
            }
            dict["deviceModel"] = _deviceInfo.deviceModel;
            dict["devicePlatform"] = _deviceInfo.devicePlatform;
            dict["deviceOperatingSystem"] = _deviceInfo.deviceOperatingSystem;
            dict["deviceLanguage"] = _deviceInfo.deviceLanguage;
            dict["deviceUniqueIdentifier"] = _deviceInfo.deviceUniqueIdentifier;
            dict["graphicsDeviceName"] = _deviceInfo.graphicsDeviceName;
            dict["graphicsDeviceVersion"] = _deviceInfo.graphicsDeviceVersion;
            dict["graphicsDeviceType"] = _deviceInfo.graphicsDeviceType;
            dict["graphicsMemorySize"] = _deviceInfo.graphicsMemorySize;
            dict["systemMemorySize"] = _deviceInfo.systemMemorySize;
            dict["processorCount"] = _deviceInfo.processorCount;
            dict["processorType"] = _deviceInfo.processorType;
            dict["isEditor"] = _deviceInfo.isEditor;
            dict["isMobile"] = _deviceInfo.isMobile;
            dict["isVRDevice"] = _deviceInfo.isVRDevice;
            dict["vrDeviceName"] = _deviceInfo.vrDeviceName;
            dict["batteryStatus"] = _deviceInfo.batteryStatus;
            dict["batteryLevel"] = _deviceInfo.batteryLevel;
            dict["networkType"] = _deviceInfo.networkType;
            dict["networkReachability"] = _deviceInfo.networkReachability;
            dict["appVersion"] = _deviceInfo.appVersion;
            dict["appBundleIdentifier"] = _deviceInfo.appBundleIdentifier;
            dict["screenDpi"] = _deviceInfo.screenDpi;
            dict["screenWidth"] = _deviceInfo.screenWidth;
            dict["screenHeight"] = _deviceInfo.screenHeight;
            dict["operatingSystemFamily"] = _deviceInfo.operatingSystemFamily;
            return dict;
        }

        private void CheckNetworkStatus()
        {
            bool wasStable = _networkMetrics.isNetworkStable;
            bool currentlyStable = Application.internetReachability != NetworkReachability.NotReachable;
            _networkMetrics.isNetworkStable = currentlyStable;
            if (!currentlyStable && wasStable)
            {
                _networkFailureCount++;
                _networkMetrics.disconnectionCount++;
                RecordEvent(currentState, "Network connectivity lost");
                OnNetworkLost?.Invoke();
                if (IsAuthenticated)
                {
                    SetState(AuthState.WaitingForNetwork);
                    StartCoroutine(WaitForNetworkRecovery());
                }
            }
            else if (currentlyStable && !wasStable)
            {
                _networkFailureCount = 0;
                RecordEvent(currentState, "Network connectivity restored");
                OnNetworkRestored?.Invoke();
                if (currentState == AuthState.WaitingForNetwork)
                {
                    SetState(AuthState.NetworkRestored);
                    if (!IsAuthenticated)
                    {
                        StartAuthentication();
                    }
                }
            }
            if (config.collectNetworkInfo)
            {
                UpdateNetworkMetrics();
            }
        }

        private void UpdateNetworkMetrics()
        {
            _networkMetrics.lastCheckedTimestamp = Time.time;
            _networkMetrics.networkReachability = Application.internetReachability.ToString();
            if (Application.internetReachability == NetworkReachability.ReachableViaLocalAreaNetwork)
            {
                _networkMetrics.networkType = "WiFi/LAN";
            }
            else if (Application.internetReachability == NetworkReachability.ReachableViaCarrierDataNetwork)
            {
                _networkMetrics.networkType = "Cellular";
            }
            else
            {
                _networkMetrics.networkType = "None";
            }
            string currentStatus = Application.internetReachability == NetworkReachability.NotReachable ? "Disconnected" : "Connected";
            _networkMetrics.currentNetworkStatus = currentStatus;
            float uptime = Time.time;
            _networkMetrics.uptimeSeconds = uptime;
            OnNetworkMetricsUpdated?.Invoke(_networkMetrics);
        }

        private IEnumerator WaitForNetworkRecovery()
        {
            Log("[MetaAuth] Waiting for network recovery");
            float startTime = Time.time;
            int recoveryAttempts = 0;
            while (Time.time - startTime < config.maxNetworkRecoveryTimeSeconds)
            {
                yield return new WaitForSeconds(config.networkRecoveryBackoffBase);
                recoveryAttempts++;
                if (Application.internetReachability != NetworkReachability.NotReachable)
                {
                    Log("[MetaAuth] Network recovered");
                    SetState(AuthState.NetworkRestored);
                    OnNetworkRestored?.Invoke();
                    if (!IsAuthenticated)
                    {
                        StartAuthentication();
                    }
                    else
                    {
                        if (config.enablePhoton)
                        {
                            SetState(AuthState.ReconnectingPhoton);
                        }
                        if (config.enablePlayFab)
                        {
                            SetState(AuthState.ReconnectingPlayFab);
                        }
                    }
                    yield break;
                }
                if (recoveryAttempts >= config.networkRecoveryMaxRetries)
                {
                    LogWarning($"[MetaAuth] Network recovery attempts exhausted ({recoveryAttempts})");
                }
            }
            LogError("[MetaAuth] Network recovery timed out");
            HandleError(AuthErrorType.NetworkUnavailable, "Could not restore network connectivity");
        }

        private void CheckTokenExpiry()
        {
            if (string.IsNullOrEmpty(_serverAuthToken))
            {
                return;
            }
            if (_serverAPI != null && !string.IsNullOrEmpty(_serverAuthToken))
            {
                bool tokenExpired = false;
                _serverAPI.CheckAuthStatus(
                    (response) =>
                    {
                        if (!response.success || !response.data.authenticated)
                        {
                            tokenExpired = true;
                        }
                    },
                    (error) =>
                    {
                        if (error.Contains("AUTH_EXPIRED") || error.Contains("401"))
                        {
                            tokenExpired = true;
                        }
                    }
                );
                if (tokenExpired)
                {
                    LogWarning("[MetaAuth] Token has expired");
                    OnTokenExpired?.Invoke(_serverAuthToken);
                    if (config.enableTokenAutoRefresh)
                    {
                        StartCoroutine(RefreshExpiredToken());
                    }
                }
            }
        }

        private IEnumerator RefreshExpiredToken()
        {
            SetSubState(AuthSubState.WaitingForTokenRefresh);
            SetState(AuthState.RefreshingToken);
            Log("[MetaAuth] Refreshing expired token");
            if (_serverAPI != null && !string.IsNullOrEmpty(_oculusUserId) && !string.IsNullOrEmpty(_oculusNonce))
            {
                bool refreshed = false;
                _serverAPI.AuthenticateOculus(
                    _oculusUserId,
                    _oculusNonce,
                    config.displayName,
                    (response) =>
                    {
                        if (response.success)
                        {
                            _serverAuthToken = response.data.token;
                            _serverAPI.SetAuthToken(_serverAuthToken);
                            refreshed = true;
                            Log("[MetaAuth] Token refreshed successfully");
                            OnTokenRefreshed?.Invoke(_serverAuthToken);
                        }
                    },
                    (error) =>
                    {
                        LogWarning($"[MetaAuth] Token refresh failed: {error}");
                    }
                );
                float refreshTimeout = 15f;
                float refreshElapsed = 0f;
                while (!refreshed && refreshElapsed < refreshTimeout)
                {
                    refreshElapsed += Time.deltaTime;
                    yield return null;
                }
                if (refreshed)
                {
                    SetState(AuthState.TokenRefreshed);
                }
                else
                {
                    LogWarning("[MetaAuth] Token refresh failed, will retry");
                }
            }
            SetSubState(AuthSubState.None);
        }

        private IEnumerator PerformHealthCheck()
        {
            if (_serverAPI == null)
            {
                _healthCheckCoroutine = null;
                yield break;
            }
            SetState(AuthState.PerformingHealthCheck);
            bool healthPassed = false;
            _serverAPI.GetHealth(
                (response) =>
                {
                    if (response.success)
                    {
                        healthPassed = true;
                    }
                },
                (error) =>
                {
                    LogWarning($"[MetaAuth] Health check failed: {error}");
                }
            );
            float healthTimeout = 10f;
            float healthElapsed = 0f;
            while (!healthPassed && healthElapsed < healthTimeout)
            {
                healthElapsed += Time.deltaTime;
                yield return null;
            }
            if (healthPassed)
            {
                SetState(AuthState.HealthCheckComplete);
                OnHealthCheckPassed?.Invoke();
            }
            else
            {
                OnHealthCheckFailed?.Invoke("Server health check failed");
            }
            _healthCheckCoroutine = null;
        }

        private IEnumerator SyncPlayerData()
        {
            if (!config.enablePlayFab || !config.playfabEnableDataSync)
            {
                yield break;
            }
            SetState(AuthState.SyncingPlayerData);
            if (_serverAPI != null && _serverAPI.IsAuthenticated)
            {
                bool synced = false;
                _serverAPI.GetAuthStatus(
                    (response) =>
                    {
                        if (response.success)
                        {
                            synced = true;
                        }
                    },
                    (error) =>
                    {
                        LogWarning($"[MetaAuth] Data sync check failed: {error}");
                    }
                );
                float syncTimeout = 5f;
                float syncElapsed = 0f;
                while (!synced && syncElapsed < syncTimeout)
                {
                    syncElapsed += Time.deltaTime;
                    yield return null;
                }
            }
            SetState(AuthState.PlayerDataSynced);
        }

        private void ProcessPendingOperations()
        {
            if (_pendingOperations.Count > 0 && !_isProcessing)
            {
                Action operation = _pendingOperations.Dequeue();
                if (operation != null)
                {
                    operation.Invoke();
                }
            }
        }

        public void QueueOperation(Action operation)
        {
            if (operation == null)
            {
                return;
            }
            if (_pendingOperations.Count < 50)
            {
                _pendingOperations.Enqueue(operation);
            }
            else
            {
                LogWarning("[MetaAuth] Operation queue full, discarding operation");
            }
        }

        private bool IsRateLimited(string operationType)
        {
            if (!config.enableRateLimiting)
            {
                return false;
            }
            string key = operationType;
            if (_rateLimitTracker.ContainsKey(key))
            {
                float lastTime = _rateLimitTracker[key];
                float minInterval = 60f / config.maxRequestsPerMinute;
                if (Time.time - lastTime < minInterval)
                {
                    return true;
                }
            }
            return false;
        }

        private void TrackRateLimit(string operationType)
        {
            if (!config.enableRateLimiting)
            {
                return;
            }
            _rateLimitTracker[operationType] = Time.time;
        }

        private float GetRateLimitWaitTime(string operationType)
        {
            if (!config.enableRateLimiting)
            {
                return 0f;
            }
            string key = operationType;
            if (_rateLimitTracker.ContainsKey(key))
            {
                float lastTime = _rateLimitTracker[key];
                float minInterval = 60f / config.maxRequestsPerMinute;
                float timeSinceLast = Time.time - lastTime;
                if (timeSinceLast < minInterval)
                {
                    return minInterval - timeSinceLast;
                }
            }
            return 0f;
        }

        private bool IsNonceProcessed(string nonce)
        {
            if (!config.enableReplayAttackProtection)
            {
                return false;
            }
            return _processedNonces.Contains(nonce);
        }

        private void MarkNonceProcessed(string nonce)
        {
            if (!config.enableReplayAttackProtection)
            {
                return;
            }
            _processedNonces.Add(nonce);
            if (_processedNonces.Count > 100)
            {
                string[] noncesArray = new string[_processedNonces.Count];
                _processedNonces.CopyTo(noncesArray);
                _processedNonces.Clear();
                for (int i = Math.Max(0, noncesArray.Length - 50); i < noncesArray.Length; i++)
                {
                    _processedNonces.Add(noncesArray[i]);
                }
            }
        }

        private bool CheckLocalBanCache(string deviceId)
        {
            if (!config.enableLocalBanCache || string.IsNullOrEmpty(deviceId))
            {
                return false;
            }
            if (_localBanCache.ContainsKey(deviceId))
            {
                string banData = _localBanCache[deviceId];
                string[] parts = banData.Split('|');
                if (parts.Length >= 2)
                {
                    float banTime;
                    if (float.TryParse(parts[0], out banTime))
                    {
                        float banDuration = config.banCacheDurationHours * 3600f;
                        if (Time.time - banTime < banDuration)
                        {
                            LogWarning($"[MetaAuth] Device is locally banned: {parts[1]}");
                            return true;
                        }
                        else
                        {
                            _localBanCache.Remove(deviceId);
                            SaveLocalBanCache();
                        }
                    }
                }
            }
            return false;
        }

        private void AddLocalBan(string deviceId, string reason)
        {
            if (!config.enableLocalBanCache || string.IsNullOrEmpty(deviceId))
            {
                return;
            }
            string banData = Time.time + "|" + reason;
            _localBanCache[deviceId] = banData;
            SaveLocalBanCache();
            Log($"[MetaAuth] Added local ban for device {deviceId}: {reason}");
        }

        private void SaveLocalBanCache()
        {
            if (!config.enableLocalBanCache)
            {
                return;
            }
            try
            {
                string data = "";
                foreach (KeyValuePair<string, string> entry in _localBanCache)
                {
                    data += entry.Key + "=" + entry.Value + "\n";
                }
                PlayerPrefs.SetString("MetaAuth_LocalBanCache", data);
                PlayerPrefs.Save();
            }
            catch (Exception e)
            {
                LogWarning($"[MetaAuth] Failed to save local ban cache: {e.Message}");
            }
        }

        private void LoadLocalBanCache()
        {
            try
            {
                string data = PlayerPrefs.GetString("MetaAuth_LocalBanCache", "");
                if (string.IsNullOrEmpty(data))
                {
                    return;
                }
                string[] lines = data.Split('\n');
                foreach (string line in lines)
                {
                    if (string.IsNullOrEmpty(line))
                    {
                        continue;
                    }
                    string[] parts = line.Split('=');
                    if (parts.Length >= 2)
                    {
                        _localBanCache[parts[0]] = parts[1];
                    }
                }
                Log($"[MetaAuth] Loaded {_localBanCache.Count} local ban entries");
            }
            catch (Exception e)
            {
                LogWarning($"[MetaAuth] Failed to load local ban cache: {e.Message}");
            }
        }

        private void SaveCachedSessions()
        {
            if (!config.enableSessionPersistence || !config.enableCrossSessionCaching)
            {
                return;
            }
            try
            {
                string data = "";
                int sessionsToSave = Mathf.Min(_cachedSessions.Count, config.maxCachedSessions);
                int startIndex = Mathf.Max(0, _cachedSessions.Count - sessionsToSave);
                for (int i = startIndex; i < _cachedSessions.Count; i++)
                {
                    CachedSessionData session = _cachedSessions[i];
                    if (session != null)
                    {
                        data += session.oculusUserId + "|";
                        data += session.serverAuthToken + "|";
                        data += session.attestationServerToken + "|";
                        data += session.photonRealtimeAppId + "|";
                        data += session.photonVoiceAppId + "|";
                        data += session.playfabTitleId + "|";
                        data += session.displayName + "|";
                        data += session.lastAuthenticatedTimestamp + "|";
                        data += session.tokenExpiryTimestamp + "|";
                        data += session.sessionId + "|";
                        data += session.authenticationCount + "\n";
                    }
                }
                PlayerPrefs.SetString("MetaAuth_CachedSessions", data);
                PlayerPrefs.Save();
            }
            catch (Exception e)
            {
                LogWarning($"[MetaAuth] Failed to save cached sessions: {e.Message}");
            }
        }

        private void LoadCachedSessions()
        {
            try
            {
                string data = PlayerPrefs.GetString("MetaAuth_CachedSessions", "");
                if (string.IsNullOrEmpty(data))
                {
                    return;
                }
                string[] lines = data.Split('\n');
                foreach (string line in lines)
                {
                    if (string.IsNullOrEmpty(line))
                    {
                        continue;
                    }
                    string[] parts = line.Split('|');
                    if (parts.Length >= 11)
                    {
                        CachedSessionData session = new CachedSessionData();
                        session.oculusUserId = parts[0];
                        session.serverAuthToken = parts[1];
                        session.attestationServerToken = parts[2];
                        session.photonRealtimeAppId = parts[3];
                        session.photonVoiceAppId = parts[4];
                        session.playfabTitleId = parts[5];
                        session.displayName = parts[6];
                        float.TryParse(parts[7], out session.lastAuthenticatedTimestamp);
                        float.TryParse(parts[8], out session.tokenExpiryTimestamp);
                        session.sessionId = parts[9];
                        int.TryParse(parts[10], out session.authenticationCount);
                        _cachedSessions.Add(session);
                    }
                }
                Log($"[MetaAuth] Loaded {_cachedSessions.Count} cached sessions");
            }
            catch (Exception e)
            {
                LogWarning($"[MetaAuth] Failed to load cached sessions: {e.Message}");
            }
        }

        private void CacheCurrentSession()
        {
            if (!config.enableSessionPersistence || !config.enableCrossSessionCaching)
            {
                return;
            }
            CachedSessionData session = new CachedSessionData();
            session.oculusUserId = _oculusUserId;
            session.serverAuthToken = _serverAuthToken;
            session.attestationServerToken = _attestationServerToken;
            session.photonRealtimeAppId = config.photonRealtimeAppId;
            session.photonVoiceAppId = config.photonVoiceAppId;
            session.playfabTitleId = config.playfabTitleId;
            session.displayName = config.displayName;
            session.lastAuthenticatedTimestamp = Time.time;
            session.tokenExpiryTimestamp = Time.time + 86400f;
            session.sessionId = _sessionId;
            session.authenticationCount = _authenticationCount;
            _cachedSessions.Add(session);
            if (_cachedSessions.Count > config.maxCachedSessions)
            {
                _cachedSessions.RemoveAt(0);
            }
            SaveCachedSessions();
        }

        private void RestoreCachedSession(CachedSessionData session)
        {
            if (session == null)
            {
                return;
            }
            _oculusUserId = session.oculusUserId;
            _serverAuthToken = session.serverAuthToken;
            _attestationServerToken = session.attestationServerToken;
            config.photonRealtimeAppId = session.photonRealtimeAppId;
            config.photonVoiceAppId = session.photonVoiceAppId;
            config.playfabTitleId = session.playfabTitleId;
            config.displayName = session.displayName;
            _authenticationCount = session.authenticationCount;
            _sessionId = session.sessionId;
            if (_serverAPI != null && !string.IsNullOrEmpty(_serverAuthToken))
            {
                _serverAPI.SetAuthToken(_serverAuthToken);
            }
            Log($"[MetaAuth] Restored session for user {_oculusUserId}");
        }

        private IEnumerator AuthenticationCoroutine()
        {
            _isProcessing = true;
            _retryCount = 0;
            lastError = "";
            lastErrorType = AuthErrorType.None;
            SetState(AuthState.InitializingOculus);
            OnProgress?.Invoke(0.02f);

            bool oculusSuccess = false;
            string oculusError = "";
            yield return StartCoroutine(Step_GetOculusCredentials(
                () => oculusSuccess = true,
                (err) =>
                {
                    oculusError = err;
                    lastErrorType = AuthErrorType.OculusInitFailed;
                }
            ));

            if (!oculusSuccess)
            {
                if (_retryCount < config.maxAuthRetries)
                {
                    _retryCount++;
                    LogWarning($"[MetaAuth] Retrying Oculus auth ({_retryCount}/{config.maxAuthRetries})...");
                    SetSubState(AuthSubState.WaitingForRetryBackoff);
                    float backoffDelay = Mathf.Min(config.retryBackoffBaseDelay * _retryCount, config.retryBackoffMaxDelay);
                    yield return new WaitForSeconds(backoffDelay);
                    SetSubState(AuthSubState.None);
                    yield return StartCoroutine(Step_GetOculusCredentials(
                        () => oculusSuccess = true,
                        (err) =>
                        {
                            oculusError = err;
                            lastErrorType = AuthErrorType.OculusInitFailed;
                        }
                    ));
                }
                if (!oculusSuccess)
                {
                    HandleError(lastErrorType, "Failed to get Oculus credentials: " + oculusError);
                    yield break;
                }
            }

            OnProgress?.Invoke(0.15f);

            if (config.requireEntitlementCheck && !Application.isEditor)
            {
                SetState(AuthState.CheckingEntitlement);
                bool entitlementOk = false;
                string entitlementErr = "";
                yield return StartCoroutine(CheckEntitlement(
                    () => entitlementOk = true,
                    (err) =>
                    {
                        entitlementErr = err;
                        lastErrorType = AuthErrorType.OculusEntitlementFailed;
                    }
                ));
                if (!entitlementOk)
                {
                    HandleError(lastErrorType, "Entitlement check failed: " + entitlementErr);
                    yield break;
                }
                SetState(AuthState.EntitlementChecked);
                OnProgress?.Invoke(0.2f);
            }

            bool serverAuthSuccess = false;
            string serverAuthError = "";
            yield return StartCoroutine(Step_ServerAuthentication(
                () => serverAuthSuccess = true,
                (err) =>
                {
                    serverAuthError = err;
                    lastErrorType = AuthErrorType.ServerAuthFailed;
                }
            ));

            if (!serverAuthSuccess)
            {
                HandleError(lastErrorType, "Server authentication failed: " + serverAuthError);
                yield break;
            }

            OnProgress?.Invoke(0.35f);
            OnProgress?.Invoke(0.4f);

            if (config.collectDeviceInfo && config.sendDeviceInfoToServer)
            {
                yield return StartCoroutine(SendDeviceInfoToServer());
            }

            if (config.enableAttestation && !Application.isEditor)
            {
                yield return StartCoroutine(Step_Attestation());
                if (currentState == AuthState.Error || currentState == AuthState.Banned)
                {
                    yield break;
                }
            }
            else if (config.enableAttestation && Application.isEditor && config.editorSimulateAttestation)
            {
                Log("[MetaAuth] Editor mode: simulating attestation");
                yield return new WaitForSeconds(config.editorSimulatedLatency);
                OnProgress?.Invoke(0.6f);
            }

            OnProgress?.Invoke(0.6f);
            OnProgress?.Invoke(0.65f);

            if (config.enablePhoton)
            {
                yield return StartCoroutine(Step_PhotonConnection());
            }

            OnProgress?.Invoke(0.8f);
            OnProgress?.Invoke(0.82f);

            if (config.enablePlayFab)
            {
                yield return StartCoroutine(Step_PlayFabLogin());
            }

            OnProgress?.Invoke(0.9f);
            OnProgress?.Invoke(0.95f);

            if (config.enableSessionPersistence)
            {
                CacheCurrentSession();
                OnSessionCreated?.Invoke(_sessionId);
            }

            OnProgress?.Invoke(1.0f);
            SetState(AuthState.FullAuthComplete);
            _isProcessing = false;
            RecordEvent(AuthState.FullAuthComplete, "Authentication complete");
            Log("[MetaAuth] Authentication complete!");
            OnAuthenticationComplete?.Invoke();
        }

        private IEnumerator Step_GetOculusCredentials(Action onSuccess, Action<string> onError)
        {
            SetState(AuthState.GettingOculusCredentials);
            SetSubState(AuthSubState.WaitingForUserInfo);
            Log("[MetaAuth] Getting Oculus credentials...");

#if UNITY_EDITOR
            if (config.skipOculusInitInEditor)
            {
                Log($"[MetaAuth] Editor mode: using test credentials (UserID: {config.editorOverrideUserId})");
                _oculusUserId = config.editorOverrideUserId;
                _oculusNonce = config.editorOverrideNonce;
                SetSubState(AuthSubState.None);
                SetState(AuthState.OculusCredentialsReady);
                yield return new WaitForSeconds(config.editorSimulatedLatency);
                onSuccess?.Invoke();
                yield break;
            }
#endif

#if OCULUS_PLATFORM
            bool initDone = false;
            bool initError = false;
            string initErrorMsg = "";

            SetSubState(AuthSubState.WaitingForOculusInit);
            Log("[MetaAuth] Initializing Oculus Platform...");

            Core.AsyncInitialize().OnComplete((Message<PlatformInitialize> msg) =>
            {
                if (msg.IsError)
                {
                    initError = true;
                    initErrorMsg = msg.GetError().Message;
                    LogError($"[MetaAuth] Oculus init error: {initErrorMsg}");
                }
                else
                {
                    Log("[MetaAuth] Oculus Platform initialized");
                    initDone = true;
                }
            });

            float timeout = 15f * config.authTimeoutMultiplier;
            float elapsed = 0f;
            while (!initDone && !initError && elapsed < timeout)
            {
                elapsed += Time.deltaTime;
                yield return null;
            }

            if (initError)
            {
                SetSubState(AuthSubState.None);
                lastErrorType = AuthErrorType.OculusInitFailed;
                onError?.Invoke("Oculus init failed: " + initErrorMsg);
                yield break;
            }
            if (!initDone)
            {
                SetSubState(AuthSubState.None);
                lastErrorType = AuthErrorType.OculusTimeout;
                onError?.Invoke("Oculus init timed out after " + timeout + "s");
                yield break;
            }

            SetSubState(AuthSubState.None);
            SetState(AuthState.OculusReady);
            OnProgress?.Invoke(0.08f);

            if (config.requireEntitlementCheck)
            {
                SetSubState(AuthSubState.WaitingForEntitlement);
                bool entitledDone = false;
                bool entitledError = false;
                string entitledErrorMsg = "";

                Entitlements.IsUserEntitledToApplication().OnComplete((Message msg) =>
                {
                    if (msg.IsError)
                    {
                        entitledError = true;
                        entitledErrorMsg = msg.GetError().Message;
                        LogError($"[MetaAuth] Entitlement error: {entitledErrorMsg}");
                    }
                    else
                    {
                        Log("[MetaAuth] User is entitled");
                        entitledDone = true;
                    }
                });

                elapsed = 0f;
                while (!entitledDone && !entitledError && elapsed < 10f)
                {
                    elapsed += Time.deltaTime;
                    yield return null;
                }

                if (entitledError)
                {
                    SetSubState(AuthSubState.None);
                    lastErrorType = AuthErrorType.OculusEntitlementFailed;
                    onError?.Invoke("Entitlement check failed: " + entitledErrorMsg);
                    yield break;
                }

                SetSubState(AuthSubState.None);
                OnEntitlementConfirmed?.Invoke();
            }

            SetSubState(AuthSubState.WaitingForUserInfo);
            bool userDone = false;
            bool userError = false;
            string userName = "";

            Users.GetLoggedInUser().OnComplete((Message<User> msg) =>
            {
                if (msg.IsError)
                {
                    userError = true;
                }
                else
                {
                    _oculusUserId = msg.Data.ID.ToString();
                    userName = msg.Data.OculusID;
                    userDone = true;
                    Log($"[MetaAuth] Logged in as {userName} (ID: {_oculusUserId})");
                }
            });

            elapsed = 0f;
            while (!userDone && !userError && elapsed < 10f)
            {
                elapsed += Time.deltaTime;
                yield return null;
            }

            if (userError || string.IsNullOrEmpty(_oculusUserId))
            {
                SetSubState(AuthSubState.None);
                lastErrorType = AuthErrorType.OculusUserNotFound;
                onError?.Invoke("Failed to get logged in user");
                yield break;
            }

            SetSubState(AuthSubState.WaitingForUserProof);
            bool proofDone = false;
            bool proofError = false;

            Users.GetUserProof().OnComplete((Message<UserProof> msg) =>
            {
                if (msg.IsError)
                {
                    proofError = true;
                }
                else
                {
                    _oculusNonce = msg.Data.Value;
                    proofDone = true;
                    Log("[MetaAuth] Got Oculus nonce");
                }
            });

            elapsed = 0f;
            while (!proofDone && !proofError && elapsed < 10f)
            {
                elapsed += Time.deltaTime;
                yield return null;
            }

            if (proofError || string.IsNullOrEmpty(_oculusNonce))
            {
                SetSubState(AuthSubState.None);
                lastErrorType = AuthErrorType.OculusProofFailed;
                onError?.Invoke("Failed to get user proof (nonce)");
                yield break;
            }

            if (string.IsNullOrEmpty(config.displayName) || config.displayName == "WaterTag Player")
            {
                config.displayName = SanitizeDisplayName(userName);
            }

            SetSubState(AuthSubState.None);
            SetState(AuthState.OculusCredentialsReady);
            onSuccess?.Invoke();
#else
            LogWarning("[MetaAuth] OCULUS_PLATFORM define not found. Install Oculus Platform SDK and add 'OCULUS_PLATFORM' to Scripting Define Symbols.");
            lastErrorType = AuthErrorType.OculusInitFailed;
            onError?.Invoke("OCULUS_PLATFORM not defined");
            yield break;
#endif
        }

        private IEnumerator CheckEntitlement(Action onSuccess, Action<string> onError)
        {
#if OCULUS_PLATFORM && !UNITY_EDITOR
            Log("[MetaAuth] Checking Oculus entitlement...");
            bool entitledDone = false;
            bool entitledError = false;
            string entitledErrorMsg = "";

            Entitlements.IsUserEntitledToApplication().OnComplete((Message msg) =>
            {
                if (msg.IsError)
                {
                    entitledError = true;
                    entitledErrorMsg = msg.GetError().Message;
                    LogError($"[MetaAuth] Entitlement check error: {entitledErrorMsg}");
                }
                else
                {
                    Log("[MetaAuth] User is entitled to this application");
                    entitledDone = true;
                }
            });

            float timeout = 10f;
            float elapsed = 0f;
            while (!entitledDone && !entitledError && elapsed < timeout)
            {
                elapsed += Time.deltaTime;
                yield return null;
            }

            if (entitledError)
            {
                onError?.Invoke(entitledErrorMsg);
                yield break;
            }
            if (!entitledDone)
            {
                onError?.Invoke("Entitlement check timed out");
                yield break;
            }

            onSuccess?.Invoke();
#else
            Log("[MetaAuth] Entitlement check skipped (editor or no Oculus SDK)");
            onSuccess?.Invoke();
            yield break;
#endif
        }

        private IEnumerator Step_ServerAuthentication(Action onSuccess, Action<string> onError)
        {
            SetState(AuthState.AuthenticatingWithServer);
            SetSubState(AuthSubState.WaitingForServerAuth);
            Log("[MetaAuth] Authenticating with server...");

            if (IsRateLimited("server_auth"))
            {
                float waitTime = GetRateLimitWaitTime("server_auth");
                SetState(AuthState.RateLimitWaiting);
                OnRateLimitHit?.Invoke("server_auth", waitTime);
                yield return new WaitForSeconds(waitTime);
                SetState(AuthState.RateLimitComplete);
                OnRateLimitLifted?.Invoke();
            }

            bool done = false;
            string errorMsg = "";

            _serverAPI.AuthenticateOculus(_oculusUserId, _oculusNonce, config.displayName,
                (response) =>
                {
                    TrackRateLimit("server_auth");
                    if (response.success)
                    {
                        _serverAuthToken = response.data.token;
                        _serverAPI.SetAuthToken(_serverAuthToken);
                        Log($"[MetaAuth] Server authenticated. UserID: {response.data.userId}");
                        done = true;
                    }
                    else
                    {
                        errorMsg = response.message;
                        done = true;
                        if (response.code == "RATE_LIMITED")
                        {
                            lastErrorType = AuthErrorType.RateLimited;
                        }
                    }
                },
                (error) =>
                {
                    errorMsg = error;
                    done = true;
                    if (error.Contains("AUTH_EXPIRED"))
                    {
                        lastErrorType = AuthErrorType.ServerTokenExpired;
                    }
                    else if (error.Contains("timeout") || error.Contains("Timeout"))
                    {
                        lastErrorType = AuthErrorType.NetworkTimeout;
                    }
                    else
                    {
                        lastErrorType = AuthErrorType.ServerAuthFailed;
                    }
                });

            yield return new WaitUntil(() => done);

            if (!string.IsNullOrEmpty(errorMsg) || string.IsNullOrEmpty(_serverAuthToken))
            {
                SetSubState(AuthSubState.None);
                onError?.Invoke(errorMsg);
                yield break;
            }

            SetSubState(AuthSubState.None);
            SetState(AuthState.ServerAuthenticated);
            onSuccess?.Invoke();
        }

        private IEnumerator SendDeviceInfoToServer()
        {
            if (_deviceInfo == null || !config.sendDeviceInfoToServer || _serverAPI == null)
            {
                yield break;
            }
            if (!_serverAPI.IsAuthenticated)
            {
                yield break;
            }
            Log("[MetaAuth] Sending device info to server");
            Dictionary<string, object> deviceData = GetDeviceInfoDictionary();
            yield return null;
        }

        private IEnumerator Step_Attestation()
        {
            SetState(AuthState.GettingChallengeNonce);
            SetSubState(AuthSubState.WaitingForChallengeNonce);
            Log("[MetaAuth] Getting challenge nonce...");

            if (IsRateLimited("challenge_nonce"))
            {
                float waitTime = GetRateLimitWaitTime("challenge_nonce");
                SetState(AuthState.RateLimitWaiting);
                OnRateLimitHit?.Invoke("challenge_nonce", waitTime);
                yield return new WaitForSeconds(waitTime);
                SetState(AuthState.RateLimitComplete);
                OnRateLimitLifted?.Invoke();
            }

            bool nonceDone = false;
            string nonceError = "";

            _serverAPI.GetChallengeNonce(
                (response) =>
                {
                    TrackRateLimit("challenge_nonce");
                    if (response.success)
                    {
                        _challengeNonce = response.data.challengeNonce;
                        _signedNonce = response.data.signedNonce;
                        string noncePreview = _challengeNonce;
                        if (noncePreview.Length > 16)
                        {
                            noncePreview = noncePreview.Substring(0, 16);
                        }
                        Log($"[MetaAuth] Challenge nonce received: {noncePreview}...");
                        nonceDone = true;
                    }
                    else
                    {
                        nonceError = response.message;
                        nonceDone = true;
                    }
                },
                (error) =>
                {
                    nonceError = error;
                    nonceDone = true;
                });

            yield return new WaitUntil(() => nonceDone);

            if (string.IsNullOrEmpty(_challengeNonce))
            {
                LogWarning($"[MetaAuth] Failed to get challenge nonce: {nonceError}. Skipping attestation.");
                OnProgress?.Invoke(0.5f);
                SetSubState(AuthSubState.None);
                yield break;
            }

            if (IsNonceProcessed(_challengeNonce) && config.enableReplayAttackProtection)
            {
                LogWarning("[MetaAuth] Challenge nonce was already processed, possible replay attack");
                SetSubState(AuthSubState.None);
                yield break;
            }

            MarkNonceProcessed(_challengeNonce);

            SetSubState(AuthSubState.None);
            SetState(AuthState.ChallengeNonceReady);
            OnProgress?.Invoke(0.45f);

            SetState(AuthState.RequestingAttestation);
            SetSubState(AuthSubState.WaitingForAttestationRequest);
            Log("[MetaAuth] Requesting attestation token from device...");

            bool attestApiDone = false;
            string attestApiError = "";

            StartCoroutine(RequestAttestationToken(_challengeNonce,
                (token) =>
                {
                    _attestationToken = token;
                    attestApiDone = true;
                    string tokenPreview = token;
                    if (tokenPreview.Length > 32)
                    {
                        tokenPreview = tokenPreview.Substring(0, 32);
                    }
                    Log($"[MetaAuth] Attestation token received: {tokenPreview}...");
                },
                (error) =>
                {
                    attestApiError = error;
                    attestApiDone = true;
                    lastErrorType = AuthErrorType.AttestationApiUnavailable;
                }));

            yield return new WaitUntil(() => attestApiDone);

            if (string.IsNullOrEmpty(_attestationToken))
            {
                LogWarning($"[MetaAuth] Attestation API failed: {attestApiError}. Skipping attestation verification.");
                OnProgress?.Invoke(0.5f);
                SetSubState(AuthSubState.None);
                yield break;
            }

            SetSubState(AuthSubState.None);
            SetState(AuthState.AttestationTokenReady);
            OnProgress?.Invoke(0.5f);

            if (config.enableDeviceBanCheck && !string.IsNullOrEmpty(_deviceUniqueId))
            {
                if (CheckLocalBanCache(_deviceUniqueId))
                {
                    lastErrorType = AuthErrorType.DeviceBanned;
                    SetState(AuthState.Banned);
                    OnBanned?.Invoke();
                    OnBanDetected?.Invoke("Device is locally banned");
                    SetSubState(AuthSubState.None);
                    yield break;
                }
            }

            SetState(AuthState.VerifyingAttestation);
            SetSubState(AuthSubState.WaitingForAttestationVerify);
            Log("[MetaAuth] Verifying attestation token...");

            if (IsRateLimited("verify_attestation"))
            {
                float waitTime = GetRateLimitWaitTime("verify_attestation");
                SetState(AuthState.RateLimitWaiting);
                OnRateLimitHit?.Invoke("verify_attestation", waitTime);
                yield return new WaitForSeconds(waitTime);
                SetState(AuthState.RateLimitComplete);
                OnRateLimitLifted?.Invoke();
            }

            bool verifyDone = false;
            string verifyError = "";

            _serverAPI.VerifyAttestation(_attestationToken, _signedNonce, _challengeNonce,
                (response) =>
                {
                    TrackRateLimit("verify_attestation");
                    if (response.success)
                    {
                        _attestationServerToken = response.data.token;
                        string appInteg = response.data.appIntegrity;
                        string devInteg = response.data.deviceIntegrity;
                        string pkgId = response.data.packageId;
                        string uniqueId = response.data.uniqueId;
                        bool banned = response.data.banActive || response.data.isBanned;

                        Log($"[MetaAuth] Attestation verified!");
                        Log($"[MetaAuth]   App Integrity: {appInteg}");
                        Log($"[MetaAuth]   Device Integrity: {devInteg}");
                        Log($"[MetaAuth]   Package: {pkgId}");
                        Log($"[MetaAuth]   Unique Device ID: {uniqueId}");

                        if (banned)
                        {
                            string banMsg = response.data.banMessage;
                            int banTime = response.data.banRemainingTime;
                            LogError($"[MetaAuth] DEVICE IS BANNED! Remaining: {banTime} minutes - {banMsg}");
                            if (!string.IsNullOrEmpty(_deviceUniqueId))
                            {
                                AddLocalBan(_deviceUniqueId, banMsg);
                            }
                            lastErrorType = AuthErrorType.DeviceBanned;
                            SetState(AuthState.Banned);
                            OnBanned?.Invoke();
                            OnBanDetected?.Invoke(banMsg);
                            verifyDone = true;
                            return;
                        }

                        if (!string.IsNullOrEmpty(response.data.photonRealtimeAppId))
                        {
                            config.photonRealtimeAppId = response.data.photonRealtimeAppId;
                        }
                        if (!string.IsNullOrEmpty(response.data.photonVoiceAppId))
                        {
                            config.photonVoiceAppId = response.data.photonVoiceAppId;
                        }
                        if (!string.IsNullOrEmpty(response.data.playfabTitleId))
                        {
                            config.playfabTitleId = response.data.playfabTitleId;
                        }

                        if (response.data.attestationPassed && devInteg == "NotTrusted")
                        {
                            LogWarning("[MetaAuth] Device integrity is NotTrusted. Consider limiting functionality.");
                        }

                        verifyDone = true;
                    }
                    else
                    {
                        verifyError = response.message;
                        verifyDone = true;
                        if (response.code == "NONCE_MISMATCH")
                        {
                            lastErrorType = AuthErrorType.AttestationTokenInvalid;
                        }
                        else if (response.code == "TOKEN_EXPIRED")
                        {
                            lastErrorType = AuthErrorType.AttestationTimeout;
                        }
                        else
                        {
                            lastErrorType = AuthErrorType.AttestationVerificationFailed;
                        }
                    }
                },
                (error) =>
                {
                    if (error.StartsWith("AUTH_EXPIRED:"))
                    {
                        LogError("[MetaAuth] Token expired during attestation. Restart auth flow.");
                        lastErrorType = AuthErrorType.ServerTokenExpired;
                    }
                    verifyError = error;
                    verifyDone = true;
                    lastErrorType = AuthErrorType.AttestationVerificationFailed;
                });

            yield return new WaitUntil(() => verifyDone);

            if (!string.IsNullOrEmpty(verifyError))
            {
                LogWarning($"[MetaAuth] Attestation verification failed: {verifyError}. Continuing without attestation.");
                OnProgress?.Invoke(0.55f);
                SetSubState(AuthSubState.None);
                yield break;
            }

            SetSubState(AuthSubState.None);
            SetState(AuthState.AttestationVerified);
            OnProgress?.Invoke(0.55f);
        }

        private IEnumerator RequestAttestationToken(string challengeNonce, Action<string> onToken, Action<string> onError)
        {
#if !UNITY_ANDROID
            LogWarning("[MetaAuth] Attestation API requires Android platform (Meta Quest). Generating mock token.");
            string mockPayload = "{\"mock\":true,\"nonce\":\"" + challengeNonce + "\"}";
            string mockToken = Convert.ToBase64String(Encoding.UTF8.GetBytes(mockPayload));
            yield return new WaitForSeconds(config.editorSimulatedLatency);
            onToken?.Invoke(mockToken);
            yield break;
#endif

#if OCULUS_PLATFORM && UNITY_ANDROID
            Log("[MetaAuth] Calling DeviceApplicationIntegrity.GetIntegrityToken...");

            bool apiDone = false;
            bool apiError = false;
            string apiErrorMsg = "";
            string resultToken = "";

            DeviceApplicationIntegrity
                .GetIntegrityToken(challengeNonce)
                .OnComplete((Message<string> msg) =>
                {
                    if (msg.IsError)
                    {
                        apiError = true;
                        apiErrorMsg = msg.GetError().Message;
                        LogError($"[MetaAuth] GetIntegrityToken error: {apiErrorMsg}");
                    }
                    else
                    {
                        resultToken = msg.Data;
                        Log("[MetaAuth] GetIntegrityToken succeeded");
                        apiDone = true;
                    }
                });

            float timeout = 30f * config.authTimeoutMultiplier;
            float elapsed = 0f;
            while (!apiDone && !apiError && elapsed < timeout)
            {
                elapsed += Time.deltaTime;
                yield return null;
            }

            if (apiError)
            {
                onError?.Invoke(apiErrorMsg);
                yield break;
            }
            if (!apiDone)
            {
                onError?.Invoke("GetIntegrityToken timed out after " + timeout + "s");
                yield break;
            }

            onToken?.Invoke(resultToken);
#else
            LogWarning("[MetaAuth] OCULUS_PLATFORM not defined or not Android. Cannot call native attestation API.");
            onError?.Invoke("Attestation API not available");
            yield break;
#endif
        }

        private IEnumerator Step_PhotonConnection()
        {
            SetState(AuthState.ConnectingPhoton);
            SetSubState(AuthSubState.WaitingForPhotonConnect);
            Log("[MetaAuth] Setting up Photon connection...");

            if (config.enableAnalytics)
            {
                RecordEvent(AuthState.ConnectingPhoton, "Starting Photon connection flow");
            }

            if (string.IsNullOrEmpty(config.photonRealtimeAppId))
            {
                Log("[MetaAuth] Photon App ID not configured locally, requesting from server...");
                bool done = false;
                string error = "";

                _serverAPI.GetPhotonAuth(config.displayName,
                    (response) =>
                    {
                        if (response.success)
                        {
                            config.photonRealtimeAppId = response.data.photonRealtimeAppId;
                            config.photonVoiceAppId = response.data.photonVoiceAppId;
                            Log($"[MetaAuth] Photon config from server: RT={config.photonRealtimeAppId} Voice={config.photonVoiceAppId}");
                        }
                        done = true;
                    },
                    (err) =>
                    {
                        error = err;
                        done = true;
                        lastErrorType = AuthErrorType.PhotonConfigMissing;
                    });

                yield return new WaitUntil(() => done);

                if (string.IsNullOrEmpty(config.photonRealtimeAppId))
                {
                    LogWarning($"[MetaAuth] Could not get Photon config from server: {error}. Skipping Photon connection.");
                    SetSubState(AuthSubState.None);
                    yield break;
                }
            }

            Log($"[MetaAuth] Ready to connect to Photon Realtime: {config.photonRealtimeAppId}");
            if (!string.IsNullOrEmpty(config.photonVoiceAppId) && config.photonEnableVoice)
            {
                Log($"[MetaAuth] Ready to connect to Photon Voice: {config.photonVoiceAppId}");
            }

            if (!string.IsNullOrEmpty(config.photonRealtimeAppId))
            {
                PhotonNetwork.PhotonServerSettings.AppSettings.AppIdRealtime = config.photonRealtimeAppId;
                if (!string.IsNullOrEmpty(config.photonVoiceAppId) && config.photonEnableVoice)
                {
                    PhotonNetwork.PhotonServerSettings.AppSettings.AppIdVoice = config.photonVoiceAppId;
                }

                PhotonNetwork.NetworkingClient.AuthValues = new Photon.Realtime.AuthenticationValues();
                PhotonNetwork.NetworkingClient.AuthValues.AuthType = Photon.Realtime.CustomAuthenticationType.Oculus;
                PhotonNetwork.NetworkingClient.AuthValues.AddAuthParameter("userid", _oculusUserId);
                PhotonNetwork.NetworkingClient.AuthValues.AddAuthParameter("nonce", _oculusNonce);

                Log("[MetaAuth] Oculus auth values set for Photon");
                GorillaNetworking.PhotonNetworkController.Instance.InitiateConnection();
                SetSubState(AuthSubState.None);
                SetState(AuthState.PhotonConnected);
                OnProgress?.Invoke(0.75f);
            }
            else
            {
                SetSubState(AuthSubState.None);
                LogWarning("[MetaAuth] Photon connection failed, continuing without multiplayer");
                OnProgress?.Invoke(0.75f);
            }
        }

        private IEnumerator Step_PlayFabLogin()
        {
            SetState(AuthState.LoggingIntoPlayFab);
            SetSubState(AuthSubState.WaitingForPlayFabLogin);
            Log("[MetaAuth] Logging into PlayFab...");

            if (config.enableAnalytics)
            {
                RecordEvent(AuthState.LoggingIntoPlayFab, "Starting PlayFab login flow");
            }

            if (IsRateLimited("playfab_login"))
            {
                float waitTime = GetRateLimitWaitTime("playfab_login");
                SetState(AuthState.RateLimitWaiting);
                OnRateLimitHit?.Invoke("playfab_login", waitTime);
                yield return new WaitForSeconds(waitTime);
                SetState(AuthState.RateLimitComplete);
                OnRateLimitLifted?.Invoke();
            }

            bool loginDone = false;
            string loginError = "";

            if (string.IsNullOrEmpty(config.playfabTitleId))
            {
                Log("[MetaAuth] PlayFab Title ID not set locally, requesting from server...");
                _serverAPI.LoginPlayFab(config.displayName,
                    (response) =>
                    {
                        TrackRateLimit("playfab_login");
                        if (response.success)
                        {
                            Log("[MetaAuth] PlayFab login successful via server");
                        }
                        else
                        {
                            loginError = response.message;
                        }
                        loginDone = true;
                    },
                    (err) =>
                    {
                        loginError = err;
                        loginDone = true;
                        lastErrorType = AuthErrorType.PlayFabLoginFailed;
                    });
            }
            else
            {
                Log($"[MetaAuth] PlayFab configured with Title ID: {config.playfabTitleId}");
                _serverAPI.LoginPlayFab(config.displayName,
                    (response) =>
                    {
                        TrackRateLimit("playfab_login");
                        if (response.success)
                        {
                            Log("[MetaAuth] PlayFab login successful via server");
                        }
                        else
                        {
                            loginError = response.message;
                        }
                        loginDone = true;
                    },
                    (err) =>
                    {
                        loginError = err;
                        loginDone = true;
                        lastErrorType = AuthErrorType.PlayFabLoginFailed;
                    });
            }

            yield return new WaitUntil(() => loginDone);

            if (!string.IsNullOrEmpty(loginError))
            {
                LogWarning($"[MetaAuth] PlayFab login failed: {loginError}");
                lastErrorType = AuthErrorType.PlayFabLoginFailed;
            }

            SetSubState(AuthSubState.None);
            SetState(AuthState.PlayFabLoggedIn);
            OnProgress?.Invoke(0.85f);
        }

        private void SetState(AuthState newState)
        {
            AuthState oldState = currentState;
            currentState = newState;
            OnStateChanged?.Invoke(newState);
            RecordEvent(newState, "State: " + oldState + " -> " + newState);
        }

        private void SetSubState(AuthSubState newSubState)
        {
            currentSubState = newSubState;
            OnSubStateChanged?.Invoke(newSubState);
        }

        private void HandleError(AuthErrorType errorType, string error)
        {
            lastError = error;
            lastErrorType = errorType;
            SetState(AuthState.Error);
            _isProcessing = false;
            LogError("[MetaAuth] Error: [" + errorType + "] " + error);
            OnError?.Invoke(errorType, error);
            RecordEvent(AuthState.Error, "Error: " + error + " (Type: " + errorType + ")");
        }

        private void OnServerTokenUpdated(string token)
        {
            Log("[MetaAuth] Server token updated");
            OnTokenRefreshed?.Invoke(token);
        }

        private void OnServerTokenCleared()
        {
            Log("[MetaAuth] Server token cleared (session expired)");
            if (currentState == AuthState.FullAuthComplete)
            {
                LogWarning("[MetaAuth] Auth token was cleared after full auth - session may have expired");
                OnTokenExpired?.Invoke("[MetaAuth] Token cleared");
            }
        }

        private void RecordEvent(AuthState state, string description)
        {
            if (!config.enableEventHistory)
            {
                return;
            }
            AuthenticationEvent evt = new AuthenticationEvent();
            evt.timestamp = Time.time;
            evt.state = state;
            evt.description = description;
            evt.isError = state == AuthState.Error || state == AuthState.Banned;
            if (evt.isError)
            {
                evt.errorCode = lastErrorType.ToString();
            }
            _eventHistory.Add(evt);
            if (_eventHistory.Count > config.maxEventHistoryEntries)
            {
                _eventHistory.RemoveAt(0);
            }
        }

        public List<AuthenticationEvent> GetEventHistory()
        {
            return new List<AuthenticationEvent>(_eventHistory);
        }

        public List<AuthenticationEvent> GetEventHistorySince(float timestamp)
        {
            List<AuthenticationEvent> filtered = new List<AuthenticationEvent>();
            foreach (AuthenticationEvent evt in _eventHistory)
            {
                if (evt.timestamp >= timestamp)
                {
                    filtered.Add(evt);
                }
            }
            return filtered;
        }

        public List<AuthenticationEvent> GetErrorEvents()
        {
            List<AuthenticationEvent> errors = new List<AuthenticationEvent>();
            foreach (AuthenticationEvent evt in _eventHistory)
            {
                if (evt.isError)
                {
                    errors.Add(evt);
                }
            }
            return errors;
        }

        public List<AuthenticationEvent> GetEventsByState(AuthState state)
        {
            List<AuthenticationEvent> filtered = new List<AuthenticationEvent>();
            foreach (AuthenticationEvent evt in _eventHistory)
            {
                if (evt.state == state)
                {
                    filtered.Add(evt);
                }
            }
            return filtered;
        }

        public float GetTimeSinceLastStateChange()
        {
            if (_eventHistory.Count < 2)
            {
                return 0f;
            }
            return Time.time - _eventHistory[_eventHistory.Count - 1].timestamp;
        }

        public float GetTotalAuthenticationTime()
        {
            if (currentState == AuthState.FullAuthComplete || currentState == AuthState.Error || currentState == AuthState.Banned)
            {
                return Time.time - _authStartTime;
            }
            return -1f;
        }

        public Dictionary<string, object> GetDiagnosticReport()
        {
            Dictionary<string, object> report = new Dictionary<string, object>();
            report["currentState"] = currentState.ToString();
            report["currentSubState"] = currentSubState.ToString();
            report["lastError"] = lastError;
            report["lastErrorType"] = lastErrorType.ToString();
            report["isAuthenticated"] = IsAuthenticated;
            report["isProcessing"] = _isProcessing;
            report["isInitialized"] = _isInitialized;
            report["authenticationCount"] = _authenticationCount;
            report["retryCount"] = _retryCount;
            report["networkFailureCount"] = _networkFailureCount;
            report["rateLimitHitCount"] = _rateLimitHitCount;
            report["sessionId"] = _sessionId;
            report["oculusUserId"] = _oculusUserId;
            report["hasServerToken"] = !string.IsNullOrEmpty(_serverAuthToken);
            report["hasAttestationToken"] = !string.IsNullOrEmpty(_attestationToken);
            report["hasChallengeNonce"] = !string.IsNullOrEmpty(_challengeNonce);
            report["networkStable"] = _networkMetrics.isNetworkStable;
            report["networkType"] = _networkMetrics.networkType;
            report["networkStatus"] = _networkMetrics.currentNetworkStatus;
            report["eventHistoryCount"] = _eventHistory.Count;
            report["cachedSessionCount"] = _cachedSessions.Count;
            report["pendingOperations"] = _pendingOperations.Count;
            report["localBanCount"] = _localBanCache.Count;
            report["uptime"] = Time.time;
            report["authStartTime"] = _authStartTime;
            report["totalAuthTime"] = GetTotalAuthenticationTime();
            report["deviceModel"] = _deviceInfo != null ? _deviceInfo.deviceModel : "Unknown";
            report["appVersion"] = _appVersion;
            report["configServer"] = config.serverUrl;
            report["configPhoton"] = !string.IsNullOrEmpty(config.photonRealtimeAppId);
            report["configPlayFab"] = !string.IsNullOrEmpty(config.playfabTitleId);
            report["features"] = new Dictionary<string, bool>
            {
                ["attestation"] = config.enableAttestation,
                ["photon"] = config.enablePhoton,
                ["playfab"] = config.enablePlayFab,
                ["analytics"] = config.enableAnalytics,
                ["networkMonitor"] = config.enableNetworkMonitoring,
                ["tokenRefresh"] = config.enableTokenAutoRefresh,
                ["rateLimiting"] = config.enableRateLimiting,
                ["dataSync"] = config.playfabEnableDataSync,
                ["banCheck"] = config.enableDeviceBanCheck,
                ["versionCheck"] = config.enableVersionCheck
            };
            return report;
        }

        public string GetDiagnosticReportString()
        {
            Dictionary<string, object> report = GetDiagnosticReport();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== MetaAuth Diagnostic Report ===");
            sb.AppendLine("State: " + report["currentState"]);
            sb.AppendLine("SubState: " + report["currentSubState"]);
            if (!string.IsNullOrEmpty(lastError))
            {
                sb.AppendLine("Last Error: [" + report["lastErrorType"] + "] " + report["lastError"]);
            }
            sb.AppendLine("Authenticated: " + report["isAuthenticated"]);
            sb.AppendLine("Processing: " + report["isProcessing"]);
            sb.AppendLine("Auth Count: " + report["authenticationCount"]);
            sb.AppendLine("Retry Count: " + report["retryCount"]);
            sb.AppendLine("Network Failures: " + report["networkFailureCount"]);
            sb.AppendLine("Rate Limit Hits: " + report["rateLimitHitCount"]);
            sb.AppendLine("Network: " + report["networkStatus"] + " (" + report["networkType"] + ")");
            sb.AppendLine("Events: " + report["eventHistoryCount"]);
            sb.AppendLine("Cached Sessions: " + report["cachedSessionCount"]);
            sb.AppendLine("Device: " + report["deviceModel"]);
            sb.AppendLine("App Version: " + report["appVersion"]);
            sb.AppendLine("Server: " + report["configServer"]);
            return sb.ToString();
        }

        public static string SanitizeDisplayName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "WaterTag Player";
            string sanitized = Regex.Replace(name, @"[^\w\s.\-]", "");
            if (string.IsNullOrEmpty(sanitized)) return "WaterTag Player";
            if (sanitized.Length > 25) sanitized = sanitized.Substring(0, 25);
            return sanitized.Trim();
        }

        public static string GenerateChallengeNonceLocally()
        {
            byte[] randomBytes = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }
            string base64Nonce = Convert.ToBase64String(randomBytes);
            return base64Nonce.Replace('+', '-').Replace('/', '_');
        }

        public static string GenerateSessionId()
        {
            byte[] randomBytes = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }
            return Guid.NewGuid().ToString("N") + "_" + Convert.ToBase64String(randomBytes).Replace('+', '-').Replace('/', '_');
        }

        public string GetStateDescription()
        {
            switch (currentState)
            {
                case AuthState.Uninitialized: return "Not started";
                case AuthState.InitializingOculus: return "Initializing Oculus Platform SDK...";
                case AuthState.OculusReady: return "Oculus Platform SDK ready";
                case AuthState.GettingOculusCredentials: return "Getting Oculus user credentials...";
                case AuthState.OculusCredentialsReady: return "Oculus credentials obtained";
                case AuthState.AuthenticatingWithServer: return "Authenticating with game server...";
                case AuthState.ServerAuthenticated: return "Server authentication successful";
                case AuthState.GettingChallengeNonce: return "Getting attestation challenge...";
                case AuthState.ChallengeNonceReady: return "Challenge nonce received";
                case AuthState.RequestingAttestation: return "Requesting device attestation...";
                case AuthState.AttestationTokenReady: return "Attestation token received";
                case AuthState.VerifyingAttestation: return "Verifying attestation...";
                case AuthState.AttestationVerified: return "Attestation verified";
                case AuthState.ConnectingPhoton: return "Connecting to Photon...";
                case AuthState.PhotonConnected: return "Photon connected";
                case AuthState.LoggingIntoPlayFab: return "Logging into PlayFab...";
                case AuthState.PlayFabLoggedIn: return "PlayFab logged in";
                case AuthState.FullAuthComplete: return "Authentication complete!";
                case AuthState.Error: return "Error: " + lastError;
                case AuthState.Banned: return "DEVICE BANNED";
                case AuthState.Cancelled: return "Cancelled";
                case AuthState.WaitingForNetwork: return "Waiting for network...";
                case AuthState.NetworkRestored: return "Network restored";
                case AuthState.ReconnectingPhoton: return "Reconnecting to Photon...";
                case AuthState.ReconnectingPlayFab: return "Reconnecting to PlayFab...";
                case AuthState.RefreshingToken: return "Refreshing authentication token...";
                case AuthState.TokenRefreshed: return "Token refreshed";
                case AuthState.PerformingHealthCheck: return "Performing health check...";
                case AuthState.HealthCheckComplete: return "Health check passed";
                case AuthState.SyncingPlayerData: return "Syncing player data...";
                case AuthState.PlayerDataSynced: return "Player data synced";
                case AuthState.CheckingEntitlement: return "Checking Oculus entitlement...";
                case AuthState.EntitlementChecked: return "Entitlement confirmed";
                case AuthState.RequestingDeviceInfo: return "Collecting device info...";
                case AuthState.DeviceInfoCollected: return "Device info collected";
                case AuthState.ValidatingEnvironment: return "Validating environment...";
                case AuthState.EnvironmentValidated: return "Environment validated";
                case AuthState.PerformingVersionCheck: return "Checking version...";
                case AuthState.VersionCheckComplete: return "Version check passed";
                case AuthState.RateLimitWaiting: return "Rate limited, waiting...";
                case AuthState.RateLimitComplete: return "Rate limit lifted";
                default: return currentState.ToString();
            }
        }

        public string GetSubStateDescription()
        {
            switch (currentSubState)
            {
                case AuthSubState.None: return "";
                case AuthSubState.WaitingForOculusInit: return "Waiting for Oculus Platform initialization...";
                case AuthSubState.WaitingForEntitlement: return "Verifying Oculus entitlement...";
                case AuthSubState.WaitingForUserInfo: return "Getting Oculus user info...";
                case AuthSubState.WaitingForUserProof: return "Getting Oculus user proof...";
                case AuthSubState.WaitingForServerAuth: return "Contacting authentication server...";
                case AuthSubState.WaitingForChallengeNonce: return "Requesting challenge nonce...";
                case AuthSubState.WaitingForAttestationRequest: return "Requesting attestation from device...";
                case AuthSubState.WaitingForAttestationVerify: return "Verifying attestation token...";
                case AuthSubState.WaitingForPhotonConnect: return "Connecting to Photon servers...";
                case AuthSubState.WaitingForPlayFabLogin: return "Logging into PlayFab...";
                case AuthSubState.WaitingForTokenRefresh: return "Refreshing session token...";
                case AuthSubState.WaitingForHealthCheck: return "Checking server health...";
                case AuthSubState.WaitingForDataSync: return "Synchronizing player data...";
                case AuthSubState.WaitingForRetryBackoff: return "Waiting before retry...";
                case AuthSubState.WaitingForNetworkRecovery: return "Waiting for network recovery...";
                case AuthSubState.WaitingForRateLimit: return "Rate limited, cooling down...";
                default: return currentSubState.ToString();
            }
        }

        public static string GetErrorDescription(AuthErrorType errorType)
        {
            switch (errorType)
            {
                case AuthErrorType.None: return "No error";
                case AuthErrorType.OculusInitFailed: return "Oculus Platform SDK initialization failed";
                case AuthErrorType.OculusEntitlementFailed: return "Oculus entitlement check failed";
                case AuthErrorType.OculusUserNotFound: return "Could not get Oculus user information";
                case AuthErrorType.OculusProofFailed: return "Failed to get Oculus user proof (nonce)";
                case AuthErrorType.OculusTimeout: return "Oculus operation timed out";
                case AuthErrorType.ServerUnreachable: return "Authentication server is unreachable";
                case AuthErrorType.ServerAuthFailed: return "Server rejected authentication";
                case AuthErrorType.ServerTokenExpired: return "Authentication token has expired";
                case AuthErrorType.ChallengeNonceFailed: return "Failed to get attestation challenge nonce";
                case AuthErrorType.AttestationApiUnavailable: return "Device attestation API is unavailable";
                case AuthErrorType.AttestationTokenInvalid: return "Attestation token is invalid";
                case AuthErrorType.AttestationVerificationFailed: return "Server rejected attestation token";
                case AuthErrorType.AttestationTimeout: return "Attestation operation timed out";
                case AuthErrorType.PhotonConfigMissing: return "Photon configuration is missing";
                case AuthErrorType.PhotonConnectionFailed: return "Failed to connect to Photon";
                case AuthErrorType.PhotonTimeout: return "Photon connection timed out";
                case AuthErrorType.PlayFabConfigMissing: return "PlayFab configuration is missing";
                case AuthErrorType.PlayFabLoginFailed: return "PlayFab login failed";
                case AuthErrorType.PlayFabServerError: return "PlayFab server returned an error";
                case AuthErrorType.NetworkUnavailable: return "Network connection is unavailable";
                case AuthErrorType.NetworkTimeout: return "Network operation timed out";
                case AuthErrorType.DeviceBanned: return "This device has been banned";
                case AuthErrorType.InvalidConfiguration: return "Invalid authentication configuration";
                case AuthErrorType.RateLimited: return "Too many requests, rate limited";
                case AuthErrorType.VersionMismatch: return "Game version mismatch";
                case AuthErrorType.Unknown: return "An unknown error occurred";
                default: return "Unknown error";
            }
        }

        private void Log(string msg)
        {
            Debug.Log(msg);
            OnLogMessage?.Invoke(msg);
        }

        private void LogWarning(string msg)
        {
            Debug.LogWarning(msg);
            OnLogMessage?.Invoke("[WARN] " + msg);
        }

        private void LogError(string msg)
        {
            Debug.LogError(msg);
            OnLogMessage?.Invoke("[ERROR] " + msg);
        }

        public void SetEditorOverrideCredentials(string userId, string nonce)
        {
            config.editorOverrideUserId = userId;
            config.editorOverrideNonce = nonce;
            Log($"[MetaAuth] Editor override credentials set: UserID={userId}");
        }

        public void SetDisplayName(string displayName)
        {
            config.displayName = SanitizeDisplayName(displayName);
            Log($"[MetaAuth] Display name set to: {config.displayName}");
        }

        public void SetServerUrl(string url)
        {
            config.serverUrl = url;
            if (_serverAPI != null)
            {
                _serverAPI.SetServerUrl(url);
            }
            Log($"[MetaAuth] Server URL set to: {url}");
        }

        public void SetPhotonAppIds(string realtimeId, string voiceId)
        {
            config.photonRealtimeAppId = realtimeId;
            config.photonVoiceAppId = voiceId;
            Log($"[MetaAuth] Photon App IDs updated");
        }

        public void SetPlayFabTitleId(string titleId)
        {
            config.playfabTitleId = titleId;
            Log($"[MetaAuth] PlayFab Title ID set to: {titleId}");
        }

        public void ToggleFeature(string featureName, bool enabled)
        {
            switch (featureName.ToLowerInvariant())
            {
                case "attestation":
                    config.enableAttestation = enabled;
                    break;
                case "photon":
                    config.enablePhoton = enabled;
                    break;
                case "playfab":
                    config.enablePlayFab = enabled;
                    break;
                case "voice":
                    config.photonEnableVoice = enabled;
                    break;
                case "analytics":
                    config.enableAnalytics = enabled;
                    break;
                case "healthcheck":
                    config.enableServerHealthCheck = enabled;
                    break;
                case "networkmonitor":
                    config.enableNetworkMonitoring = enabled;
                    break;
                case "autorefresh":
                    config.enableTokenAutoRefresh = enabled;
                    break;
                case "datasync":
                    config.playfabEnableDataSync = enabled;
                    break;
                case "ratelimiting":
                    config.enableRateLimiting = enabled;
                    break;
                case "bancheck":
                    config.enableDeviceBanCheck = enabled;
                    break;
                case "versioncheck":
                    config.enableVersionCheck = enabled;
                    break;
                case "sessionpersistence":
                    config.enableSessionPersistence = enabled;
                    break;
                default:
                    LogWarning($"[MetaAuth] Unknown feature: {featureName}");
                    return;
            }
            Log($"[MetaAuth] Feature '{featureName}' set to {enabled}");
        }

        public string GetConfigurationSummary()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== MetaAuth Configuration ===");
            sb.AppendLine("Server URL: " + config.serverUrl);
            sb.AppendLine("Server Timeout: " + config.serverRequestTimeout + "s");
            sb.AppendLine("Max Retries: " + config.maxAuthRetries);
            sb.AppendLine("Retry Backoff: " + config.retryBackoffBaseDelay + "s - " + config.retryBackoffMaxDelay + "s");
            sb.AppendLine("Display Name: " + config.displayName);
            sb.AppendLine("Attestation: " + (config.enableAttestation ? "ON" : "OFF"));
            sb.AppendLine("Photon: " + (config.enablePhoton ? "ON" : "OFF") + " (Voice: " + (config.photonEnableVoice ? "ON" : "OFF") + ")");
            sb.AppendLine("PlayFab: " + (config.enablePlayFab ? "ON" : "OFF"));
            sb.AppendLine("Token Caching: " + (config.cacheTokens ? "ON" : "OFF"));
            sb.AppendLine("Auto Refresh: " + (config.enableTokenAutoRefresh ? "ON" : "OFF"));
            sb.AppendLine("Network Monitor: " + (config.enableNetworkMonitoring ? "ON" : "OFF"));
            sb.AppendLine("Rate Limiting: " + (config.enableRateLimiting ? "ON (" + config.maxRequestsPerMinute + "/min)" : "OFF"));
            sb.AppendLine("Analytics: " + (config.enableAnalytics ? "ON" : "OFF"));
            sb.AppendLine("Health Check: " + (config.enableServerHealthCheck ? "ON (every " + config.healthCheckInterval + "s)" : "OFF"));
            sb.AppendLine("Data Sync: " + (config.playfabEnableDataSync ? "ON (every " + config.playfabDataSyncInterval + "s)" : "OFF"));
            sb.AppendLine("Device Info: " + (config.collectDeviceInfo ? "ON" : "OFF"));
            sb.AppendLine("Ban Check: " + (config.enableDeviceBanCheck ? "ON" : "OFF"));
            sb.AppendLine("Version Check: " + (config.enableVersionCheck ? "ON (min " + config.minimumGameVersion + ")" : "OFF"));
            sb.AppendLine("Session Persistence: " + (config.enableSessionPersistence ? "ON" : "OFF"));
            sb.AppendLine("Cross-Session Caching: " + (config.enableCrossSessionCaching ? "ON (max " + config.maxCachedSessions + ")" : "OFF"));
            return sb.ToString();
        }

        public NetworkQualityMetrics GetNetworkMetrics()
        {
            return _networkMetrics;
        }

        public void ResetNetworkMetrics()
        {
            _networkMetrics = new NetworkQualityMetrics();
            _networkFailureCount = 0;
            Log("[MetaAuth] Network metrics reset");
        }

        public void RecordSuccessfulRequest()
        {
            _networkMetrics.successfulRequests++;
            _networkMetrics.totalRequests++;
            _networkMetrics.consecutiveFailures = 0;
            _networkMetrics.successRate = (float)_networkMetrics.successfulRequests / Mathf.Max(1, _networkMetrics.totalRequests) * 100f;
        }

        public void RecordFailedRequest()
        {
            _networkMetrics.failedRequests++;
            _networkMetrics.totalRequests++;
            _networkMetrics.consecutiveFailures++;
            _networkMetrics.successRate = (float)_networkMetrics.successfulRequests / Mathf.Max(1, _networkMetrics.totalRequests) * 100f;
        }

        public void RecordPingMeasurement(float pingMs)
        {
            _networkMetrics.lastPingMs = pingMs;
            if (_networkMetrics.minPingMs <= 0 || pingMs < _networkMetrics.minPingMs)
            {
                _networkMetrics.minPingMs = pingMs;
            }
            if (pingMs > _networkMetrics.maxPingMs)
            {
                _networkMetrics.maxPingMs = pingMs;
            }
            if (_networkMetrics.averagePingMs <= 0)
            {
                _networkMetrics.averagePingMs = pingMs;
            }
            else
            {
                _networkMetrics.averagePingMs = (_networkMetrics.averagePingMs * 0.9f) + (pingMs * 0.1f);
            }
            float jitter = Mathf.Abs(pingMs - _networkMetrics.lastPingMs);
            if (_networkMetrics.jitterMs <= 0)
            {
                _networkMetrics.jitterMs = jitter;
            }
            else
            {
                _networkMetrics.jitterMs = (_networkMetrics.jitterMs * 0.9f) + (jitter * 0.1f);
            }
        }

        public bool HasRequiredConfiguration()
        {
            if (string.IsNullOrEmpty(config.serverUrl) || config.serverUrl == "https://your-project.vercel.app")
            {
                LogWarning("[MetaAuth] Server URL is not configured");
                return false;
            }
            if (config.enablePhoton && string.IsNullOrEmpty(config.photonRealtimeAppId))
            {
                LogWarning("[MetaAuth] Photon is enabled but Realtime App ID is not set");
            }
            if (config.enablePlayFab && string.IsNullOrEmpty(config.playfabTitleId))
            {
                LogWarning("[MetaAuth] PlayFab is enabled but Title ID is not set");
            }
            return true;
        }

        public List<string> GetConfigurationIssues()
        {
            List<string> issues = new List<string>();
            if (string.IsNullOrEmpty(config.serverUrl) || config.serverUrl == "https://your-project.vercel.app")
            {
                issues.Add("Server URL is not configured (default value still in use)");
            }
            if (config.serverRequestTimeout < 5)
            {
                issues.Add("Server request timeout is too low (" + config.serverRequestTimeout + "s), minimum recommended is 10s");
            }
            if (config.serverRequestTimeout > 60)
            {
                issues.Add("Server request timeout is very high (" + config.serverRequestTimeout + "s), consider lowering");
            }
            if (config.maxAuthRetries < 1)
            {
                issues.Add("Max auth retries is set to 0, authentication may fail on transient errors");
            }
            if (config.enablePhoton && string.IsNullOrEmpty(config.photonRealtimeAppId) && string.IsNullOrEmpty(config.serverUrl))
            {
                issues.Add("Photon is enabled but no Realtime App ID is configured and server URL is not set");
            }
            if (config.enablePlayFab && string.IsNullOrEmpty(config.playfabTitleId) && string.IsNullOrEmpty(config.serverUrl))
            {
                issues.Add("PlayFab is enabled but no Title ID is configured and server URL is not set");
            }
            if (config.enableAttestation && Application.isEditor && !config.editorSimulateAttestation)
            {
                issues.Add("Attestation is enabled but editor simulation is disabled - attestation will not work in editor");
            }
            if (config.enableNetworkMonitoring && config.networkCheckInterval < 1f)
            {
                issues.Add("Network check interval is very frequent (" + config.networkCheckInterval + "s), may cause performance issues");
            }
            if (config.tokenRefreshCheckInterval < 5f)
            {
                issues.Add("Token refresh check interval is very frequent (" + config.tokenRefreshCheckInterval + "s)");
            }
            if (config.enableRateLimiting && config.maxRequestsPerMinute > 120)
            {
                issues.Add("Rate limit is very high (" + config.maxRequestsPerMinute + "/min), consider lowering");
            }
            if (string.IsNullOrEmpty(config.displayName) || config.displayName == "WaterTag Player")
            {
                issues.Add("Display name is set to default value, consider setting a custom name");
            }
            return issues;
        }

        public void ValidateAndFixConfiguration()
        {
            if (config.serverRequestTimeout < 5)
            {
                config.serverRequestTimeout = 10;
            }
            if (config.maxAuthRetries < 1)
            {
                config.maxAuthRetries = 3;
            }
            if (config.retryBackoffBaseDelay < 0.5f)
            {
                config.retryBackoffBaseDelay = 1f;
            }
            if (config.retryBackoffMaxDelay < config.retryBackoffBaseDelay)
            {
                config.retryBackoffMaxDelay = config.retryBackoffBaseDelay * 10f;
            }
            if (config.photonConnectionTimeout < 5)
            {
                config.photonConnectionTimeout = 20;
            }
            if (config.networkCheckInterval < 1f)
            {
                config.networkCheckInterval = 5f;
            }
            if (config.tokenRefreshCheckInterval < 5f)
            {
                config.tokenRefreshCheckInterval = 30f;
            }
            if (config.healthCheckInterval < 10f)
            {
                config.healthCheckInterval = 60f;
            }
            if (config.playfabDataSyncInterval < 30f)
            {
                config.playfabDataSyncInterval = 120f;
            }
            if (config.maxRequestsPerMinute < 1)
            {
                config.maxRequestsPerMinute = 60;
            }
            if (config.maxEventHistoryEntries < 10)
            {
                config.maxEventHistoryEntries = 100;
            }
            if (config.maxCachedSessions < 1)
            {
                config.maxCachedSessions = 5;
            }
            if (config.tokenExpiryBufferSeconds < 30)
            {
                config.tokenExpiryBufferSeconds = 300;
            }
            Log("[MetaAuth] Configuration validated and fixed");
        }

        public Dictionary<string, object> GetAuthStateSnapshot()
        {
            Dictionary<string, object> snapshot = new Dictionary<string, object>();
            snapshot["state"] = currentState.ToString();
            snapshot["subState"] = currentSubState.ToString();
            snapshot["isAuthenticated"] = IsAuthenticated;
            snapshot["isProcessing"] = _isProcessing;
            snapshot["isBanned"] = IsBanned;
            snapshot["userId"] = _oculusUserId;
            snapshot["hasToken"] = !string.IsNullOrEmpty(_serverAuthToken);
            snapshot["hasAttestation"] = !string.IsNullOrEmpty(_attestationToken);
            snapshot["networkStable"] = _networkMetrics.isNetworkStable;
            snapshot["lastError"] = lastError;
            snapshot["lastErrorType"] = lastErrorType.ToString();
            snapshot["authCount"] = _authenticationCount;
            snapshot["retryCount"] = _retryCount;
            snapshot["sessionId"] = _sessionId;
            snapshot["timestamp"] = Time.time;
            snapshot["authDuration"] = GetTotalAuthenticationTime();
            return snapshot;
        }

        public string GetAuthStateSnapshotString()
        {
            Dictionary<string, object> snap = GetAuthStateSnapshot();
            StringBuilder sb = new StringBuilder();
            sb.Append("[").Append(snap["state"]);
            if (currentSubState != AuthSubState.None)
            {
                sb.Append(" / ").Append(snap["subState"]);
            }
            sb.Append("] ");
            sb.Append("User: ").Append(snap["userId"] ?? "none");
            sb.Append(" Token: ").Append((bool)snap["hasToken"] ? "yes" : "no");
            sb.Append(" Attestation: ").Append((bool)snap["hasAttestation"] ? "yes" : "no");
            sb.Append(" Network: ").Append((bool)snap["networkStable"] ? "ok" : "down");
            if (!string.IsNullOrEmpty((string)snap["lastError"]))
            {
                sb.Append(" Error: ").Append(snap["lastError"]);
            }
            return sb.ToString();
        }

        public bool WaitForAuthentication(float timeoutSeconds)
        {
            float startTime = Time.time;
            while (Time.time - startTime < timeoutSeconds)
            {
                if (IsAuthenticated) return true;
                if (currentState == AuthState.Error) return false;
                if (currentState == AuthState.Banned) return false;
            }
            return IsAuthenticated;
        }

        public IEnumerator WaitForAuthenticationCoroutine(float timeoutSeconds, Action<bool> onResult)
        {
            float startTime = Time.time;
            while (Time.time - startTime < timeoutSeconds)
            {
                if (IsAuthenticated)
                {
                    onResult?.Invoke(true);
                    yield break;
                }
                if (currentState == AuthState.Error || currentState == AuthState.Banned)
                {
                    onResult?.Invoke(false);
                    yield break;
                }
                yield return null;
            }
            onResult?.Invoke(IsAuthenticated);
        }

        public void SimulateServerResponse(string endpoint, string jsonResponse)
        {
#if UNITY_EDITOR
            Log("[MetaAuth] Simulating server response for " + endpoint + ": " + jsonResponse);
#endif
        }

        public void InjectTestToken(string token)
        {
#if UNITY_EDITOR
            _serverAuthToken = token;
            if (_serverAPI != null)
            {
                _serverAPI.SetAuthToken(token);
            }
            Log("[MetaAuth] Test token injected");
#endif
        }

        public void ForceState(AuthState forcedState)
        {
#if UNITY_EDITOR
            SetState(forcedState);
            if (forcedState == AuthState.FullAuthComplete)
            {
                _isProcessing = false;
                OnAuthenticationComplete?.Invoke();
            }
            Log("[MetaAuth] State forced to: " + forcedState);
#endif
        }

        public void ClearEventHistory()
        {
            _eventHistory.Clear();
            Log("[MetaAuth] Event history cleared");
        }

        public void ClearCachedSessions()
        {
            _cachedSessions.Clear();
            PlayerPrefs.DeleteKey("MetaAuth_CachedSessions");
            Log("[MetaAuth] Cached sessions cleared");
        }

        public void ClearLocalBanCache()
        {
            _localBanCache.Clear();
            PlayerPrefs.DeleteKey("MetaAuth_LocalBanCache");
            Log("[MetaAuth] Local ban cache cleared");
        }

        public void ClearAllCachedData()
        {
            ClearEventHistory();
            ClearCachedSessions();
            ClearLocalBanCache();
            ResetNetworkMetrics();
            _processedNonces.Clear();
            _rateLimitTracker.Clear();
            Log("[MetaAuth] All cached data cleared");
        }

        public int GetEventHistoryCount()
        {
            return _eventHistory.Count;
        }

        public int GetCachedSessionCount()
        {
            return _cachedSessions.Count;
        }

        public int GetLocalBanCount()
        {
            return _localBanCache.Count;
        }

        public float GetTimeSinceLastEvent()
        {
            if (_eventHistory.Count == 0) return -1f;
            return Time.time - _eventHistory[_eventHistory.Count - 1].timestamp;
        }

        public float GetTimeSinceAuthentication()
        {
            if (!IsAuthenticated) return -1f;
            if (_eventHistory.Count == 0) return -1f;
            for (int i = _eventHistory.Count - 1; i >= 0; i--)
            {
                if (_eventHistory[i].state == AuthState.FullAuthComplete)
                {
                    return Time.time - _eventHistory[i].timestamp;
                }
            }
            return -1f;
        }

        public float GetAuthProgressPercentage()
        {
            if (IsAuthenticated) return 100f;
            if (currentState == AuthState.Error || currentState == AuthState.Banned) return 0f;
            switch (currentState)
            {
                case AuthState.Uninitialized: return 0f;
                case AuthState.InitializingOculus: return 2f;
                case AuthState.OculusReady: return 5f;
                case AuthState.GettingOculusCredentials: return 10f;
                case AuthState.OculusCredentialsReady: return 15f;
                case AuthState.CheckingEntitlement: return 18f;
                case AuthState.EntitlementChecked: return 20f;
                case AuthState.AuthenticatingWithServer: return 25f;
                case AuthState.ServerAuthenticated: return 35f;
                case AuthState.GettingChallengeNonce: return 40f;
                case AuthState.ChallengeNonceReady: return 43f;
                case AuthState.RequestingAttestation: return 48f;
                case AuthState.AttestationTokenReady: return 52f;
                case AuthState.VerifyingAttestation: return 55f;
                case AuthState.AttestationVerified: return 60f;
                case AuthState.ConnectingPhoton: return 70f;
                case AuthState.PhotonConnected: return 80f;
                case AuthState.LoggingIntoPlayFab: return 85f;
                case AuthState.PlayFabLoggedIn: return 90f;
                case AuthState.RefreshingToken: return 50f;
                case AuthState.TokenRefreshed: return 95f;
                case AuthState.PerformingHealthCheck: return 50f;
                case AuthState.SyncingPlayerData: return 75f;
                case AuthState.WaitingForNetwork: return 30f;
                case AuthState.ReconnectingPhoton: return 65f;
                case AuthState.ReconnectingPlayFab: return 82f;
                case AuthState.RateLimitWaiting: return 20f;
                default: return 50f;
            }
        }

        public string GetAuthProgressDescription()
        {
            return GetAuthProgressPercentage() + "% - " + GetStateDescription();
        }

        public bool IsAuthenticationStuck(float thresholdSeconds = 120f)
        {
            if (!_isProcessing) return false;
            if (_eventHistory.Count < 2) return false;
            float lastChangeTime = _eventHistory[_eventHistory.Count - 1].timestamp;
            return (Time.time - lastChangeTime) > thresholdSeconds;
        }

        public void RecoverFromStuckState()
        {
            if (!IsAuthenticationStuck())
            {
                return;
            }
            LogWarning("[MetaAuth] Attempting to recover from stuck state: " + currentState);
            if (currentState == AuthState.WaitingForNetwork)
            {
                if (Application.internetReachability != NetworkReachability.NotReachable)
                {
                    SetState(AuthState.NetworkRestored);
                    if (!IsAuthenticated)
                    {
                        StartAuthentication();
                    }
                }
            }
            else if (currentState == AuthState.PerformingHealthCheck)
            {
                SetState(AuthState.HealthCheckComplete);
            }
            else if (currentState == AuthState.SyncingPlayerData)
            {
                SetState(AuthState.PlayerDataSynced);
            }
            else if (currentState == AuthState.RefreshingToken)
            {
                SetState(AuthState.TokenRefreshed);
            }
            else if (_isProcessing && !IsAuthenticated)
            {
                ResetAuthentication();
                StartAuthentication();
            }
        }

        public string ExportEventHistoryAsJson()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("[");
            for (int i = 0; i < _eventHistory.Count; i++)
            {
                AuthenticationEvent evt = _eventHistory[i];
                sb.Append("  {");
                sb.Append("\"timestamp\":").Append(evt.timestamp.ToString("F1")).Append(",");
                sb.Append("\"state\":\"").Append(evt.state).Append("\",");
                sb.Append("\"description\":\"").Append(EscapeJsonString(evt.description)).Append("\",");
                sb.Append("\"isError\":").Append(evt.isError ? "true" : "false").Append(",");
                sb.Append("\"errorCode\":\"").Append(evt.errorCode ?? "").Append("\",");
                sb.Append("\"duration\":").Append(evt.duration.ToString("F2"));
                sb.Append("}");
                if (i < _eventHistory.Count - 1) sb.Append(",");
                sb.AppendLine();
            }
            sb.AppendLine("]");
            return sb.ToString();
        }

        private string EscapeJsonString(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");
        }

        public Dictionary<string, int> GetStateTransitionCounts()
        {
            Dictionary<string, int> counts = new Dictionary<string, int>();
            for (int i = 0; i < _eventHistory.Count; i++)
            {
                string stateName = _eventHistory[i].state.ToString();
                if (counts.ContainsKey(stateName))
                {
                    counts[stateName]++;
                }
                else
                {
                    counts[stateName] = 1;
                }
            }
            return counts;
        }

        public float GetAverageTimeInState(AuthState state)
        {
            List<float> durations = new List<float>();
            for (int i = 0; i < _eventHistory.Count - 1; i++)
            {
                if (_eventHistory[i].state == state)
                {
                    float duration = _eventHistory[i + 1].timestamp - _eventHistory[i].timestamp;
                    durations.Add(duration);
                }
            }
            if (durations.Count == 0) return 0f;
            float total = 0f;
            foreach (float d in durations) total += d;
            return total / durations.Count;
        }

        public string GetStateTimingReport()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== Auth State Timing Report ===");
            string[] stateNames = System.Enum.GetNames(typeof(AuthState));
            foreach (string name in stateNames)
            {
                AuthState state = (AuthState)System.Enum.Parse(typeof(AuthState), name);
                float avgTime = GetAverageTimeInState(state);
                if (avgTime > 0)
                {
                    sb.AppendLine(name + ": " + avgTime.ToString("F2") + "s avg");
                }
            }
            return sb.ToString();
        }

        public void RegisterPhotonCallbacks()
        {
#if PUN_2_OR_NEWER
            Log("[MetaAuth] Registering Photon callbacks");
#endif
        }

        public void UnregisterPhotonCallbacks()
        {
#if PUN_2_OR_NEWER
            Log("[MetaAuth] Unregistering Photon callbacks");
#endif
        }

        public void AttachToGorillaNetworking()
        {
            Log("[MetaAuth] Attaching to GorillaNetworking system");
            RegisterPhotonCallbacks();
        }

        public void DetachFromGorillaNetworking()
        {
            Log("[MetaAuth] Detaching from GorillaNetworking system");
            UnregisterPhotonCallbacks();
        }

        public void SynchronizeWithPlayFabAuthenticator()
        {
            Log("[MetaAuth] Synchronizing with PlayFabAuthenticator");
            GorillaNetworking.PlayFabAuthenticator pfa = GorillaNetworking.PlayFabAuthenticator.instance;
            if (pfa != null)
            {
                if (!string.IsNullOrEmpty(_oculusUserId))
                {
                    pfa.userID = _oculusUserId;
                }
                Log("[MetaAuth] Synced user ID with PlayFabAuthenticator: " + _oculusUserId);
            }
        }

        public void SynchronizeWithPhotonNetworkController()
        {
            Log("[MetaAuth] Synchronizing with PhotonNetworkController");
            GorillaNetworking.PhotonNetworkController pnc = GorillaNetworking.PhotonNetworkController.Instance;
            if (pnc != null)
            {
                if (_serverAPI != null && !string.IsNullOrEmpty(_serverAuthToken))
                {
                    Log("[MetaAuth] PhotonNetworkController ready");
                }
            }
        }

        public void FullGorillaTagIntegration()
        {
            Log("[MetaAuth] Performing full GorillaTag integration");
            SynchronizeWithPlayFabAuthenticator();
            SynchronizeWithPhotonNetworkController();
            RegisterPhotonCallbacks();
        }

        public void BroadcastServerMessage(string message)
        {
            OnServerMessage?.Invoke(message);
            Log("[MetaAuth] Server message: " + message);
        }

        public void UpdateServerConfig(Dictionary<string, object> configData)
        {
            if (configData == null) return;
            OnServerConfigUpdated?.Invoke(configData);
            if (configData.ContainsKey("serverUrl"))
            {
                SetServerUrl(configData["serverUrl"].ToString());
            }
            if (configData.ContainsKey("displayName"))
            {
                SetDisplayName(configData["displayName"].ToString());
            }
            if (configData.ContainsKey("photonRealtimeAppId"))
            {
                config.photonRealtimeAppId = configData["photonRealtimeAppId"].ToString();
            }
            if (configData.ContainsKey("photonVoiceAppId"))
            {
                config.photonVoiceAppId = configData["photonVoiceAppId"].ToString();
            }
            if (configData.ContainsKey("playfabTitleId"))
            {
                config.playfabTitleId = configData["playfabTitleId"].ToString();
            }
            if (configData.ContainsKey("gameVersion"))
            {
                config.photonGameVersion = configData["gameVersion"].ToString();
            }
            if (configData.ContainsKey("enableAttestation"))
            {
                config.enableAttestation = Convert.ToBoolean(configData["enableAttestation"]);
            }
            if (configData.ContainsKey("enablePhoton"))
            {
                config.enablePhoton = Convert.ToBoolean(configData["enablePhoton"]);
            }
            if (configData.ContainsKey("enablePlayFab"))
            {
                config.enablePlayFab = Convert.ToBoolean(configData["enablePlayFab"]);
            }
            Log("[MetaAuth] Server config updated");
        }

        public byte[] GenerateRandomBytes(int count)
        {
            byte[] bytes = new byte[count];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        public string GenerateRandomString(int length)
        {
            byte[] bytes = GenerateRandomBytes(length);
            return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').Substring(0, Mathf.Min(length, 64));
        }

        public string HashString(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = sha256.ComputeHash(inputBytes);
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }

        public string ComputeHmacSha256(string key, string data)
        {
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(data)) return "";
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            using (HMACSHA256 hmac = new HMACSHA256(keyBytes))
            {
                byte[] hashBytes = hmac.ComputeHash(dataBytes);
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }

        public string Base64Encode(string data)
        {
            if (string.IsNullOrEmpty(data)) return "";
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
        }

        public string Base64Decode(string data)
        {
            if (string.IsNullOrEmpty(data)) return "";
            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(data));
            }
            catch
            {
                return "";
            }
        }

        public string UrlSafeBase64(string data)
        {
            return data.Replace('+', '-').Replace('/', '_').Replace("=", "");
        }

        public Dictionary<string, string> ParseQueryString(string query)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(query)) return result;
            string[] pairs = query.Split('&');
            foreach (string pair in pairs)
            {
                string[] kv = pair.Split('=');
                if (kv.Length >= 2)
                {
                    result[kv[0]] = WWW.UnEscapeURL(kv[1]);
                }
            }
            return result;
        }

        public long GetCurrentUnixTimestamp()
        {
            return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
        }

        public DateTime UnixTimestampToDateTime(long timestamp)
        {
            return new DateTime(1970, 1, 1).AddSeconds(timestamp);
        }

        public string FormatTimestamp(long timestamp)
        {
            return UnixTimestampToDateTime(timestamp).ToString("yyyy-MM-dd HH:mm:ss UTC");
        }

        public bool IsTokenExpired(string token)
        {
            if (string.IsNullOrEmpty(token)) return true;
            try
            {
                string[] parts = token.Split('.');
                if (parts.Length < 2) return true;
                string payload = parts[1];
                int padding = 4 - payload.Length % 4;
                if (padding < 4) payload += new string('=', padding);
                byte[] payloadBytes = Convert.FromBase64String(payload);
                string json = Encoding.UTF8.GetString(payloadBytes);
                Dictionary<string, object> data = JsonUtility.FromJson<Dictionary<string, object>>(json);
                if (data != null && data.ContainsKey("exp"))
                {
                    long exp = Convert.ToInt64(data["exp"]);
                    return GetCurrentUnixTimestamp() >= exp - config.tokenExpiryBufferSeconds;
                }
            }
            catch
            {
            }
            return false;
        }

        public void SetCustomAuthParameter(string key, string value)
        {
            Log("[MetaAuth] Custom auth parameter set: " + key + " = " + value);
        }

        public object GetCustomAuthParameter(string key)
        {
            return null;
        }

        public string GetLocalEndpointAddress()
        {
            return config.serverUrl;
        }

        public void SetLocalEndpointAddress(string address)
        {
            SetServerUrl(address);
        }

        public bool IsServerReachable()
        {
            return Application.internetReachability != NetworkReachability.NotReachable;
        }

        public string GetNetworkReachabilityDescription()
        {
            switch (Application.internetReachability)
            {
                case NetworkReachability.NotReachable: return "No network connection";
                case NetworkReachability.ReachableViaCarrierDataNetwork: return "Cellular data network";
                case NetworkReachability.ReachableViaLocalAreaNetwork: return "WiFi or LAN";
                default: return "Unknown";
            }
        }

        public void SetPerformanceTrackingEnabled(bool enabled)
        {
            config.enablePerformanceTracking = enabled;
        }

        public void SetDetailedLoggingEnabled(bool enabled)
        {
            config.enableDetailedLogging = enabled;
        }

        public void SetVerboseLogging(bool verbose)
        {
            config.enableDetailedLogging = verbose;
        }

        public string GetVersion()
        {
            return "2.0.0";
        }

        public string GetApiVersion()
        {
            return "v1";
        }

        public string GetSystemInfo()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("MetaAuth System v" + GetVersion());
            sb.AppendLine("API Version: " + GetApiVersion());
            sb.AppendLine("Unity Version: " + Application.unityVersion);
            sb.AppendLine("Platform: " + Application.platform);
            sb.AppendLine("Engine: " + Application.unityVersion);
            sb.AppendLine("Data Path: " + Application.dataPath);
            sb.AppendLine("Persistent Data Path: " + Application.persistentDataPath);
            sb.AppendLine("Temporary Cache Path: " + Application.temporaryCachePath);
            sb.AppendLine("Company Name: " + Application.companyName);
            sb.AppendLine("Product Name: " + Application.productName);
            sb.AppendLine("Build GUID: " + Application.buildGUID);
            sb.AppendLine("Is Batch Mode: " + Application.isBatchMode);
            sb.AppendLine("Is Console Platform: " + Application.isConsolePlatform);
            sb.AppendLine("System Language: " + Application.systemLanguage);
            sb.AppendLine("Internet Reachability: " + Application.internetReachability);
            sb.AppendLine("Is Mobile: " + Application.isMobilePlatform);
            sb.AppendLine("Is Editor: " + Application.isEditor);
            sb.AppendLine("Low Memory: " + (SystemInfo.systemMemorySize < 512));
            sb.AppendLine("Device UID: " + SystemInfo.deviceUniqueIdentifier);
            sb.AppendLine("Device Name: " + SystemInfo.deviceName);
            sb.AppendLine("Device Type: " + SystemInfo.deviceType);
            sb.AppendLine("Graphics Device ID: " + SystemInfo.graphicsDeviceID);
            sb.AppendLine("Graphics Device Vendor ID: " + SystemInfo.graphicsDeviceVendorID);
            sb.AppendLine("Graphics Pixel Fillrate: " + SystemInfo.graphicsPixelFillrate);
            sb.AppendLine("Graphics Shader Level: " + SystemInfo.graphicsShaderLevel);
            sb.AppendLine("Graphics Multi-threaded: " + SystemInfo.graphicsMultiThreaded);
            sb.AppendLine("Graphics UV Starts at top: " + SystemInfo.graphicsUVStartsAtTop);
            sb.AppendLine("Has Hidden Surface Removal: " + SystemInfo.graphicsShaderLevel);
            sb.AppendLine("NPOT Support: " + SystemInfo.npotSupport);
            sb.AppendLine("Max Texture Size: " + SystemInfo.maxTextureSize);
            sb.AppendLine("Max Cubemap Size: " + SystemInfo.maxCubemapSize);
            sb.AppendLine("Supported Render Target Count: " + SystemInfo.supportedRenderTargetCount);
            sb.AppendLine("Supports 3D Textures: " + SystemInfo.supports3DTextures);
            sb.AppendLine("Supports 2D Array Textures: " + SystemInfo.supports2DArrayTextures);
            sb.AppendLine("Supports Compute Shaders: " + SystemInfo.supportsComputeShaders);
            sb.AppendLine("Supports Instancing: " + SystemInfo.supportsInstancing);
            sb.AppendLine("Supports Motion Vectors: " + SystemInfo.supportsMotionVectors);
            sb.AppendLine("Supports Shadows: " + SystemInfo.supportsShadows);
            sb.AppendLine("Supports Sparse Textures: " + SystemInfo.supportsSparseTextures);
            sb.AppendLine("Supports Vibration: " + SystemInfo.supportsVibration);
            sb.AppendLine("Supports Audio: " + SystemInfo.supportsAudio);
            sb.AppendLine("Supports Location Service: " + SystemInfo.supportsLocationService);
            sb.AppendLine("Supports Accelerometer: " + SystemInfo.supportsAccelerometer);
            sb.AppendLine("Supports Gyroscope: " + SystemInfo.supportsGyroscope);
            return sb.ToString();
        }

        public void PrintSystemInfo()
        {
            Log("[MetaAuth] System Info:\n" + GetSystemInfo());
        }

        public void EnableAllFeatures()
        {
            config.enableAttestation = true;
            config.enablePhoton = true;
            config.enablePlayFab = true;
            config.photonEnableVoice = true;
            config.enableServerHealthCheck = true;
            config.enableNetworkMonitoring = true;
            config.enableTokenAutoRefresh = true;
            config.enableAnalytics = true;
            config.enableRateLimiting = true;
            config.enableDeviceBanCheck = true;
            config.enableVersionCheck = true;
            config.enableSessionPersistence = true;
            config.enableCrossSessionCaching = true;
            config.enableNonceValidation = true;
            config.enableReplayAttackProtection = true;
            config.enableTimestampValidation = true;
            config.enableAsyncOperations = true;
            config.collectDeviceInfo = true;
            config.collectAppInfo = true;
            config.collectNetworkInfo = true;
            config.sendDeviceInfoToServer = true;
            config.playfabEnableDataSync = true;
            config.playfabEnableStatistics = true;
            config.cacheTokens = true;
            config.enableEventHistory = true;
            config.enablePerformanceTracking = true;
            Log("[MetaAuth] All features enabled");
        }

        public void DisableAllFeatures()
        {
            config.enableAttestation = false;
            config.enablePhoton = false;
            config.enablePlayFab = false;
            config.photonEnableVoice = false;
            config.enableServerHealthCheck = false;
            config.enableNetworkMonitoring = false;
            config.enableTokenAutoRefresh = false;
            config.enableAnalytics = false;
            config.enableRateLimiting = false;
            config.enableDeviceBanCheck = false;
            config.enableVersionCheck = false;
            config.enableSessionPersistence = false;
            config.enableCrossSessionCaching = false;
            config.enableNonceValidation = false;
            config.enableReplayAttackProtection = false;
            config.enableTimestampValidation = false;
            config.enableAsyncOperations = false;
            config.collectDeviceInfo = false;
            config.collectAppInfo = false;
            config.collectNetworkInfo = false;
            config.sendDeviceInfoToServer = false;
            config.playfabEnableDataSync = false;
            config.playfabEnableStatistics = false;
            config.cacheTokens = false;
            config.enableEventHistory = false;
            config.enablePerformanceTracking = false;
            Log("[MetaAuth] All features disabled");
        }

        public void SetRecommendedConfiguration()
        {
            config.serverUrl = "https://your-project.vercel.app";
            config.serverRequestTimeout = 30;
            config.maxServerRetries = 3;
            config.retryBackoffBaseDelay = 1f;
            config.retryBackoffMaxDelay = 30f;
            config.enableServerHealthCheck = true;
            config.healthCheckInterval = 60f;
            config.photonConnectionTimeout = 20;
            config.photonAutoJoinLobby = true;
            config.photonCreateRoomIfNotExists = true;
            config.photonMaxPlayersPerRoom = 10;
            config.photonEnableVoice = true;
            config.playfabAutoCreateAccount = true;
            config.playfabEnableDataSync = true;
            config.playfabEnableStatistics = true;
            config.playfabDataSyncInterval = 120f;
            config.enableAttestation = true;
            config.enablePhoton = true;
            config.enablePlayFab = true;
            config.cacheTokens = true;
            config.maxAuthRetries = 3;
            config.authTimeoutMultiplier = 1f;
            config.requireEntitlementCheck = true;
            config.enableDeviceBanCheck = true;
            config.enableVersionCheck = true;
            config.minimumGameVersion = "1.0.0";
            config.enableEnvironmentValidation = true;
            config.tokenExpiryBufferSeconds = 300;
            config.enableTokenAutoRefresh = true;
            config.tokenRefreshCheckInterval = 30f;
            config.enableNetworkMonitoring = true;
            config.networkCheckInterval = 5f;
            config.networkFailureThreshold = 3;
            config.networkRecoveryMaxRetries = 5;
            config.networkRecoveryBackoffBase = 2f;
            config.maxNetworkRecoveryTimeSeconds = 120;
            config.enableRateLimiting = true;
            config.maxRequestsPerMinute = 60;
            config.rateLimitMaxRetries = 3;
            config.rateLimitBackoffBase = 5f;
            config.enableAnalytics = true;
            config.enablePerformanceTracking = true;
            config.enableDetailedLogging = false;
            config.enableEventHistory = true;
            config.maxEventHistoryEntries = 100;
            config.enableNonceValidation = true;
            config.enableReplayAttackProtection = true;
            config.maxNonceAgeSeconds = 300;
            config.enableTimestampValidation = true;
            config.timestampToleranceSeconds = 300;
            config.enableAsyncOperations = true;
            config.maxConcurrentOperations = 3;
            config.collectDeviceInfo = true;
            config.collectAppInfo = true;
            config.collectNetworkInfo = true;
            config.sendDeviceInfoToServer = true;
            config.enableSessionPersistence = true;
            config.sessionTimeoutMinutes = 60f;
            config.enableCrossSessionCaching = true;
            config.maxCachedSessions = 5;
            config.enableLocalBanCache = true;
            config.banCacheDurationHours = 24;
            Log("[MetaAuth] Recommended configuration applied");
        }

        public void SetSafeModeConfiguration()
        {
            config.enableAttestation = false;
            config.enablePhoton = false;
            config.enablePlayFab = false;
            config.enableServerHealthCheck = false;
            config.enableNetworkMonitoring = false;
            config.enableTokenAutoRefresh = false;
            config.enableAnalytics = false;
            config.enableRateLimiting = false;
            config.enableDeviceBanCheck = false;
            config.enableVersionCheck = false;
            config.enableSessionPersistence = false;
            config.enableCrossSessionCaching = false;
            config.enableNonceValidation = false;
            config.enableReplayAttackProtection = false;
            config.enableTimestampValidation = false;
            config.enableAsyncOperations = false;
            config.collectDeviceInfo = false;
            config.collectNetworkInfo = false;
            config.sendDeviceInfoToServer = false;
            config.playfabEnableDataSync = false;
            config.playfabEnableStatistics = false;
            config.cacheTokens = false;
            config.enableEventHistory = false;
            config.enablePerformanceTracking = false;
            config.requireEntitlementCheck = false;
            config.enableDetailedLogging = false;
            config.maxAuthRetries = 0;
            config.serverRequestTimeout = 10;
            config.editorSimulateAttestation = false;
            config.editorSimulatePhoton = false;
            config.editorSimulatePlayFab = false;
            Log("[MetaAuth] Safe mode configuration applied");
        }

        public void SaveConfiguration()
        {
            try
            {
                PlayerPrefs.SetString("MetaAuth_ServerUrl", config.serverUrl);
                PlayerPrefs.SetInt("MetaAuth_ServerTimeout", config.serverRequestTimeout);
                PlayerPrefs.SetInt("MetaAuth_MaxRetries", config.maxAuthRetries);
                PlayerPrefs.SetString("MetaAuth_DisplayName", config.displayName);
                PlayerPrefs.SetString("MetaAuth_PhotonRealtimeId", config.photonRealtimeAppId);
                PlayerPrefs.SetString("MetaAuth_PhotonVoiceId", config.photonVoiceAppId);
                PlayerPrefs.SetString("MetaAuth_PlayFabTitleId", config.playfabTitleId);
                PlayerPrefs.SetInt("MetaAuth_EnableAttestation", config.enableAttestation ? 1 : 0);
                PlayerPrefs.SetInt("MetaAuth_EnablePhoton", config.enablePhoton ? 1 : 0);
                PlayerPrefs.SetInt("MetaAuth_EnablePlayFab", config.enablePlayFab ? 1 : 0);
                PlayerPrefs.SetInt("MetaAuth_EnablePhotonVoice", config.photonEnableVoice ? 1 : 0);
                PlayerPrefs.SetInt("MetaAuth_EnableNetworkMonitor", config.enableNetworkMonitoring ? 1 : 0);
                PlayerPrefs.SetInt("MetaAuth_EnableAnalytics", config.enableAnalytics ? 1 : 0);
                PlayerPrefs.SetInt("MetaAuth_EnableRateLimiting", config.enableRateLimiting ? 1 : 0);
                PlayerPrefs.Save();
                Log("[MetaAuth] Configuration saved to PlayerPrefs");
            }
            catch (Exception e)
            {
                LogWarning("[MetaAuth] Failed to save configuration: " + e.Message);
            }
        }

        public void LoadConfiguration()
        {
            try
            {
                if (PlayerPrefs.HasKey("MetaAuth_ServerUrl"))
                {
                    config.serverUrl = PlayerPrefs.GetString("MetaAuth_ServerUrl", config.serverUrl);
                }
                if (PlayerPrefs.HasKey("MetaAuth_ServerTimeout"))
                {
                    config.serverRequestTimeout = PlayerPrefs.GetInt("MetaAuth_ServerTimeout", config.serverRequestTimeout);
                }
                if (PlayerPrefs.HasKey("MetaAuth_MaxRetries"))
                {
                    config.maxAuthRetries = PlayerPrefs.GetInt("MetaAuth_MaxRetries", config.maxAuthRetries);
                }
                if (PlayerPrefs.HasKey("MetaAuth_DisplayName"))
                {
                    config.displayName = PlayerPrefs.GetString("MetaAuth_DisplayName", config.displayName);
                }
                if (PlayerPrefs.HasKey("MetaAuth_PhotonRealtimeId"))
                {
                    config.photonRealtimeAppId = PlayerPrefs.GetString("MetaAuth_PhotonRealtimeId", config.photonRealtimeAppId);
                }
                if (PlayerPrefs.HasKey("MetaAuth_PhotonVoiceId"))
                {
                    config.photonVoiceAppId = PlayerPrefs.GetString("MetaAuth_PhotonVoiceId", config.photonVoiceAppId);
                }
                if (PlayerPrefs.HasKey("MetaAuth_PlayFabTitleId"))
                {
                    config.playfabTitleId = PlayerPrefs.GetString("MetaAuth_PlayFabTitleId", config.playfabTitleId);
                }
                if (PlayerPrefs.HasKey("MetaAuth_EnableAttestation"))
                {
                    config.enableAttestation = PlayerPrefs.GetInt("MetaAuth_EnableAttestation", 1) == 1;
                }
                if (PlayerPrefs.HasKey("MetaAuth_EnablePhoton"))
                {
                    config.enablePhoton = PlayerPrefs.GetInt("MetaAuth_EnablePhoton", 1) == 1;
                }
                if (PlayerPrefs.HasKey("MetaAuth_EnablePlayFab"))
                {
                    config.enablePlayFab = PlayerPrefs.GetInt("MetaAuth_EnablePlayFab", 1) == 1;
                }
                Log("[MetaAuth] Configuration loaded from PlayerPrefs");
            }
            catch (Exception e)
            {
                LogWarning("[MetaAuth] Failed to load configuration: " + e.Message);
            }
        }

        public void ExportConfigurationToJson(string filePath)
        {
            try
            {
                Dictionary<string, object> configDict = new Dictionary<string, object>();
                configDict["serverUrl"] = config.serverUrl;
                configDict["serverRequestTimeout"] = config.serverRequestTimeout;
                configDict["maxAuthRetries"] = config.maxAuthRetries;
                configDict["displayName"] = config.displayName;
                configDict["photonRealtimeAppId"] = config.photonRealtimeAppId;
                configDict["photonVoiceAppId"] = config.photonVoiceAppId;
                configDict["playfabTitleId"] = config.playfabTitleId;
                configDict["enableAttestation"] = config.enableAttestation;
                configDict["enablePhoton"] = config.enablePhoton;
                configDict["enablePlayFab"] = config.enablePlayFab;
                string json = JsonUtility.ToJson(new ConfigExportWrapper { config = configDict });
                System.IO.File.WriteAllText(filePath, json);
                Log("[MetaAuth] Configuration exported to: " + filePath);
            }
            catch (Exception e)
            {
                LogWarning("[MetaAuth] Failed to export configuration: " + e.Message);
            }
        }

        [Serializable]
        private class ConfigExportWrapper
        {
            public Dictionary<string, object> config;
        }

        public string SerializeConfiguration()
        {
            Dictionary<string, object> configDict = new Dictionary<string, object>();
            configDict["serverUrl"] = config.serverUrl;
            configDict["serverRequestTimeout"] = config.serverRequestTimeout;
            configDict["maxServerRetries"] = config.maxServerRetries;
            configDict["retryBackoffBaseDelay"] = config.retryBackoffBaseDelay;
            configDict["retryBackoffMaxDelay"] = config.retryBackoffMaxDelay;
            configDict["enableServerHealthCheck"] = config.enableServerHealthCheck;
            configDict["healthCheckInterval"] = config.healthCheckInterval;
            configDict["photonRealtimeAppId"] = config.photonRealtimeAppId;
            configDict["photonVoiceAppId"] = config.photonVoiceAppId;
            configDict["photonGameVersion"] = config.photonGameVersion;
            configDict["photonConnectionTimeout"] = config.photonConnectionTimeout;
            configDict["photonAutoJoinLobby"] = config.photonAutoJoinLobby;
            configDict["photonCreateRoomIfNotExists"] = config.photonCreateRoomIfNotExists;
            configDict["photonMaxPlayersPerRoom"] = config.photonMaxPlayersPerRoom;
            configDict["photonDefaultRoomName"] = config.photonDefaultRoomName;
            configDict["photonEnableVoice"] = config.photonEnableVoice;
            configDict["playfabTitleId"] = config.playfabTitleId;
            configDict["playfabCustomIdPrefix"] = config.playfabCustomIdPrefix;
            configDict["playfabAutoCreateAccount"] = config.playfabAutoCreateAccount;
            configDict["playfabEnableDataSync"] = config.playfabEnableDataSync;
            configDict["playfabEnableStatistics"] = config.playfabEnableStatistics;
            configDict["playfabDataSyncInterval"] = config.playfabDataSyncInterval;
            configDict["displayName"] = config.displayName;
            configDict["enableAttestation"] = config.enableAttestation;
            configDict["enablePhoton"] = config.enablePhoton;
            configDict["enablePlayFab"] = config.enablePlayFab;
            configDict["cacheTokens"] = config.cacheTokens;
            configDict["maxAuthRetries"] = config.maxAuthRetries;
            configDict["authTimeoutMultiplier"] = config.authTimeoutMultiplier;
            configDict["requireEntitlementCheck"] = config.requireEntitlementCheck;
            configDict["enableDeviceBanCheck"] = config.enableDeviceBanCheck;
            configDict["enableVersionCheck"] = config.enableVersionCheck;
            configDict["minimumGameVersion"] = config.minimumGameVersion;
            configDict["enableEnvironmentValidation"] = config.enableEnvironmentValidation;
            configDict["tokenExpiryBufferSeconds"] = config.tokenExpiryBufferSeconds;
            configDict["enableTokenAutoRefresh"] = config.enableTokenAutoRefresh;
            configDict["tokenRefreshCheckInterval"] = config.tokenRefreshCheckInterval;
            configDict["maxConcurrentTokenRefreshes"] = config.maxConcurrentTokenRefreshes;
            configDict["enableNetworkMonitoring"] = config.enableNetworkMonitoring;
            configDict["networkCheckInterval"] = config.networkCheckInterval;
            configDict["networkFailureThreshold"] = config.networkFailureThreshold;
            configDict["networkRecoveryMaxRetries"] = config.networkRecoveryMaxRetries;
            configDict["networkRecoveryBackoffBase"] = config.networkRecoveryBackoffBase;
            configDict["maxNetworkRecoveryTimeSeconds"] = config.maxNetworkRecoveryTimeSeconds;
            configDict["enableRateLimiting"] = config.enableRateLimiting;
            configDict["maxRequestsPerMinute"] = config.maxRequestsPerMinute;
            configDict["rateLimitMaxRetries"] = config.rateLimitMaxRetries;
            configDict["rateLimitBackoffBase"] = config.rateLimitBackoffBase;
            configDict["enableAnalytics"] = config.enableAnalytics;
            configDict["enablePerformanceTracking"] = config.enablePerformanceTracking;
            configDict["enableDetailedLogging"] = config.enableDetailedLogging;
            configDict["enableEventHistory"] = config.enableEventHistory;
            configDict["maxEventHistoryEntries"] = config.maxEventHistoryEntries;
            configDict["skipOculusInitInEditor"] = config.skipOculusInitInEditor;
            configDict["editorOverrideUserId"] = config.editorOverrideUserId;
            configDict["editorOverrideNonce"] = config.editorOverrideNonce;
            configDict["editorSimulateAttestation"] = config.editorSimulateAttestation;
            configDict["editorSimulatePhoton"] = config.editorSimulatePhoton;
            configDict["editorSimulatePlayFab"] = config.editorSimulatePlayFab;
            configDict["editorSimulatedLatency"] = config.editorSimulatedLatency;
            configDict["editorEnableAdvancedDebug"] = config.editorEnableAdvancedDebug;
            configDict["enableNonceValidation"] = config.enableNonceValidation;
            configDict["enableReplayAttackProtection"] = config.enableReplayAttackProtection;
            configDict["maxNonceAgeSeconds"] = config.maxNonceAgeSeconds;
            configDict["enableTimestampValidation"] = config.enableTimestampValidation;
            configDict["timestampToleranceSeconds"] = config.timestampToleranceSeconds;
            configDict["enableAsyncOperations"] = config.enableAsyncOperations;
            configDict["maxConcurrentOperations"] = config.maxConcurrentOperations;
            configDict["useObjectPooling"] = config.useObjectPooling;
            configDict["objectPoolInitialSize"] = config.objectPoolInitialSize;
            configDict["collectDeviceInfo"] = config.collectDeviceInfo;
            configDict["collectAppInfo"] = config.collectAppInfo;
            configDict["collectNetworkInfo"] = config.collectNetworkInfo;
            configDict["sendDeviceInfoToServer"] = config.sendDeviceInfoToServer;
            configDict["enableSessionPersistence"] = config.enableSessionPersistence;
            configDict["sessionTimeoutMinutes"] = config.sessionTimeoutMinutes;
            configDict["enableCrossSessionCaching"] = config.enableCrossSessionCaching;
            configDict["maxCachedSessions"] = config.maxCachedSessions;
            configDict["enableLocalBanCache"] = config.enableLocalBanCache;
            configDict["banCacheDurationHours"] = config.banCacheDurationHours;
            configDict["enableBanWebhook"] = config.enableBanWebhook;
            configDict["banWebhookUrl"] = config.banWebhookUrl;
            return JsonUtility.ToJson(new ConfigExportWrapper { config = configDict });
        }

        public void DeserializeConfiguration(string json)
        {
            if (string.IsNullOrEmpty(json)) return;
            try
            {
                ConfigExportWrapper wrapper = JsonUtility.FromJson<ConfigExportWrapper>(json);
                if (wrapper?.config != null)
                {
                    Dictionary<string, object> configDict = wrapper.config;
                    if (configDict.ContainsKey("serverUrl")) config.serverUrl = configDict["serverUrl"].ToString();
                    if (configDict.ContainsKey("serverRequestTimeout")) config.serverRequestTimeout = Convert.ToInt32(configDict["serverRequestTimeout"]);
                    if (configDict.ContainsKey("displayName")) config.displayName = configDict["displayName"].ToString();
                    if (configDict.ContainsKey("photonRealtimeAppId")) config.photonRealtimeAppId = configDict["photonRealtimeAppId"].ToString();
                    if (configDict.ContainsKey("photonVoiceAppId")) config.photonVoiceAppId = configDict["photonVoiceAppId"].ToString();
                    if (configDict.ContainsKey("playfabTitleId")) config.playfabTitleId = configDict["playfabTitleId"].ToString();
                    if (configDict.ContainsKey("enableAttestation")) config.enableAttestation = Convert.ToBoolean(configDict["enableAttestation"]);
                    if (configDict.ContainsKey("enablePhoton")) config.enablePhoton = Convert.ToBoolean(configDict["enablePhoton"]);
                    if (configDict.ContainsKey("enablePlayFab")) config.enablePlayFab = Convert.ToBoolean(configDict["enablePlayFab"]);
                    Log("[MetaAuth] Configuration deserialized successfully");
                }
            }
            catch (Exception e)
            {
                LogWarning("[MetaAuth] Failed to deserialize configuration: " + e.Message);
            }
        }

        public void CopyConfigurationFrom(AuthConfiguration source)
        {
            if (source == null) return;
            config.serverUrl = source.serverUrl;
            config.serverRequestTimeout = source.serverRequestTimeout;
            config.maxServerRetries = source.maxServerRetries;
            config.retryBackoffBaseDelay = source.retryBackoffBaseDelay;
            config.retryBackoffMaxDelay = source.retryBackoffMaxDelay;
            config.enableServerHealthCheck = source.enableServerHealthCheck;
            config.healthCheckInterval = source.healthCheckInterval;
            config.photonRealtimeAppId = source.photonRealtimeAppId;
            config.photonVoiceAppId = source.photonVoiceAppId;
            config.photonGameVersion = source.photonGameVersion;
            config.photonConnectionTimeout = source.photonConnectionTimeout;
            config.photonAutoJoinLobby = source.photonAutoJoinLobby;
            config.photonCreateRoomIfNotExists = source.photonCreateRoomIfNotExists;
            config.photonMaxPlayersPerRoom = source.photonMaxPlayersPerRoom;
            config.photonDefaultRoomName = source.photonDefaultRoomName;
            config.photonEnableVoice = source.photonEnableVoice;
            config.playfabTitleId = source.playfabTitleId;
            config.playfabCustomIdPrefix = source.playfabCustomIdPrefix;
            config.playfabAutoCreateAccount = source.playfabAutoCreateAccount;
            config.playfabEnableDataSync = source.playfabEnableDataSync;
            config.playfabEnableStatistics = source.playfabEnableStatistics;
            config.playfabDataSyncInterval = source.playfabDataSyncInterval;
            config.displayName = source.displayName;
            config.enableAttestation = source.enableAttestation;
            config.enablePhoton = source.enablePhoton;
            config.enablePlayFab = source.enablePlayFab;
            config.cacheTokens = source.cacheTokens;
            config.maxAuthRetries = source.maxAuthRetries;
            config.requireEntitlementCheck = source.requireEntitlementCheck;
            config.enableDeviceBanCheck = source.enableDeviceBanCheck;
            config.enableVersionCheck = source.enableVersionCheck;
            config.minimumGameVersion = source.minimumGameVersion;
            config.tokenExpiryBufferSeconds = source.tokenExpiryBufferSeconds;
            config.enableTokenAutoRefresh = source.enableTokenAutoRefresh;
            config.tokenRefreshCheckInterval = source.tokenRefreshCheckInterval;
            config.enableNetworkMonitoring = source.enableNetworkMonitoring;
            config.networkCheckInterval = source.networkCheckInterval;
            config.networkFailureThreshold = source.networkFailureThreshold;
            config.enableRateLimiting = source.enableRateLimiting;
            config.maxRequestsPerMinute = source.maxRequestsPerMinute;
            config.enableAnalytics = source.enableAnalytics;
            config.enablePerformanceTracking = source.enablePerformanceTracking;
            config.enableDetailedLogging = source.enableDetailedLogging;
            config.enableEventHistory = source.enableEventHistory;
            config.maxEventHistoryEntries = source.maxEventHistoryEntries;
            config.skipOculusInitInEditor = source.skipOculusInitInEditor;
            config.editorOverrideUserId = source.editorOverrideUserId;
            config.editorOverrideNonce = source.editorOverrideNonce;
            config.editorSimulateAttestation = source.editorSimulateAttestation;
            config.collectDeviceInfo = source.collectDeviceInfo;
            config.collectNetworkInfo = source.collectNetworkInfo;
            config.sendDeviceInfoToServer = source.sendDeviceInfoToServer;
            config.enableSessionPersistence = source.enableSessionPersistence;
            config.sessionTimeoutMinutes = source.sessionTimeoutMinutes;
            config.enableCrossSessionCaching = source.enableCrossSessionCaching;
            config.maxCachedSessions = source.maxCachedSessions;
            config.enableLocalBanCache = source.enableLocalBanCache;
            config.banCacheDurationHours = source.banCacheDurationHours;
            Log("[MetaAuth] Configuration copied from external source");
        }

        public void ResetToDefaults()
        {
            config.serverUrl = "https://your-project.vercel.app";
            config.serverRequestTimeout = 30;
            config.maxServerRetries = 3;
            config.retryBackoffBaseDelay = 1f;
            config.retryBackoffMaxDelay = 30f;
            config.enableServerHealthCheck = true;
            config.healthCheckInterval = 60f;
            config.photonRealtimeAppId = "";
            config.photonVoiceAppId = "";
            config.photonGameVersion = "1.0.0";
            config.photonConnectionTimeout = 20;
            config.photonAutoJoinLobby = true;
            config.photonCreateRoomIfNotExists = true;
            config.photonMaxPlayersPerRoom = 10;
            config.photonDefaultRoomName = "default";
            config.photonEnableVoice = true;
            config.playfabTitleId = "";
            config.playfabCustomIdPrefix = "sul_oculus_";
            config.playfabAutoCreateAccount = true;
            config.playfabEnableDataSync = true;
            config.playfabEnableStatistics = true;
            config.playfabDataSyncInterval = 120f;
            config.displayName = "WaterTag Player";
            config.enableAttestation = true;
            config.enablePhoton = true;
            config.enablePlayFab = true;
            config.cacheTokens = true;
            config.maxAuthRetries = 3;
            config.authTimeoutMultiplier = 1f;
            config.requireEntitlementCheck = true;
            config.enableDeviceBanCheck = true;
            config.enableVersionCheck = true;
            config.minimumGameVersion = "1.0.0";
            config.enableEnvironmentValidation = true;
            config.tokenExpiryBufferSeconds = 300;
            config.enableTokenAutoRefresh = true;
            config.tokenRefreshCheckInterval = 30f;
            config.maxConcurrentTokenRefreshes = 1;
            config.enableNetworkMonitoring = true;
            config.networkCheckInterval = 5f;
            config.networkFailureThreshold = 3;
            config.networkRecoveryMaxRetries = 5;
            config.networkRecoveryBackoffBase = 2f;
            config.maxNetworkRecoveryTimeSeconds = 120;
            config.enableRateLimiting = true;
            config.maxRequestsPerMinute = 60;
            config.rateLimitMaxRetries = 3;
            config.rateLimitBackoffBase = 5f;
            config.enableAnalytics = true;
            config.enablePerformanceTracking = true;
            config.enableDetailedLogging = false;
            config.enableEventHistory = true;
            config.maxEventHistoryEntries = 100;
            config.skipOculusInitInEditor = true;
            config.editorOverrideUserId = "1234567890";
            config.editorOverrideNonce = "test-nonce-abc123";
            config.editorSimulateAttestation = true;
            config.editorSimulatePhoton = false;
            config.editorSimulatePlayFab = false;
            config.editorSimulatedLatency = 0.1f;
            config.editorEnableAdvancedDebug = false;
            config.enableNonceValidation = true;
            config.enableReplayAttackProtection = true;
            config.maxNonceAgeSeconds = 300;
            config.enableTimestampValidation = true;
            config.timestampToleranceSeconds = 300;
            config.enableAsyncOperations = true;
            config.maxConcurrentOperations = 3;
            config.useObjectPooling = true;
            config.objectPoolInitialSize = 10;
            config.collectDeviceInfo = true;
            config.collectAppInfo = true;
            config.collectNetworkInfo = true;
            config.sendDeviceInfoToServer = true;
            config.enableSessionPersistence = true;
            config.sessionTimeoutMinutes = 60f;
            config.enableCrossSessionCaching = true;
            config.maxCachedSessions = 5;
            config.enableLocalBanCache = true;
            config.banCacheDurationHours = 24;
            config.enableBanWebhook = false;
            config.banWebhookUrl = "";
            Log("[MetaAuth] Configuration reset to defaults");
        }

        public AuthConfiguration GetConfigurationCopy()
        {
            AuthConfiguration copy = new AuthConfiguration();
            copy.serverUrl = config.serverUrl;
            copy.serverRequestTimeout = config.serverRequestTimeout;
            copy.maxServerRetries = config.maxServerRetries;
            copy.retryBackoffBaseDelay = config.retryBackoffBaseDelay;
            copy.retryBackoffMaxDelay = config.retryBackoffMaxDelay;
            copy.enableServerHealthCheck = config.enableServerHealthCheck;
            copy.healthCheckInterval = config.healthCheckInterval;
            copy.photonRealtimeAppId = config.photonRealtimeAppId;
            copy.photonVoiceAppId = config.photonVoiceAppId;
            copy.photonGameVersion = config.photonGameVersion;
            copy.photonConnectionTimeout = config.photonConnectionTimeout;
            copy.photonAutoJoinLobby = config.photonAutoJoinLobby;
            copy.photonCreateRoomIfNotExists = config.photonCreateRoomIfNotExists;
            copy.photonMaxPlayersPerRoom = config.photonMaxPlayersPerRoom;
            copy.photonDefaultRoomName = config.photonDefaultRoomName;
            copy.photonEnableVoice = config.photonEnableVoice;
            copy.playfabTitleId = config.playfabTitleId;
            copy.playfabCustomIdPrefix = config.playfabCustomIdPrefix;
            copy.playfabAutoCreateAccount = config.playfabAutoCreateAccount;
            copy.playfabEnableDataSync = config.playfabEnableDataSync;
            copy.playfabEnableStatistics = config.playfabEnableStatistics;
            copy.playfabDataSyncInterval = config.playfabDataSyncInterval;
            copy.displayName = config.displayName;
            copy.enableAttestation = config.enableAttestation;
            copy.enablePhoton = config.enablePhoton;
            copy.enablePlayFab = config.enablePlayFab;
            copy.cacheTokens = config.cacheTokens;
            copy.maxAuthRetries = config.maxAuthRetries;
            copy.authTimeoutMultiplier = config.authTimeoutMultiplier;
            copy.requireEntitlementCheck = config.requireEntitlementCheck;
            copy.enableDeviceBanCheck = config.enableDeviceBanCheck;
            copy.enableVersionCheck = config.enableVersionCheck;
            copy.minimumGameVersion = config.minimumGameVersion;
            copy.enableEnvironmentValidation = config.enableEnvironmentValidation;
            copy.tokenExpiryBufferSeconds = config.tokenExpiryBufferSeconds;
            copy.enableTokenAutoRefresh = config.enableTokenAutoRefresh;
            copy.tokenRefreshCheckInterval = config.tokenRefreshCheckInterval;
            copy.enableNetworkMonitoring = config.enableNetworkMonitoring;
            copy.networkCheckInterval = config.networkCheckInterval;
            copy.networkFailureThreshold = config.networkFailureThreshold;
            copy.enableRateLimiting = config.enableRateLimiting;
            copy.maxRequestsPerMinute = config.maxRequestsPerMinute;
            copy.enableAnalytics = config.enableAnalytics;
            copy.enablePerformanceTracking = config.enablePerformanceTracking;
            copy.enableDetailedLogging = config.enableDetailedLogging;
            copy.enableEventHistory = config.enableEventHistory;
            copy.maxEventHistoryEntries = config.maxEventHistoryEntries;
            copy.skipOculusInitInEditor = config.skipOculusInitInEditor;
            copy.editorOverrideUserId = config.editorOverrideUserId;
            copy.editorOverrideNonce = config.editorOverrideNonce;
            copy.editorSimulateAttestation = config.editorSimulateAttestation;
            copy.collectDeviceInfo = config.collectDeviceInfo;
            copy.collectNetworkInfo = config.collectNetworkInfo;
            copy.sendDeviceInfoToServer = config.sendDeviceInfoToServer;
            copy.enableSessionPersistence = config.enableSessionPersistence;
            copy.sessionTimeoutMinutes = config.sessionTimeoutMinutes;
            copy.enableCrossSessionCaching = config.enableCrossSessionCaching;
            copy.maxCachedSessions = config.maxCachedSessions;
            copy.enableLocalBanCache = config.enableLocalBanCache;
            copy.banCacheDurationHours = config.banCacheDurationHours;
            return copy;
        }

        public void RunSelfTest()
        {
            Log("[MetaAuth] Running self-test...");
            bool allPassed = true;
            if (_serverAPI == null)
            {
                LogError("[MetaAuth] SELF-TEST FAIL: ServerAPI is null");
                allPassed = false;
            }
            else
            {
                Log("[MetaAuth] SELF-TEST PASS: ServerAPI instance exists");
            }
            if (string.IsNullOrEmpty(config.serverUrl) || config.serverUrl == "https://your-project.vercel.app")
            {
                LogWarning("[MetaAuth] SELF-TEST WARN: Server URL is default value");
            }
            else
            {
                Log("[MetaAuth] SELF-TEST PASS: Server URL configured");
            }
            if (config.enablePhoton && string.IsNullOrEmpty(config.photonRealtimeAppId))
            {
                LogWarning("[MetaAuth] SELF-TEST WARN: Photon enabled but no App ID");
            }
            if (config.enablePlayFab && string.IsNullOrEmpty(config.playfabTitleId))
            {
                LogWarning("[MetaAuth] SELF-TEST WARN: PlayFab enabled but no Title ID");
            }
            if (_eventHistory == null)
            {
                LogError("[MetaAuth] SELF-TEST FAIL: Event history is null");
                allPassed = false;
            }
            else
            {
                Log("[MetaAuth] SELF-TEST PASS: Event history: " + _eventHistory.Count + " entries");
            }
            if (_networkMetrics == null)
            {
                LogError("[MetaAuth] SELF-TEST FAIL: Network metrics is null");
                allPassed = false;
            }
            else
            {
                Log("[MetaAuth] SELF-TEST PASS: Network metrics initialized");
            }
            if (_cachedSessions == null)
            {
                LogError("[MetaAuth] SELF-TEST FAIL: Cached sessions is null");
                allPassed = false;
            }
            else
            {
                Log("[MetaAuth] SELF-TEST PASS: Cached sessions: " + _cachedSessions.Count);
            }
            if (_localBanCache == null)
            {
                LogError("[MetaAuth] SELF-TEST FAIL: Local ban cache is null");
                allPassed = false;
            }
            else
            {
                Log("[MetaAuth] SELF-TEST PASS: Local ban cache entries: " + _localBanCache.Count);
            }
            if (_rateLimitTracker == null)
            {
                LogError("[MetaAuth] SELF-TEST FAIL: Rate limit tracker is null");
                allPassed = false;
            }
            else
            {
                Log("[MetaAuth] SELF-TEST PASS: Rate limit tracker initialized");
            }
            if (_pendingOperations == null)
            {
                LogError("[MetaAuth] SELF-TEST FAIL: Pending operations queue is null");
                allPassed = false;
            }
            else
            {
                Log("[MetaAuth] SELF-TEST PASS: Pending operations: " + _pendingOperations.Count);
            }
            if (_processedNonces == null)
            {
                LogError("[MetaAuth] SELF-TEST FAIL: Processed nonces set is null");
                allPassed = false;
            }
            else
            {
                Log("[MetaAuth] SELF-TEST PASS: Processed nonces: " + _processedNonces.Count);
            }
            int expectedStates = System.Enum.GetValues(typeof(AuthState)).Length;
            Log("[MetaAuth] SELF-TEST: AuthState has " + expectedStates + " states");
            int expectedSubStates = System.Enum.GetValues(typeof(AuthSubState)).Length;
            Log("[MetaAuth] SELF-TEST: AuthSubState has " + expectedSubStates + " sub-states");
            int expectedErrors = System.Enum.GetValues(typeof(AuthErrorType)).Length;
            Log("[MetaAuth] SELF-TEST: AuthErrorType has " + expectedErrors + " error types");
            if (allPassed)
            {
                Log("[MetaAuth] SELF-TEST COMPLETE: All checks passed");
            }
            else
            {
                LogError("[MetaAuth] SELF-TEST COMPLETE: Some checks failed");
            }
        }

        public Dictionary<string, bool> GetSelfTestResults()
        {
            Dictionary<string, bool> results = new Dictionary<string, bool>();
            results["serverApiExists"] = _serverAPI != null;
            results["serverUrlConfigured"] = !string.IsNullOrEmpty(config.serverUrl) && config.serverUrl != "https://your-project.vercel.app";
            results["eventHistoryExists"] = _eventHistory != null;
            results["networkMetricsExists"] = _networkMetrics != null;
            results["cachedSessionsExists"] = _cachedSessions != null;
            results["localBanCacheExists"] = _localBanCache != null;
            results["rateLimitTrackerExists"] = _rateLimitTracker != null;
            results["pendingOperationsExists"] = _pendingOperations != null;
            results["processedNoncesExists"] = _processedNonces != null;
            results["isInitialized"] = _isInitialized;
            results["authTokenAvailable"] = !string.IsNullOrEmpty(_serverAuthToken);
            results["oculusUserIdAvailable"] = !string.IsNullOrEmpty(_oculusUserId);
            return results;
        }

        public void BenchmarkOperation(string operationName, Action operation)
        {
            if (operation == null) return;
            float startTime = Time.realtimeSinceStartup;
            operation.Invoke();
            float duration = Time.realtimeSinceStartup - startTime;
            if (config.enablePerformanceTracking)
            {
                Log("[MetaAuth] Benchmark [" + operationName + "]: " + (duration * 1000f).ToString("F1") + "ms");
            }
        }

        public float BenchmarkFunction(string functionName, Func<float> function)
        {
            if (function == null) return -1f;
            float startTime = Time.realtimeSinceStartup;
            float result = function.Invoke();
            float duration = Time.realtimeSinceStartup - startTime;
            if (config.enablePerformanceTracking)
            {
                Log("[MetaAuth] Benchmark [" + functionName + "]: " + (duration * 1000f).ToString("F1") + "ms (result: " + result + ")");
            }
            return duration;
        }

        public void MeasureCoroutine(string coroutineName, IEnumerator coroutine)
        {
            if (coroutine == null) return;
            StartCoroutine(MeasureCoroutineInternal(coroutineName, coroutine));
        }

        private IEnumerator MeasureCoroutineInternal(string name, IEnumerator coroutine)
        {
            float startTime = Time.realtimeSinceStartup;
            yield return StartCoroutine(coroutine);
            float duration = Time.realtimeSinceStartup - startTime;
            if (config.enablePerformanceTracking)
            {
                Log("[MetaAuth] Coroutine [" + name + "]: " + (duration * 1000f).ToString("F1") + "ms");
            }
        }

        public int GetStateIndex(AuthState state)
        {
            string[] names = System.Enum.GetNames(typeof(AuthState));
            for (int i = 0; i < names.Length; i++)
            {
                if (names[i] == state.ToString())
                {
                    return i;
                }
            }
            return -1;
        }

        public AuthState GetStateAtIndex(int index)
        {
            string[] names = System.Enum.GetNames(typeof(AuthState));
            if (index >= 0 && index < names.Length)
            {
                return (AuthState)System.Enum.Parse(typeof(AuthState), names[index]);
            }
            return AuthState.Uninitialized;
        }

        public int GetTotalStateCount()
        {
            return System.Enum.GetNames(typeof(AuthState)).Length;
        }

        public int GetTotalSubStateCount()
        {
            return System.Enum.GetNames(typeof(AuthSubState)).Length;
        }

        public int GetTotalErrorTypeCount()
        {
            return System.Enum.GetNames(typeof(AuthErrorType)).Length;
        }

        public bool IsStateAfter(AuthState checkState, AuthState afterState)
        {
            return GetStateIndex(checkState) > GetStateIndex(afterState);
        }

        public bool IsStateBefore(AuthState checkState, AuthState beforeState)
        {
            return GetStateIndex(checkState) < GetStateIndex(beforeState);
        }

        public bool IsTerminalState(AuthState state)
        {
            return state == AuthState.FullAuthComplete || state == AuthState.Error || state == AuthState.Banned || state == AuthState.Cancelled;
        }

        public bool IsErrorState(AuthState state)
        {
            return state == AuthState.Error || state == AuthState.Banned;
        }

        public bool IsProgressState(AuthState state)
        {
            return !IsTerminalState(state) && state != AuthState.Uninitialized && state != AuthState.OculusReady;
        }

        public bool IsWaitingState(AuthState state)
        {
            return state == AuthState.WaitingForNetwork || state == AuthState.RateLimitWaiting || state == AuthState.PerformingHealthCheck || state == AuthState.SyncingPlayerData || state == AuthState.RefreshingToken;
        }

        public bool CanRestartFromState(AuthState state)
        {
            return IsTerminalState(state) || state == AuthState.OculusReady || state == AuthState.Cancelled;
        }

        public string GetStateTransitionPath()
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < _eventHistory.Count; i++)
            {
                if (i > 0) sb.Append(" -> ");
                sb.Append(_eventHistory[i].state);
            }
            return sb.ToString();
        }

        public string GetLastStateTransitionChain(int count)
        {
            StringBuilder sb = new StringBuilder();
            int startIndex = Mathf.Max(0, _eventHistory.Count - count);
            for (int i = startIndex; i < _eventHistory.Count; i++)
            {
                if (i > startIndex) sb.Append(" -> ");
                sb.Append(_eventHistory[i].state);
            }
            return sb.ToString();
        }

        public Dictionary<string, float> GetStateDurations()
        {
            Dictionary<string, float> durations = new Dictionary<string, float>();
            for (int i = 0; i < _eventHistory.Count - 1; i++)
            {
                string stateName = _eventHistory[i].state.ToString();
                float duration = _eventHistory[i + 1].timestamp - _eventHistory[i].timestamp;
                if (durations.ContainsKey(stateName))
                {
                    durations[stateName] += duration;
                }
                else
                {
                    durations[stateName] = duration;
                }
            }
            return durations;
        }

        public string GetStateDurationReport()
        {
            Dictionary<string, float> durations = GetStateDurations();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== State Duration Report ===");
            foreach (KeyValuePair<string, float> kvp in durations)
            {
                sb.AppendLine(kvp.Key + ": " + kvp.Value.ToString("F2") + "s");
            }
            return sb.ToString();
        }

        public float GetTotalTimeSpentInState(AuthState state)
        {
            float total = 0f;
            for (int i = 0; i < _eventHistory.Count - 1; i++)
            {
                if (_eventHistory[i].state == state)
                {
                    total += _eventHistory[i + 1].timestamp - _eventHistory[i].timestamp;
                }
            }
            return total;
        }

        public int GetTransitionCountToState(AuthState state)
        {
            int count = 0;
            for (int i = 0; i < _eventHistory.Count; i++)
            {
                if (_eventHistory[i].state == state)
                {
                    count++;
                }
            }
            return count;
        }

        public int GetTransitionCountFromState(AuthState state)
        {
            int count = 0;
            for (int i = 0; i < _eventHistory.Count - 1; i++)
            {
                if (_eventHistory[i].state == state)
                {
                    count++;
                }
            }
            return count;
        }

        public float GetLastTransitionTimeForState(AuthState state)
        {
            for (int i = _eventHistory.Count - 1; i >= 0; i--)
            {
                if (_eventHistory[i].state == state)
                {
                    return _eventHistory[i].timestamp;
                }
            }
            return -1f;
        }

        public float GetTimeSinceState(AuthState state)
        {
            float lastTime = GetLastTransitionTimeForState(state);
            if (lastTime < 0) return -1f;
            return Time.time - lastTime;
        }

        public bool HasVisitedState(AuthState state)
        {
            foreach (AuthenticationEvent evt in _eventHistory)
            {
                if (evt.state == state)
                {
                    return true;
                }
            }
            return false;
        }

        public int CountStateVisits(AuthState state)
        {
            int count = 0;
            foreach (AuthenticationEvent evt in _eventHistory)
            {
                if (evt.state == state)
                {
                    count++;
                }
            }
            return count;
        }

        public string GetSummary()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== MetaAuth Summary ===");
            sb.AppendLine("Version: " + GetVersion());
            sb.AppendLine("State: " + currentState + " / " + currentSubState);
            sb.AppendLine("Authenticated: " + IsAuthenticated);
            sb.AppendLine("Processing: " + _isProcessing);
            sb.AppendLine("Initialized: " + _isInitialized);
            sb.AppendLine("Auth Count: " + _authenticationCount);
            sb.AppendLine("Retry Count: " + _retryCount);
            sb.AppendLine("Session ID: " + _sessionId);
            sb.AppendLine("Oculus User ID: " + (_oculusUserId ?? "none"));
            sb.AppendLine("Server Token: " + (string.IsNullOrEmpty(_serverAuthToken) ? "none" : _serverAuthToken.Substring(0, Mathf.Min(20, _serverAuthToken.Length)) + "..."));
            sb.AppendLine("Has Attestation: " + !string.IsNullOrEmpty(_attestationToken));
            sb.AppendLine("Network: " + _networkMetrics.currentNetworkStatus + " (" + _networkMetrics.networkType + ")");
            sb.AppendLine("Server: " + config.serverUrl);
            sb.AppendLine("Photon: " + (config.enablePhoton ? "enabled" : "disabled"));
            sb.AppendLine("PlayFab: " + (config.enablePlayFab ? "enabled" : "disabled"));
            sb.AppendLine("Events Logged: " + _eventHistory.Count);
            sb.AppendLine("Cached Sessions: " + _cachedSessions.Count);
            sb.AppendLine("Banned Devices: " + _localBanCache.Count);
            sb.AppendLine("Pending Ops: " + _pendingOperations.Count);
            return sb.ToString();
        }

        public string GetNetworkReport()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== Network Report ===");
            sb.AppendLine("Status: " + _networkMetrics.currentNetworkStatus);
            sb.AppendLine("Type: " + _networkMetrics.networkType);
            sb.AppendLine("Stable: " + _networkMetrics.isNetworkStable);
            sb.AppendLine("Average Ping: " + _networkMetrics.averagePingMs.ToString("F1") + "ms");
            sb.AppendLine("Last Ping: " + _networkMetrics.lastPingMs.ToString("F1") + "ms");
            sb.AppendLine("Min Ping: " + _networkMetrics.minPingMs.ToString("F1") + "ms");
            sb.AppendLine("Max Ping: " + _networkMetrics.maxPingMs.ToString("F1") + "ms");
            sb.AppendLine("Jitter: " + _networkMetrics.jitterMs.ToString("F1") + "ms");
            sb.AppendLine("Packet Loss: " + _networkMetrics.packetLossPercent.ToString("F1") + "%");
            sb.AppendLine("Success Rate: " + _networkMetrics.successRate.ToString("F1") + "%");
            sb.AppendLine("Total Requests: " + _networkMetrics.totalRequests);
            sb.AppendLine("Successful: " + _networkMetrics.successfulRequests);
            sb.AppendLine("Failed: " + _networkMetrics.failedRequests);
            sb.AppendLine("Consecutive Failures: " + _networkMetrics.consecutiveFailures);
            sb.AppendLine("Uptime: " + _networkMetrics.uptimeSeconds.ToString("F0") + "s");
            sb.AppendLine("Disconnections: " + _networkMetrics.disconnectionCount);
            return sb.ToString();
        }

        public string GetTokenReport()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== Token Report ===");
            sb.AppendLine("Server Token: " + (string.IsNullOrEmpty(_serverAuthToken) ? "NOT SET" : "SET (" + _serverAuthToken.Length + " chars)"));
            sb.AppendLine("Attestation Token: " + (string.IsNullOrEmpty(_attestationToken) ? "NOT SET" : "SET (" + _attestationToken.Length + " chars)"));
            sb.AppendLine("Attestation Server Token: " + (string.IsNullOrEmpty(_attestationServerToken) ? "NOT SET" : "SET"));
            sb.AppendLine("Challenge Nonce: " + (string.IsNullOrEmpty(_challengeNonce) ? "NOT SET" : "SET"));
            sb.AppendLine("Signed Nonce: " + (string.IsNullOrEmpty(_signedNonce) ? "NOT SET" : "SET"));
            sb.AppendLine("Oculus Nonce: " + (string.IsNullOrEmpty(_oculusNonce) ? "NOT SET" : "SET"));
            return sb.ToString();
        }

        public string GetCacheReport()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== Cache Report ===");
            sb.AppendLine("Event History: " + _eventHistory.Count + " / " + config.maxEventHistoryEntries + " entries");
            sb.AppendLine("Cached Sessions: " + _cachedSessions.Count + " / " + config.maxCachedSessions);
            sb.AppendLine("Local Ban Cache: " + _localBanCache.Count + " entries");
            sb.AppendLine("Rate Limit Trackers: " + _rateLimitTracker.Count + " entries");
            sb.AppendLine("Pending Operations: " + _pendingOperations.Count + " queued");
            sb.AppendLine("Processed Nonces: " + _processedNonces.Count + " tracked");
            return sb.ToString();
        }

        public string GetFullDiagnosticReport()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(GetSummary());
            sb.AppendLine();
            sb.AppendLine(GetNetworkReport());
            sb.AppendLine();
            sb.AppendLine(GetTokenReport());
            sb.AppendLine();
            sb.AppendLine(GetCacheReport());
            sb.AppendLine();
            sb.AppendLine(GetConfigurationSummary());
            sb.AppendLine();
            sb.AppendLine(GetStateTransitionPath());
            sb.AppendLine();
            sb.AppendLine(GetStateDurationReport());
            return sb.ToString();
        }

        public IEnumerator PollServerForUpdates(float interval)
        {
            while (!_isDestroyed)
            {
                yield return new WaitForSeconds(interval);
                if (_serverAPI != null && _serverAPI.IsAuthenticated)
                {
                    bool gotUpdate = false;
                    _serverAPI.CheckAuthStatus(
                        (response) =>
                        {
                            if (response.success)
                            {
                                gotUpdate = true;
                            }
                        },
                        (error) =>
                        {
                        }
                    );
                    float pollTimeout = 5f;
                    float pollElapsed = 0f;
                    while (!gotUpdate && pollElapsed < pollTimeout)
                    {
                        pollElapsed += Time.deltaTime;
                        yield return null;
                    }
                }
            }
        }

        public IEnumerator PollForDeviceAttestation(float timeout)
        {
            float startTime = Time.time;
            bool attestationReceived = false;
            while (Time.time - startTime < timeout && !attestationReceived)
            {
                if (!string.IsNullOrEmpty(_attestationToken))
                {
                    attestationReceived = true;
                    break;
                }
                yield return new WaitForSeconds(0.5f);
            }
            if (!attestationReceived)
            {
                LogWarning("[MetaAuth] Polling for device attestation timed out");
            }
        }

        public IEnumerator WaitForPhotonConnection(float timeout)
        {
            float startTime = Time.time;
            while (Time.time - startTime < timeout)
            {
                if (PhotonNetwork.IsConnected)
                {
                    Log("[MetaAuth] Photon connection established (polled)");
                    yield break;
                }
                yield return new WaitForSeconds(0.5f);
            }
            LogWarning("[MetaAuth] Waiting for Photon connection timed out");
        }

        public IEnumerator WaitForPlayFabLogin(float timeout)
        {
            float startTime = Time.time;
            while (Time.time - startTime < timeout)
            {
                if (GorillaNetworking.PlayFabAuthenticator.instance != null && !string.IsNullOrEmpty(GorillaNetworking.PlayFabAuthenticator.instance._playFabPlayerIdCache))
                {
                    Log("[MetaAuth] PlayFab login confirmed (polled)");
                    yield break;
                }
                yield return new WaitForSeconds(0.5f);
            }
            LogWarning("[MetaAuth] Waiting for PlayFab login timed out");
        }

        public IEnumerator SequentialAuthentication()
        {
            Log("[MetaAuth] Starting sequential authentication");
            yield return StartCoroutine(Step_GetOculusCredentials(null, null));
            if (currentState == AuthState.Error || currentState == AuthState.Banned) yield break;
            yield return StartCoroutine(Step_ServerAuthentication(null, null));
            if (currentState == AuthState.Error || currentState == AuthState.Banned) yield break;
            if (config.enableAttestation)
            {
                yield return StartCoroutine(Step_Attestation());
                if (currentState == AuthState.Error || currentState == AuthState.Banned) yield break;
            }
            if (config.enablePhoton)
            {
                yield return StartCoroutine(Step_PhotonConnection());
            }
            if (config.enablePlayFab)
            {
                yield return StartCoroutine(Step_PlayFabLogin());
            }
            SetState(AuthState.FullAuthComplete);
            _isProcessing = false;
            OnAuthenticationComplete?.Invoke();
        }

        public IEnumerator AuthenticateWithRetry(int maxRetries)
        {
            int attempts = 0;
            bool success = false;
            while (attempts < maxRetries && !success && !_isDestroyed)
            {
                attempts++;
                Log("[MetaAuth] Authentication attempt " + attempts + "/" + maxRetries);
                yield return StartCoroutine(SequentialAuthentication());
                if (IsAuthenticated)
                {
                    success = true;
                    Log("[MetaAuth] Authentication succeeded on attempt " + attempts);
                }
                else if (currentState == AuthState.Banned)
                {
                    LogError("[MetaAuth] Device is banned, not retrying");
                    yield break;
                }
                else
                {
                    float backoff = Mathf.Min(config.retryBackoffBaseDelay * attempts, config.retryBackoffMaxDelay);
                    LogWarning("[MetaAuth] Authentication failed, retrying in " + backoff + "s");
                    ResetAuthentication();
                    yield return new WaitForSeconds(backoff);
                }
            }
            if (!success)
            {
                HandleError(AuthErrorType.ServerAuthFailed, "Authentication failed after " + maxRetries + " attempts");
            }
        }

        public void SetAuthMode(bool useOculus, bool useAttestation, bool usePhoton, bool usePlayFab)
        {
            config.enableAttestation = config.enableAttestation && useAttestation;
            config.enablePhoton = config.enablePhoton && usePhoton;
            config.enablePlayFab = config.enablePlayFab && usePlayFab;
            Log("[MetaAuth] Auth mode set: Oculus=" + useOculus + " Attestation=" + useAttestation + " Photon=" + usePhoton + " PlayFab=" + usePlayFab);
        }

        public void SetAuthComplexity(int level)
        {
            switch (level)
            {
                case 0:
                    config.enableAttestation = false;
                    config.enablePhoton = false;
                    config.enablePlayFab = false;
                    config.requireEntitlementCheck = false;
                    break;
                case 1:
                    config.enableAttestation = false;
                    config.enablePhoton = true;
                    config.enablePlayFab = false;
                    config.requireEntitlementCheck = true;
                    break;
                case 2:
                    config.enableAttestation = true;
                    config.enablePhoton = true;
                    config.enablePlayFab = false;
                    config.requireEntitlementCheck = true;
                    break;
                case 3:
                    config.enableAttestation = true;
                    config.enablePhoton = true;
                    config.enablePlayFab = true;
                    config.requireEntitlementCheck = true;
                    break;
                default:
                    SetRecommendedConfiguration();
                    break;
            }
            Log("[MetaAuth] Auth complexity set to level " + level);
        }

        public string GetAuthComplexityDescription()
        {
            if (!config.enableAttestation && !config.enablePhoton && !config.enablePlayFab)
                return "Minimal (Oculus only)";
            if (!config.enableAttestation && config.enablePhoton && !config.enablePlayFab)
                return "Standard (Oculus + Photon)";
            if (config.enableAttestation && config.enablePhoton && !config.enablePlayFab)
                return "Secure (Oculus + Attestation + Photon)";
            if (config.enableAttestation && config.enablePhoton && config.enablePlayFab)
                return "Full (Oculus + Attestation + Photon + PlayFab)";
            return "Custom";
        }
    }
}
