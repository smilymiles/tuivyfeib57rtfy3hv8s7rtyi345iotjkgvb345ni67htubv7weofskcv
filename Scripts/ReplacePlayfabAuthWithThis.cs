// This is for winter 2024 auth when making this, btw idk if it will work for lower.
using System;
using System.Collections.Generic;
using System.Text;
using Photon.Pun;
using Photon.Realtime;
using PlayFab;
using PlayFab.ClientModels;
using UnityEngine;
using UnityEngine.UI;

namespace GorillaNetworking
{
    public class PlayFabAuthenticator : MonoBehaviour
    {
        public static volatile PlayFabAuthenticator instance;

        public string _playFabPlayerIdCache;

        private string _sessionTicket;

        private string _displayName;

        public string userID;

        private string orgScopedID;

        private string userToken;

        private bool enableCustomAuth;

        public GorillaComputer gorillaComputer;

        public Text debugText;

        public bool screenDebugMode;

        public bool loginFailed;

        public string loginDisplayID;

        public GameObject emptyObject;

        private string isup = "true";

        private string version = "live1122";

        public void Awake()
        {
            PhotonNetwork.PhotonServerSettings.AppSettings.AppIdRealtime = "Change to YOUR realtime id";
            PhotonNetwork.PhotonServerSettings.AppSettings.AppIdVoice = "Change to YOUR voice id";
            PlayFabSettings.TitleId = "Change to YOUR title id";
            if (instance == null)
            {
                instance = this;
            }
            else if (instance != this)
            {
                UnityEngine.Object.Destroy(base.gameObject);
            }
            if (screenDebugMode)
            {
                debugText.text = "";
            }
            if (SUL.MetaAuth.Instance != null && SUL.MetaAuth.Instance.IsAuthenticated)
            {
                Debug.Log("MetaAuth already authenticated, using existing session");
                string oculusId = SUL.MetaAuth.Instance.OculusUserId;
                userID = oculusId;
                if (!string.IsNullOrEmpty(oculusId))
                {
                    PlayFabClientAPI.LoginWithCustomID(new LoginWithCustomIDRequest
                    {
                        CreateAccount = true,
                        CustomId = "sul_oculus_" + oculusId
                    }, ClientGetTitleData, OnPlayFabError);
                }
            }
            else
            {
                OnGetAuthSessionTicketResponse();
            }
            PlayFabSettings.DisableFocusTimeCollection = true;
        }

        public void AuthenticateWithPlayFab()
        {
            if (!loginFailed)
            {
                Debug.Log("authenticating with playFab!");
            }
        }

        private void ClientGetTitleData(LoginResult obj)
        {
            LogMessage("Playfab authenticated ... Getting Title Data");
            enableCustomAuth = false;
            PlayFabClientAPI.GetTitleData(new GetTitleDataRequest(), delegate (GetTitleDataResult result)
            {
                if (result.Data == null || !result.Data.ContainsKey("EnableCustomAuthentication"))
                {
                    Debug.Log("Couldn't find EnableCustomAuthentication in the title data");
                    enableCustomAuth = false;
                }
                else
                {
                    enableCustomAuth = result.Data["EnableCustomAuthentication"] == "true";
                }
                RequestPhotonToken(obj);
            }, delegate (PlayFabError error)
            {
                Debug.Log("Got error getting titleData:");
                Debug.Log(error.GenerateErrorReport());
                RequestPhotonToken(obj);
            });
        }

        private void RequestPhotonToken(LoginResult obj)
        {
            LogMessage("Received Title Data. Requesting photon token...");
            _playFabPlayerIdCache = obj.PlayFabId;
            _sessionTicket = obj.SessionTicket;
            PlayFabClientAPI.GetPhotonAuthenticationToken(new GetPhotonAuthenticationTokenRequest
            {
                PhotonApplicationId = PhotonNetwork.PhotonServerSettings.AppSettings.AppIdRealtime
            }, AuthenticateWithPhoton, OnPlayFabError);
        }

        private void AuthenticateWithPhoton(GetPhotonAuthenticationTokenResult obj)
        {
            AuthenticationValues authenticationValues = new AuthenticationValues(PlayFabSettings.DeviceUniqueIdentifier);
            authenticationValues.AuthType = CustomAuthenticationType.Custom;
            string playFabPlayerIdCache = _playFabPlayerIdCache;
            _ = obj.PhotonCustomAuthenticationToken;
            authenticationValues.AddAuthParameter("username", _playFabPlayerIdCache);
            authenticationValues.AddAuthParameter("token", obj.PhotonCustomAuthenticationToken);
            if (enableCustomAuth)
            {
                Dictionary<string, object> authPostData = new Dictionary<string, object>
                {
                    { "UserId", playFabPlayerIdCache },
                    {
                        "AppId",
                        PlayFabSettings.TitleId
                    },
                    {
                        "AppVersion",
                        PhotonNetwork.AppVersion ?? "-1"
                    },
                    { "Ticket", _sessionTicket },
                    { "Token", obj.PhotonCustomAuthenticationToken }
                };
                authenticationValues.SetAuthPostData(authPostData);
            }
            PhotonNetwork.AuthValues = authenticationValues;
            GetPlayerDisplayName(_playFabPlayerIdCache);
            PlayFabClientAPI.ExecuteCloudScript(new ExecuteCloudScriptRequest
            {
                FunctionName = "AddOrRemoveDLCOwnership",
                FunctionParameter = new { }
            }, delegate
            {
                Debug.Log("got results! updating!");
                if (GorillaTagger.Instance != null)
                {
                    GorillaTagger.Instance.offlineVRRig.GetUserCosmeticsAllowed();
                }
            }, delegate (PlayFabError error)
            {
                Debug.Log("Got error retrieving user data:");
                Debug.Log(error.GenerateErrorReport());
                if (GorillaTagger.Instance != null)
                {
                    GorillaTagger.Instance.offlineVRRig.GetUserCosmeticsAllowed();
                }
            });
            if (CosmeticsController.instance != null)
            {
                Debug.Log("itinitalizing cosmetics");
                CosmeticsController.instance.Initialize();
            }
            if (gorillaComputer != null)
            {
                gorillaComputer.OnConnectedToMasterStuff();
            }
            if (PhotonNetworkController.Instance != null)
            {
                PhotonNetworkController.Instance.InitiateConnection();
            }
            IsUp();
            checkforupdate();
            SetMotd();
        }

        private void OnPlayFabError(PlayFabError obj)
        {
            LogMessage(obj.ErrorMessage);
            Debug.Log(obj.ErrorMessage);
            loginFailed = true;
            if (obj.ErrorMessage == "The account making this request is currently banned")
            {
                using (Dictionary<string, List<string>>.Enumerator enumerator = obj.ErrorDetails.GetEnumerator())
                {
                    if (enumerator.MoveNext())
                    {
                        KeyValuePair<string, List<string>> current = enumerator.Current;
                        if (current.Value[0] != "Indefinite")
                        {
                            gorillaComputer.GeneralFailureMessage("YOUR ACCOUNT " + loginDisplayID + " HAS BEEN BANNED FROM GORILLA TAG. YOU WILL NOT BE ABLE TO PLAY UNTIL THE BAN EXPIRES.\nREASON: " + current.Key + "\nHOURS LEFT: " + (int)((DateTime.Parse(current.Value[0]) - DateTime.UtcNow).TotalHours + 1.0));
                        }
                        else
                        {
                            gorillaComputer.GeneralFailureMessage("YOUR ACCOUNT " + loginDisplayID + " HAS BEEN BANNED FROM GORILLA TAG INDEFINITELY.\nREASON: " + current.Key);
                        }
                    }
                    return;
                }
            }
            if (obj.ErrorMessage == "The IP making this request is currently banned")
            {
                using (Dictionary<string, List<string>>.Enumerator enumerator2 = obj.ErrorDetails.GetEnumerator())
                {
                    if (enumerator2.MoveNext())
                    {
                        KeyValuePair<string, List<string>> current2 = enumerator2.Current;
                        if (current2.Value[0] != "Indefinite")
                        {
                            gorillaComputer.GeneralFailureMessage("THIS IP HAS BEEN BANNED FROM GORILLA TAG. YOU WILL NOT BE ABLE TO PLAY UNTIL THE BAN EXPIRES.\nREASON: " + current2.Key + "\nHOURS LEFT: " + (int)((DateTime.Parse(current2.Value[0]) - DateTime.UtcNow).TotalHours + 1.0));
                        }
                        else
                        {
                            gorillaComputer.GeneralFailureMessage("THIS IP HAS BEEN BANNED FROM GORILLA TAG INDEFINITELY.\nREASON: " + current2.Key);
                        }
                    }
                    return;
                }
            }
            if (gorillaComputer != null)
            {
                gorillaComputer.GeneralFailureMessage(gorillaComputer.unableToConnect);
            }
        }

        private static void AddGenericId(string serviceName, string userId)
        {
            PlayFabClientAPI.AddGenericID(new AddGenericIDRequest
            {
                GenericId = new GenericServiceId
                {
                    ServiceName = serviceName,
                    UserId = userId
                }
            }, delegate
            {
            }, delegate
            {
                Debug.LogError("Error setting generic id");
            });
        }

        public void LogMessage(string message)
        {
        }

        private void GetPlayerDisplayName(string playFabId)
        {
            PlayFabClientAPI.GetPlayerProfile(new GetPlayerProfileRequest
            {
                PlayFabId = playFabId,
                ProfileConstraints = new PlayerProfileViewConstraints
                {
                    ShowDisplayName = true
                }
            }, delegate (GetPlayerProfileResult result)
            {
                _displayName = result.PlayerProfile.DisplayName;
            }, delegate (PlayFabError error)
            {
                Debug.LogError(error.GenerateErrorReport());
            });
        }

        public void SetDisplayName(string playerName)
        {
            if (_displayName == null || (_displayName.Length > 4 && _displayName.Substring(0, _displayName.Length - 4) != playerName))
            {
                PlayFabClientAPI.UpdateUserTitleDisplayName(new UpdateUserTitleDisplayNameRequest
                {
                    DisplayName = playerName
                }, delegate
                {
                    _displayName = playerName;
                }, delegate (PlayFabError error)
                {
                    Debug.LogError(error.GenerateErrorReport());
                });
            }
        }

        public void ScreenDebug(string debugString)
        {
            Debug.Log(debugString);
            if (screenDebugMode)
            {
                Text text = debugText;
                text.text = text.text + debugString + "\n";
            }
        }

        public void ScreenDebugClear()
        {
            debugText.text = "";
        }

        public PlayFabAuthenticator()
        {
            loginDisplayID = "";
        }

        private void OnGetAuthSessionTicketResponse()
        {
            PlayFabClientAPI.LoginWithCustomID(new LoginWithCustomIDRequest
            {
                CreateAccount = true,
                CustomId = PlayFabSettings.DeviceUniqueIdentifier
            }, ClientGetTitleData, OnPlayFabError);
        }

        private void SetMotd()
        {

        }

        private void checkforupdate()
        {

        }

        private void IsUp()
        {

        }
    }
}
