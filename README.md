# Meta Quest Attestation API

> **Discord:** https://discord.gg/WyZssYjhcy

Complete authentication & attestation system for Meta Quest + Photon + PlayFab. Serverless-ready (Vercel).

## How It Works

```
Unity Client                      Vercel Server                   Meta/Photon/PlayFab
  |-- Oculus user ID + nonce --->|-- POST /auth/oculus --------->|-- Validate with Oculus
  |<---- JWT token --------------|<---- { token, userId } -------|
  |-- Challenge nonce ---------->|-- GET /challenge-nonce
  |<---- challenge --------------|
  |-- Device integrity token --->|-- POST /verify-attestation --->|-- Meta integrity verify
  |<---- attestation result -----|<---- { app, device state } ---|
  |-- Photon connect (Oculus) ---|> Photon validates via Oculus auth provider
  |-- PlayFab login -------------|> Server-side LoginWithCustomID
```

## Files

| Path | What |
|------|------|
| `api/index.py` | Flask server (Vercel serverless function) |
| `requirements.txt` | Python deps |
| `vercel.json` | Vercel config |
| `Scripts/MetaAuth.cs` | Unity auth orchestrator (drop into Assets) |
| `Scripts/ServerAPI.cs` | Unity HTTP client (drop into Assets) |
| `Scripts/ReplacePlayfabAuthWithThis.cs` | Modified PlayFabAuthenticator (drop into Assets, replaces GorillaNetworking one) |

## Quick Start

### 1. Deploy Server (Vercel)

```bash
npm i -g vercel
vercel login
cd "Meta Quest Attestation API"
vercel --prod
```

Or import the GitHub repo into Vercel Dashboard. Add these env vars:

| Variable | Required | What |
|----------|----------|------|
| `META_APP_ID` | Yes | Oculus App ID |
| `META_APP_SECRET` | Yes | Oculus App Secret |
| `OCULUS_ACCESS_TOKEN` | Yes | `OC\|AppId\|AppSecret` |
| `JWT_SECRET` | No | Random 64-char hex |
| `PHOTON_REALTIME_ID` | For Photon | Photon Realtime App ID |
| `PHOTON_VOICE_ID` | For Voice | Photon Voice App ID |
| `PLAYFAB_TITLE_ID` | For PlayFab | PlayFab Title ID |
| `PLAYFAB_SECRET_KEY` | For PlayFab | PlayFab Secret Key |

### 2. Unity Setup

1. Copy `Scripts/MetaAuth.cs` and `Scripts/ServerAPI.cs` into your Unity Assets folder
2. Add define symbols: `OCULUS_PLATFORM;PUN_2_OR_NEWER;PLAYFAB_SDK`
3. Set App ID in **Oculus > Platform > Edit Settings**
4. Configure **Photon Oculus auth provider** in Photon Dashboard
5. Call `MetaAuth.Instance.SetServerUrl("https://your-app.vercel.app");`
6. Call `MetaAuth.Instance.StartAuthentication();`

### 3. Photon Auth Provider Setup

In Photon Dashboard:
1. Go to your Realtime app > **Authentication** > **Add Authentication Provider**
2. Choose **Oculus**, enter App ID + App Secret

### 4. GorillaTag Integration

Drop `ReplacePlayfabAuthWithThis.cs` in `Assets/Scripts/Assembly-CSharp/GorillaNetworking/` (replaces the original `PlayFabAuthenticator`). MetaAuth auto-sets `PhotonNetwork.AuthValues` and calls `PhotonNetworkController.Instance.InitiateConnection()`.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | None | Health check + features |
| POST | `/auth/oculus` | None | Oculus login (userId, nonce) -> JWT |
| GET | `/challenge-nonce` | Bearer | Get attestation challenge nonce |
| POST | `/verify-attestation` | Bearer | Verify device integrity token |
| POST | `/full-auth` | None | Oculus + attestation in one call |
| GET | `/auth/status` | Bearer | Check token validity |
| POST | `/photon-auth` | Bearer | Get Photon App IDs |
| POST | `/playfab-auth` | Bearer | Server-side PlayFab login |
| GET | `/ping` | None | Ping |

## Usage (Unity)

```csharp
using SUL;

MetaAuth.Instance.SetServerUrl("https://your-app.vercel.app");
MetaAuth.Instance.SetDisplayName("Player");
MetaAuth.Instance.ToggleFeature("attestation", true);
MetaAuth.Instance.ToggleFeature("photon", true);
MetaAuth.Instance.ToggleFeature("playfab", true);
MetaAuth.Instance.StartAuthentication();

// Events
MetaAuth.Instance.OnAuthenticationComplete += () => { Debug.Log("Done!"); };
MetaAuth.Instance.OnError += (type, error) => { Debug.LogError(error); };
MetaAuth.Instance.OnProgress += (p) => { loadingBar.value = p; };
MetaAuth.Instance.OnStateChanged += (s) => { Debug.Log(s); };
```

## Requirements
Which u should alr have since its a gtag copy
- Unity 2021.3+ (Android)
- Oculus XR Plugin / Meta XR SDK
- Photon PUN 2
- PlayFab Unity SDK
- Meta Quest headset (for attestation)
- Vercel account (free)

## Notes

- Attestation only works on **Oculus-signed release builds**, not in editor/dev builds
- App must be uploaded to Oculus App Lab for attestation to function
- Server is stateless — no database needed
