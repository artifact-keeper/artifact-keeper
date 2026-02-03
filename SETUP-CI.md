# CI/CD Pipeline Setup Guide

This guide walks through setting up automated build, test, and release pipelines for all Artifact Keeper clients.

## Overview

| Platform | Runner | Cost | Trigger |
|----------|--------|------|---------|
| Backend | `ubuntu-latest` | Free (public repo) | Every push to main |
| Web | `ubuntu-latest` | Free (public repo) | Every push to main |
| iOS/macOS | `macos-15` | Free (public repo) | Every push to main |
| Android | `ubuntu-latest` | Free (public repo) | Every push to main |

Releases (archive + signing) trigger on `v*` tags or manual `workflow_dispatch`.

---

## 1. iOS / macOS Pipeline

**Repo:** `artifact-keeper/artifact-keeper-ios`
**Workflow:** `.github/workflows/ci.yml`

### Jobs

| Job | Trigger | What it does |
|-----|---------|-------------|
| `build` | Every push/PR | `swift build` |
| `test` | Every push/PR | `swift test` |
| `build-ios` | Push to main | Build for iOS Simulator (validates Xcode project) |
| `archive-release` | `v*` tag or manual | Archive iOS IPA + macOS app, sign, upload to App Store |

### Required Secrets

Set these in GitHub: **Settings > Secrets and variables > Actions > New repository secret**

#### For CI builds (no secrets needed)

The `build`, `test`, and `build-ios` jobs run without any secrets.

#### For signed releases

| Secret | Description | How to get it |
|--------|-------------|---------------|
| `APPLE_CERTIFICATE_BASE64` | Distribution certificate (.p12), base64-encoded | See steps below |
| `APPLE_CERTIFICATE_PASSWORD` | Password you set when exporting the .p12 | You chose this during export |
| `APPLE_PROVISIONING_PROFILE_BASE64` | Provisioning profile (.mobileprovision), base64-encoded | See steps below |
| `APPLE_TEAM_ID` | Your Apple Developer Team ID | developer.apple.com > Membership |

#### For App Store uploads (optional)

| Secret | Description | How to get it |
|--------|-------------|---------------|
| `APPSTORE_API_KEY_ID` | App Store Connect API Key ID | See steps below |
| `APPSTORE_API_ISSUER_ID` | App Store Connect API Issuer ID | See steps below |
| `APPSTORE_API_PRIVATE_KEY` | Contents of the .p8 private key file | See steps below |

### Step-by-step: Export signing certificate

1. Open **Keychain Access** on your Mac
2. Find your **Apple Distribution** certificate (or create one at developer.apple.com > Certificates)
3. Right-click > **Export** > save as `.p12` format
4. Set a password when prompted (you'll use this as `APPLE_CERTIFICATE_PASSWORD`)
5. Base64-encode it:
   ```bash
   base64 -i ~/Desktop/Certificates.p12 | pbcopy
   ```
6. Paste into GitHub secret `APPLE_CERTIFICATE_BASE64`

### Step-by-step: Create provisioning profile

1. Go to **developer.apple.com > Certificates, IDs & Profiles > Profiles**
2. Click **+** to create a new profile
3. Select **App Store Connect** (for distribution)
4. Select the App ID for Artifact Keeper (create one if needed, bundle ID should match your project)
5. Select your distribution certificate
6. Download the `.mobileprovision` file
7. Base64-encode it:
   ```bash
   base64 -i ~/Desktop/ArtifactKeeper.mobileprovision | pbcopy
   ```
8. Paste into GitHub secret `APPLE_PROVISIONING_PROFILE_BASE64`

### Step-by-step: App Store Connect API Key

1. Go to **appstoreconnect.apple.com > Users and Access > Integrations > App Store Connect API**
2. Click **+** to generate a new key
3. Give it a name (e.g., "CI/CD"), select **App Manager** role
4. Download the `.p8` file (you can only download it once!)
5. Note the **Key ID** and **Issuer ID** shown on the page
6. Set secrets:
   ```bash
   # Key ID (shown on the page, e.g., "ABC123DEF4")
   gh secret set APPSTORE_API_KEY_ID --repo artifact-keeper/artifact-keeper-ios

   # Issuer ID (shown at top of page, e.g., "69a6de78-...")
   gh secret set APPSTORE_API_ISSUER_ID --repo artifact-keeper/artifact-keeper-ios

   # Private key (contents of the .p8 file)
   gh secret set APPSTORE_API_PRIVATE_KEY --repo artifact-keeper/artifact-keeper-ios < ~/Desktop/AuthKey_ABC123DEF4.p8
   ```

### Quick setup with `gh` CLI

Once you have the files ready:

```bash
# Signing certificate
base64 -i Certificates.p12 | gh secret set APPLE_CERTIFICATE_BASE64 --repo artifact-keeper/artifact-keeper-ios
gh secret set APPLE_CERTIFICATE_PASSWORD --repo artifact-keeper/artifact-keeper-ios

# Provisioning profile
base64 -i ArtifactKeeper.mobileprovision | gh secret set APPLE_PROVISIONING_PROFILE_BASE64 --repo artifact-keeper/artifact-keeper-ios

# Team ID
gh secret set APPLE_TEAM_ID --repo artifact-keeper/artifact-keeper-ios

# App Store Connect API (optional, for automated uploads)
gh secret set APPSTORE_API_KEY_ID --repo artifact-keeper/artifact-keeper-ios
gh secret set APPSTORE_API_ISSUER_ID --repo artifact-keeper/artifact-keeper-ios
gh secret set APPSTORE_API_PRIVATE_KEY --repo artifact-keeper/artifact-keeper-ios < AuthKey_XXXXXXXXXX.p8
```

### Triggering a release

```bash
# Tag a release (triggers archive + App Store upload)
git tag v1.0.0
git push origin v1.0.0

# Or trigger manually without a tag
gh workflow run ci.yml --repo artifact-keeper/artifact-keeper-ios -f upload_to_appstore=true
```

---

## 2. Android Pipeline

**Repo:** `artifact-keeper/artifact-keeper-android`
**Workflow:** `.github/workflows/ci.yml`

### Jobs

| Job | Trigger | What it does |
|-----|---------|-------------|
| `lint` | Every push/PR | `./gradlew lint` |
| `build` | Every push/PR | `./gradlew assembleDebug`, uploads debug APK |
| `test` | Every push/PR | `./gradlew test` |
| `release` | `v*` tag or manual | Build signed release APK + AAB, upload to Play Store |

### Required Secrets

#### For CI builds (no secrets needed)

The `lint`, `build`, and `test` jobs run without any secrets.

#### For signed releases

| Secret | Description | How to get it |
|--------|-------------|---------------|
| `ANDROID_KEYSTORE_BASE64` | Release keystore (.jks), base64-encoded | See steps below |
| `ANDROID_KEYSTORE_PASSWORD` | Keystore password | You chose this during creation |
| `ANDROID_KEY_ALIAS` | Key alias in the keystore | You chose this during creation |
| `ANDROID_KEY_PASSWORD` | Key password | You chose this during creation |

#### For Play Store uploads (optional)

| Secret | Description | How to get it |
|--------|-------------|---------------|
| `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` | Google Play API service account JSON | See steps below |

### Step-by-step: Create release keystore

```bash
keytool -genkey -v \
  -keystore artifact-keeper-release.jks \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -alias artifact-keeper

# Answer the prompts (name, org, etc.)
# Remember the passwords you set!
```

**IMPORTANT:** Back up this keystore file securely. If you lose it, you cannot update the app on Google Play.

### Step-by-step: Set up Play Store API access

1. Go to **Google Cloud Console** (console.cloud.google.com)
2. Create a project (or use existing)
3. Enable the **Google Play Developer API**
4. Create a **Service Account** (IAM & Admin > Service Accounts)
5. Download the JSON key file
6. Go to **Google Play Console** (play.google.com/console)
7. Go to **Settings > API access**
8. Link the Google Cloud project
9. Grant the service account **Release Manager** access
10. Wait 24 hours for the permission to propagate (yes, really)

### Quick setup with `gh` CLI

```bash
# Release keystore
base64 -i artifact-keeper-release.jks | gh secret set ANDROID_KEYSTORE_BASE64 --repo artifact-keeper/artifact-keeper-android
gh secret set ANDROID_KEYSTORE_PASSWORD --repo artifact-keeper/artifact-keeper-android
gh secret set ANDROID_KEY_ALIAS --repo artifact-keeper/artifact-keeper-android
gh secret set ANDROID_KEY_PASSWORD --repo artifact-keeper/artifact-keeper-android

# Google Play (optional, for automated uploads)
gh secret set GOOGLE_PLAY_SERVICE_ACCOUNT_JSON --repo artifact-keeper/artifact-keeper-android < service-account.json
```

### Triggering a release

```bash
# Tag a release
git tag v1.0.0
git push origin v1.0.0

# Or manually
gh workflow run ci.yml --repo artifact-keeper/artifact-keeper-android
```

---

## 3. Web Pipeline (already working)

**Repo:** `artifact-keeper/artifact-keeper-web`
**Workflow:** `.github/workflows/ci.yml`

Already configured. Builds Docker image and pushes to `ghcr.io/artifact-keeper/artifact-keeper-web:latest` on every push to main.

No secrets needed (uses `GITHUB_TOKEN` automatically).

---

## 4. Backend Pipeline (already working)

**Repo:** `artifact-keeper/artifact-keeper`
**Workflow:** Check existing workflows.

---

## Costs Summary

| Item | Cost | Frequency |
|------|------|-----------|
| Apple Developer Program | $99 | per year |
| Google Play Console | $25 | one-time |
| GitHub Actions (all platforms) | $0 | free for public repos |
| Docker images (ghcr.io) | $0 | free for public repos |
| **Total first year** | **$124** | |
| **Subsequent years** | **$99/year** | |

---

## GitHub Open Source Program

All repos are public, which gives you:
- Unlimited GitHub Actions minutes (Linux, macOS, Windows)
- Free GitHub Packages (Docker images via ghcr.io)
- Free GitHub Pages (landing site)

To get larger/faster macOS runners (M1 silicon), apply at:
- https://github.com/enterprise/startups (for startups)
- Or email opensource@github.com with your org link

---

## Quick Reference: All Secrets

### iOS (`artifact-keeper-ios`)
```
APPLE_CERTIFICATE_BASE64          # .p12 cert, base64
APPLE_CERTIFICATE_PASSWORD        # .p12 password
APPLE_PROVISIONING_PROFILE_BASE64 # .mobileprovision, base64
APPLE_TEAM_ID                     # e.g., "A1B2C3D4E5"
APPSTORE_API_KEY_ID               # e.g., "ABC123DEF4"
APPSTORE_API_ISSUER_ID            # e.g., "69a6de78-..."
APPSTORE_API_PRIVATE_KEY          # .p8 file contents
```

### Android (`artifact-keeper-android`)
```
ANDROID_KEYSTORE_BASE64           # .jks keystore, base64
ANDROID_KEYSTORE_PASSWORD         # keystore password
ANDROID_KEY_ALIAS                 # e.g., "artifact-keeper"
ANDROID_KEY_PASSWORD              # key password
GOOGLE_PLAY_SERVICE_ACCOUNT_JSON  # service account JSON
```
