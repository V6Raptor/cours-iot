# TP2 - Reverse Engineering

## Objectif
Comprendre le fonctionnement interne du firmware.

## Analyse strings

strings httpd

Résultat :
- Script shell simple
- "Server running..."

## Analyse fichiers sensibles

/etc/passwd :
- root
- admin

/etc/shadow :
- hash présent

## Vulnérabilités potentielles
- Mots de passe faibles
- Authentification basique

## Conclusion
Firmware peu sécurisé avec logique minimale.