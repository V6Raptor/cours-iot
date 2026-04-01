# TP1 - Analyse Statique

## Objectif
Extraction et analyse d’un firmware IoT.

## Outils
- binwalk
- unsquashfs

## Analyse

binwalk firmware.bin

Résultat :
- SquashFS détecté
- Compression XZ

## Extraction

binwalk -Me firmware.bin

## Structure

/bin
/etc
/www

## Conclusion
Firmware Linux embarqué classique.
Présence de fichiers sensibles (/etc/passwd, /etc/shadow).