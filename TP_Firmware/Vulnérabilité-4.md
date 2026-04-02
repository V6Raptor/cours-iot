# Vulnérabilité 4 - Input non sécurisé

## Description
Utilisation potentielle de fonctions dangereuses :
- strcpy
- sprintf

## Impact
- Buffer overflow

## Gravité
CRITIQUE

## Correction
- Validation stricte des entrées
- Utiliser strncpy