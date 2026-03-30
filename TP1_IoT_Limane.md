## 1. Préparation de l’environnement

```bash
mkdir -p ~/IoT/formation-Jour2/{certs,csr}
cd ~/IoT/formation-Jour2
chmod 700 certs csr
```

---

## 2. Création de l’autorité de certification (CA)

```bash
openssl genrsa -out ca.key 2048

openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/C=fr/ST=ile-de-france/L=paris/O=IB/OU=IB-Data/CN=MQTT-CA"
```

---

## 3. Génération des clés et des CSR

```bash
openssl genrsa -out broker.key 2048
openssl genrsa -out client.key 2048

openssl req -new -key broker.key -out broker.csr -subj "/C=FR/ST=Ile-de-France/L=Paris/O=IB/OU=IB-Data/CN=MQTT-test"

openssl req -new -key client.key -out client.csr -subj "/C=FR/ST=Ile-de-France/L=Paris/O=IB/OU=IB-Data/CN=iot-client-iba"
```

---

## 4. Signature des certificats

```bash
openssl x509 -req -in broker.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out broker.crt -days 365

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

---

## 5. Vérification des certificats

```bash
openssl x509 -in broker.crt -text -noout | grep "MQTT-test"
openssl x509 -in client.crt -text -noout | grep "iba"
openssl x509 -in ca.crt -text -noout | grep "MQTT-CA"
```

---

## 6. Sécurisation des fichiers

```bash
chmod 600 *.key
chmod 644 *.crt *.csr
ls -la
```

---

## 7. Configuration du broker Mosquitto

```bash
listener 8883
cafile /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/broker.crt
keyfile /etc/mosquitto/certs/broker.key
require_certificate true
use_identity_as_username true
```

---

## 8. Tests de sécurité

### Test avec certificat (réussi)

```bash
mosquitto_pub -h localhost -p 8883   --cafile ca.crt --cert client.crt --key client.key   -t "test/secured" -m "mTLS OK"
```

---

### Test sans certificat (échec)

```bash
mosquitto_pub -h localhost -p 8883 --cafile ca.crt -t test -m "nope"
```

---

## Conclusion

Ce TP m’a permis de comprendre et mettre en œuvre :

- La création d’une **PKI (Public Key Infrastructure)**  
- Le fonctionnement des certificats **X.509**  
- La sécurisation des communications IoT avec **mTLS**  
- L’importance de l’authentification mutuelle dans un environnement de production 
