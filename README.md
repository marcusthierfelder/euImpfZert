# Test um EU Zertifikate zu erzeugen

das ganze braucht python3 und ein TI-Konnektor und eine Route zu dem für die Server:

### für PU

```
sudo route -n add 100.102.0.0/17 KON-IP
sudo route -n add 100.103.0.0/16 KON-IP
sudo route -n add 100.102.128.0/17 KON-IP
```

### für RU

```
sudo route -n add 10.30.17.10/24 KON-IP
```

anpassen der daten im request.py relativ weit oben

### konfigurieren und starten

```
pip3 install -r requirements.txt
```

```
python3 request.py
```


Starten geht zb mit
```
python3 euImpfZert.py -ip=10.100.9.166 -tls -p12=clientCert.p12 -pwd=123456 -mandant=TOMEDO2RU -client=TOMEDOKIM -workplace=WorkplaceKIM -user=wu -serverType=RU -body=test_impf.json -out=out_impf.pdf
python3 euImpfZert.py -ip=10.100.9.166 -tls -p12=clientCert.p12 -pwd=123456 -mandant=TOMEDO2RU -client=TOMEDOKIM -workplace=WorkplaceKIM -user=wu -serverType=RU -body=test_genesen.json -out=out_genesen.pdf
```