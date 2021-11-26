#!/usr/bin/env python3

import argparse
import getopt
import random
import string
import sys


from requestHelper import RequestHelper


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-ip", help="IP", required=True)
    parser.add_argument("-tls", help="TLS", action="store_true")
    parser.add_argument("-p12", required=True)
    parser.add_argument("-pwd", required=True)
    parser.add_argument("-mandant", required=True)
    parser.add_argument("-client", required=True)
    parser.add_argument("-workplace", required=True)
    parser.add_argument("-user", required=True)
    parser.add_argument("-serverType", choices=['RU', 'PU', 'SIMPLE'])
    parser.add_argument("-body", required=True)
    parser.add_argument("-out", required=True)

    args = parser.parse_args()
    print(args)


    with open(args.body, 'r') as file:
        bodyZert = file.read().replace('\n', '')

    bodyZert = {
        "ver": "1.0.0",
        "nam": {
            "fn": "Mustermann",
            "gn": "Max"
        },
        "dob": "1979-04-14",
        "v": [{
            "id": "011111100",
            "tg": "840539006",
            "vp": "1119305005",
            "mp": "EU/1/20/1528",
            "ma": "ORG-100030215",
            "dn": 2,
            "sd": 2,
            "dt": "2021-04-14",
            "co": "NL",
            "is": "Ministry of Public Health, Welfare and Sport",
            "ci": "urn:uvci:01:NL:PlA8UWS60Z4RZXVALl6GAZ"
        }],
    }

    print("###############################")
    rh = RequestHelper(ip=args.ip, tls=args.tls, pkcs12_filename=args.p12, pkcs12_password=args.pwd, mandant=args.mandant,
                       client=args.client, workplace=args.workplace, user=args.user, serverType=args.serverType, bodyZert=bodyZert)
    #rh = RequestHelper(args.ip, args.tls, "clientCert.p12", "123456", "TOMEDO2RU", "TOMEDOKIM", "WorkplaceKIM", "test", "RU", bodyZert)

    sds = rh.getSDS()
    cardHandle = rh.getCardHandleSMCB(sds)
    print(cardHandle)

    nonce = ''.join([random.choice(string.digits) for _ in range(30)])
    print(nonce)
    challenge, location = rh.getChallenge(nonce)
    print(challenge)

    signedChallenge = rh.externalAuth(sds, cardHandle, challenge)
    print(signedChallenge)

    certificate = rh.getCertificate(sds, cardHandle)
    print(certificate)

    authCode = rh.submitSignedChallengeOS(location, signedChallenge, certificate)
    print(authCode)

    token = rh.tokenExchange(authCode)
    print(token)

    rh.getpdf(token, args.out)

if __name__ == "__main__":
    main()
