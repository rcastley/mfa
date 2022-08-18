from flask import Flask, render_template, request
import requests
import time
import json

app = Flask(__name__)

SPLUNK_HEC_ENDPOINT = "https://52.12.161.40:8088/services/collector/raw"
SPLUNK_HEC_TOKEN = "xxxx"
auth_error = {
    "legacyEventType": "core.user_auth.login_failed",
    "request": {
        "ipChain": [
            {
                "version": "V4",
                "geographicalContext": {
                    "geolocation": {"lat": "34.07290", "lon": "-118.26060"},
                    "state": "null",
                    "city": "null",
                    "country": "United States",
                    "postalCode": "null"
                },
                "source": "null",
                "ip": "199.226.26.2"
            }
        ]
    },
    "version": "0",
    "severity": "WARN",
    "debugContext": {
        "debugData": {
            "requestId": "UooUxaFJWOYKSOXB0tjFvdEOEC1",
            "url": "/app/template_saml_2_0//u61gcev0OMGLLGIJIGGB/sso/saml?",
            "requestUri": "/app/template_saml_2_0/template_saml_2_0",
            "authnRequestId": "MkwtG2IyFOoGH0bKVq@BROXGXjw",
            "threatSuspected": "false"
        }
    },
    "eventType": "user.session.start",
    "uuid": "30064s23-0216-01jy-xu9r-2cj00latfw1l",
    "authenticationContext": {
        "externalSessionId": "null",
        "credentialType": "null",
        "authenticationStep": 0,
        "authenticationProvider": "null",
        "credentialProvider": "null",
        "interface": "null",
        "issuer": "null"
    },
    "actor": {
        "displayName": "nsmalley@splunk.com",
        "detailEntry": "null",
        "id": "00d00nhsqzgrpik300j0",
        "alternateId": "nsmalley@splunk.com",
        "type": "User"
    },
    "securityContext": {
        "domain": "null",
        "asNumber": "null",
        "isp": "null",
        "isProxy": "null",
        "asOrg": "null"
    },
    "transaction": {"id": "UooUxaFJWOYKSOXB0tjFvdEOEC1", "detail": {}, "type": "WEB"},
    "displayMessage": "User login to Okta",
    "client": {
        "userAgent": {
            "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
            "os": "Windows 11",
            "browser": "CHROME"
        },
        "zone": "null",
        "device": "Computer",
        "geographicalContext": {
            "geolocation": {"lat": "34.07290", "lon": "-118.26060"},
            "state": "null",
            "city": "null",
            "country": "United States",
            "postalCode": "null"
        },
        "id": "null",
        "ipAddress": "199.226.26.2"
    },
    "target": [
        {
            "displayName": "template_saml_2_0",
            "detailEntry": "null",
            "id": "0vf64ncwv1VGXOOHFCYZ",
            "alternateId": "template_saml_2_0",
            "type": "AppInstance"
        }
    ],
    "published": "Aug 17 16:01:20",
    "outcome": {"reason": "VERIFICATION_ERROR", "result": "FAILURE"}
}


@app.route("/")
def index():
    return render_template("login.html")


@app.route("/auth")
def cert():
    return render_template("mfa.html")


@app.route("/auth/mfa", methods=("GET", "POST"))
def mfa():
    if request.method == "POST":
        code = request.form["code"]
        if code == "123456":
            return ("Success!", 200)
        else:
            return throwWrongCode()


def throwWrongCode():
    url = SPLUNK_HEC_ENDPOINT
    headers = {"Authorization": "Splunk " + SPLUNK_HEC_TOKEN}
    event = {}
    event["event"] = "okta"
    event["time"] = int(time.time())
    #event["sourcetype"] = "json_no_timestamp"
    
    event["fields"] = auth_error

    resp = requests.post(url, json=event, headers=headers, verify=False)
    print(resp.status_code)
    print(resp.reason)
    return render_template("mfa.html")


if __name__ == "__main__":
    # For production
    # app.run(host="0.0.0.0")

    # For local testing
    app.run(host="0.0.0.0", port=5005)
