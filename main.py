import sys
import requests
import argparse

from time import sleep
from pathlib import Path
from json import loads


def login(username, password):
    login_url = "https://api.splunk.com/2.0/rest/login/splunk"
    s = requests.Session()
    payload = {}
    login_response = s.get(login_url, data=payload, auth=(username, password))

    return login_response


def validate(_token, _build, _payload={}):
    validation_url = "https://appinspect.splunk.com/v1/app/validate"

    headers = {
        "Authorization": f"bearer {_token}",
    }
    files = [
        (
            "app_package",
            (build.name, open(_build.as_posix(), "rb"), "application/octet-stream"),
        )
    ]
    validation_response = requests.request(
        "POST", validation_url, headers=headers, data=_payload, files=files
    )
    return validation_response.json()["request_id"]


def submit_and_download_html(_token, _build, _payload):
    request_id = validate(_token=_token, _build=_build, _payload=_payload)
    url = f"https://appinspect.splunk.com/v1/app/validate/status/{request_id}"
    headers = {
        "Authorization": f"bearer {_token}",
    }
    payload = {}

    for i in range(0, timeout, sleep_time):
        response = requests.request("GET", url, headers=headers, data=payload)
        if response.json()["status"] == "SUCCESS":
            break

        sleep(sleep_time)

    print(response.text)

    download_html_report(token=_token, request_id=request_id, payload=_payload)

    return response.text


def parse_results(results):
    results = loads(results)
    if results["info"]["error"] > 0 or results["info"]["failure"] > 0:
        sys.exit("Error or failures in App Inspect")


def download_html_report(token, request_id, payload):
    download_url = f"https://appinspect.splunk.com/v1/app/report/{request_id}"

    download_payload = {}
    headers = {
        'Authorization': f'bearer {token}',
        'Content-Type': 'text/html'
    }

    report_type = payload.get("included_tags", "")
    filename = f"response_{report_type}"

    response = requests.request("GET", download_url, headers=headers, data=payload)

    with open(f'response/{filename}.html', 'w') as f:
        f.write(response.text)


def main(username, password):
    login_response = login(username, password)
    token = login_response.json()["data"]["token"]
    payloads = [{}, {"included_tags": "cloud"}, {"included_tags": "self-service"}]

    for payload in payloads:
        parse_results(submit_and_download_html(_token=token, _build=build, _payload=payload))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("username")
    parser.add_argument("password")
    parser.add_argument("addon_name")
    args = parser.parse_args()

    username = args.username
    password = args.password
    addon_name = args.addon_name

    build = Path(f"./artifacts/{addon_name}")

    sleep_time = 60
    timeout = 600

    main(username, password)
