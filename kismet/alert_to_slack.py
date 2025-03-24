import requests
import time

KISMET_URL = ""
API_KEY = ""
SLACK_WEBHOOK_URL = ""

headers = {
    "KISMET": API_KEY
}

def get_recent_alerts():
    response = requests.get(
        f"{KISMET_URL}/alerts/wrapped/last-time/-60/alerts.json",
        headers=headers
    )
    if response.status_code == 200:
        return response.json().get('alerts', [])
    else:
        print(f"API Request Failed: {response.status_code}, {response.text}")
        return []

def send_to_slack(alert):
    message = {
        "text": f"*New Kismet Alert:*\n>{alert['message']}\n`Timestamp: {alert['time']}`"
    }
    response = requests.post(SLACK_WEBHOOK_URL, json=message)
    if response.status_code != 200:
        print(f"Slack webhook failed: {response.status_code}, {response.text}")

if __name__ == "__main__":
    already_seen = set()

    while True:
        alerts = get_recent_alerts()
        for alert in alerts:
            if alert['key'] not in already_seen:
                send_to_slack(alert)
                already_seen.add(alert['key'])

        time.sleep(60)
