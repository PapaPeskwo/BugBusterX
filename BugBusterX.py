import requests
import os
import sys
import json
from tabulate import tabulate
import time

API_KEY = "<your_api_key>"
API_BASE_URL = "https://www.virustotal.com/api/v3/"

def upload_file(file_path):
    url = f"{API_BASE_URL}files"
    headers = {
        "x-apikey": API_KEY
    }

    with open(file_path, "rb") as f:
        response = requests.post(url, headers=headers, files={"file": f})

    if response.status_code == 200:
        json_response = response.json()
        return json_response["data"]["id"]
    else:
        print(f"Error: {response.text}")
        return None

def get_analysis_results(analysis_id):
    url = f"{API_BASE_URL}analyses/{analysis_id}"
    headers = {
        "x-apikey": API_KEY
    }

    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            status = json_response["data"]["attributes"]["status"]
            if status == "completed":
                return json_response
            elif status in ["queued", "in_progress"]:
                print(f"Status: {status}. Waiting for analysis to complete...")
                time.sleep(5)  # Wait 5 seconds before checking again
            else:
                print(f"Error: Unexpected analysis status: {status}")
                return None
        else:
            print(f"Error: {response.text}")
            return None

def pretty_print_json(json_data):
    return json.dumps(json_data, indent=2)

def print_analysis_results(analysis):
    attributes = analysis["data"]["attributes"]
    stats = attributes["stats"]
    results = attributes["results"]

    if stats["malicious"] == 0 and stats["suspicious"] == 0:
        print("The file is safe.")
        return

    filtered_results = []
    for key, value in results.items():
        if value["category"] in ["suspicious", "malicious"]:
            filtered_results.append(value)

    if filtered_results:
        headers = ["Engine Name", "Category", "Result", "Engine Version", "Method", "Engine Update"]
        table_data = [
            [
                res["engine_name"],
                res["category"],
                res["result"],
                res["engine_version"],
                res["method"],
                res["engine_update"],
            ]
            for res in filtered_results
        ]
        print(tabulate(table_data, headers=headers))
    else:
        print("No suspicious or malicious results found.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_apk.py <apk_file_path>")
        return

    apk_path = sys.argv[1]

    if not os.path.isfile(apk_path):
        print(f"File not found: {apk_path}")
        return

    print("Uploading APK file...")
    file_id = upload_file(apk_path)

    if file_id:
        print("Waiting for analysis...")
        analysis = get_analysis_results(file_id)

        if analysis:
            print("Analysis results:")
            print_analysis_results(analysis)

if __name__ == "__main__":
    main()
