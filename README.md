# BugBusterX | Android Virus Scanner

This is a simple script to scan an APK or EXE file for viruses and malware using the VirusTotal API.
## Prerequisites

Before you can use this script, make sure you have the following:

1. An Android device with Termux installed. You can download Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the [Google Play Store](https://play.google.com/store/apps/details?id=com.termux&pli=1).
2. A Virustotal account and API key, which you will have to insert into the code under `API_KEY`
3. Git and Python installed on your Android device via Termux. Open Termux and run the following commands:

```bash
pkg update
pkg upgrade
pkg install git
pkg install python
```
Set up an SSH key on your Android device so that you can clone the repository from GitHub. Follow these instructions to generate an SSH key and add it to your GitHub account.

## Installation

Once you have the prerequisites set up, clone the repository:

```bash
git clone git@github.com:PapaPeskwo/BugBusterX.git
```

Navigate to the cloned repository directory:

```bash
cd BugBusterX
```
And install the requirements:
```bash
pip install -r requirements.txt
```
## Usage

To scan an APK or EXE file, run the following command:

```bash
python BugBusterX.py /path/to/your/file.apk
```
Replace /path/to/your/file.apk with the actual path to the APK or EXE file you want to scan.

The script will upload the file to VirusTotal, wait for the analysis to complete, and display the results. If the file is safe, it will display "The file is safe." Otherwise, it will display the results from any antivirus engines that detected the file as suspicious or malicious.

## License
This project is licensed under the MIT License. See the LICENSE file for details.