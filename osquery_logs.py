import json
import os
import pickle
import re
import sys
from datetime import datetime
from syslog import syslog

from rich.console import Console
from rich.table import Table

from send_email import send_email

TODAYS_DATE = datetime.date(datetime.today()).strftime('%Y-%m-%d')
PICKLE_FILE = 'osquery.pickle'
OSQUERY_LOGFILE = '/var/log/osquery/osqueryd.results.log'
RESULTS_FILE = 'fim_logs.txt'

ro = re.compile(r'^{"name":"pack_fim_file_events"')

# Needed for email
subject = "OSQuery File Integrity Management Logs"
sender = "<CHANGEME>"
recipient = ["CHANGEME"]
body = f"OSQuery File Integrity Management Logs for {TODAYS_DATE}"

for i in PICKLE_FILE, RESULTS_FILE:
    try:
        os.remove(i)
    except OSError as e:
        print(f"{repr(e)} : {i}")
        print("Continuing...")

osquery_logs = []
try:
    with open(OSQUERY_LOGFILE, 'r') as f:
        for line in f:
            if m := ro.search(line):
                osquery_logs.append(line)
except OSError as e:
    print(f"{repr(e)} : {OSQUERY_LOGFILE}")
    print("Exiting...")
    sys.exit()

with open(PICKLE_FILE, 'wb') as pickle_file:
     pickle.dump(osquery_logs, pickle_file)

with open(PICKLE_FILE, 'rb') as pickled:
     logs = pickle.load(pickled)

table = Table()
table.show_lines=True
table.add_column("USERNAME", justify="left", style="blue")
table.add_column("DATE", justify="left", style="blue")
table.add_column("FILENAME", justify="left", style="blue")
table.add_column("ACTION", justify="left", style="blue")

data = []
for i in range(len(logs)):
    data.append(json.loads(logs[i]))
    table.add_row(data[i]['decorations']['username'].split('@')[0], 
                  data[i]['calendarTime'], 
                  data[i]['columns']['target_path'],
                  data[i]['columns']['action'])

console = Console(record=True)
console.print(table)
console.save_text(RESULTS_FILE)

send_email(subject, sender, recipient, body, RESULTS_FILE)

syslog(f"[INFO] {sys.argv[0].split('/')[-1]} completed")
