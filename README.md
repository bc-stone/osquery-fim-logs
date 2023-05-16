# osquery-fim-logs
### Retrieve file integrity monitoring logs from Osquery running on a Linux host

For organizations already running Osquery with the file integrity monitoring pack enabled, this script will retrieve those logs (filtered by username, date, filename and action) from a Linux host.  It sends the results in tabular format as an email attachment to one or more recipients.  Based on the number of files and directories being monitored, the results file can become quite large.

The ```send_email.py``` module in this repo uses a site-specific SMTP server identified by environment variables on the local system.

Also in the repo is ```osquery_logs.sh``` - a bash wrapper script that can be used as a model for running from cron.
