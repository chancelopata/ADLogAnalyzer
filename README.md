# ADLogAnalyzer.py
This command line tool was created to assist in finding interesting information inside of AD interactive sign-in log files.
"Interesting" information is data that...
-   Is Potentially malicious
-   Helps a user get an idea of what is considered "normal" traffic

The program does this by allowing more specific queries to be made on log data than AAD normally allows and by exporting some information to excel sheets so they can be viewed.

By default 3 sheets are created.
- filtered: all the logs with filters applied.
- dangerous countries: all logs that originate from a "dangerous country".
- failed sign-ins: All failed sign in attempts grouped by user and summed up together based on the origional IP.

The user can optionally provide an API key from abuseIPDB and then sheet 3 will have additional data.