# Assignment-2

*Project overview*
This project i have made is a python based comand line tool.

What this tool does for my project is scans a list of targets i have listed such as nmap.scanme.org and example.com and it: 

Performs TCP connect scans against ports i have specified.
Identifies open, closed and filtered ports.
Performs HTTP probing on port 80.
Performs TLS certificate inspection on port 443.
Collects basic banner-style information from HTTP headers and TLS certificates.
Outputs structured files for JSON and CSV.

This tool i have made is simple and reliable to be used against targets using only python standard libraries.

*Requirements*

Libraries used:
argparse
socket
ssl
datetime
json
csv
re
time

I did not use any external libraries.

*Running the code*
To run my code you will need to enter this into this command line: python3 recon.py --targets targets.txt --ports 80,443 --http --tls

First i specify the python file to be ran.
Second i target the targets.txt file with my targets nmap.scanme.org and example.com.
Third i sepecify the ports 80 commonly used for HTTP services and 443 commonly used for HTTPS/TLS services.
Enables HTTP probing on discovered services, extracting information.
Enables TLS certificate inspection on services that support TLS.

And ensure that there are targets withing the targets.txt file so that the command can run.

*Features*













References: 
https://docs.python.org/3/library/argparse.html
https://www.geeksforgeeks.org/command-line-arguments-in-python/
https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files
https://realpython.com/read-write-files-python/
https://docs.python.org/3/library/stdtypes.html#str.split
https://stackoverflow.com/questions/4726168/parsing-command-line-input-for-port-ranges
https://docs.python.org/3/library/socket.html
https://www.geeksforgeeks.org/python/port-scanner-using-python/
https://realpython.com/python-sockets/
https://stackoverflow.com/questions/1767910/banner-grabbing-with-python
https://docs.python.org/3/library/socket.html#socket.socket.recv
https://stackoverflow.com/questions/4091573/python-socket-send-receive-http-request
https://docs.python.org/3/library/ssl.html
https://stackoverflow.com/questions/7689941/how-can-i-retrieve-the-tls-ssl-peer-certificate-of-a-remote-host-using-python
https://docs.python.org/3/library/datetime.html
https://docs.python.org/3/library/json.html
https://realpython.com/python-json/
https://docs.python.org/3/library/csv.html
https://realpython.com/python-csv/
Example code used from labs from lab 4.2 and 3.1 from mark cummins files.
Example code used from Assignemnt 2 brief from mark cummmins files.