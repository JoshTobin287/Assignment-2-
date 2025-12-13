# Assignment-2

Name: Josh Tobin
Student ID: C00309712

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

TCP connect scan(not raw SYN):

Performs a standard TCP connect scan.
Identfies port states as open, closed or filtered.
Records timeout status

Banner collection: 

For open ports, reads intial banner up to 4096 bytes and uses a non blocking recv with configure timeout
Saves raw banner in results

HTTP probing:

Performs on port 80 and sends a basic HTTP GET request.
Extracts HTML title, desctiption and server header
Used as banner style identifiers

TLS certificate analysis:

Performs on port 443 and establishes a tls connection
Extracts subject cn, certificate expiry and expiry status at runtime
TLS certificate fields are used as banner-style identifiers

Fingerprint web-application / CMS heuristic:

This was attempted but ultimately did not make it into my final version of my project.

Structured output:

Json output - Results are stored per target and per port including port status, http metadate, tls certificate details and banner style infromation from HTTP or TLS

CSV output - Each row represents a scanned port and includes host, port, status, banner, http title, server header and meta decription and tls subject CN and expiry status 

Concurrency and rate control:

This was partially implemented into my project no workers were used and other features, although no crashes on network and retires implemented but no resume support

 Other features that were either limited, attempted or not implmented in my project: 

Concurency and worker pool usage
Raw socket banner grabbing for non-HTTP services
HTTP redirect following
Cookie collection or response body sampling
TLS chain verification or weak cipher detection
Web application fingerprinting 
Resume or retry functionality
Rate limiting

*Reflection*

This project was quite difficult and challenging, a lot of struggle was had with most part of  the project, i could have improved and applied extra features and features i didnt implment but i could not figure them out.


*References:*
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