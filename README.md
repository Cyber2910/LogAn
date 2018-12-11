# LogAn

`LogAn` is a tool to analyse SSL apache log files and scan for XSS, SQLi and File inclusion attempts in GET requests.

`LogAn` can also detect privacy leaks in the form of email addresses present in GET requests, POST requests or HTTP referrer headers.

Attacks are detected primarily using regular expressions collated by the OWASP ModSecurity Core Rule Set project.

## Prerequisites
Python version > 3.6 is required. Additionally, a number of extra libraries need to be installed. This can be done using the commands below:
```
pip install ipaddress
pip install ua-parser
pip install regex
pip install configparser
```

## Setup
### Cloning the repository and downloading requisite files
```
git clone https://github.com/shanpandya/LogAn
```
The latest OWASP ModSec rules can be downloaded directly from the OWASP Github page (a copy can also be found on this page in the 'Filters_and_Rule_Sets' folder).
The files required are :
```
REQUEST-930-APPLICATION-ATTACK-LFI.conf
REQUEST-941-APPLICATION-ATTACK-XSS.conf
REQUEST-942-APPLICATION-ATTACK-SQLI.conf
lfi-os-files.data
restricted-files.data
```
These files should all be placed into a folder in the main directory named 'Filters_and_Rule_Sets'.

The latest 'crawler-user-agents.json' file should also be downloaded from:
```
https://github.com/monperrus/crawler-user-agents
```
This file should also be placed in the 'Filters_and_Rule_Sets' folder.

### Parsing the downloaded files
`Setup.py` parses all the downloaded files and creates two folders named `App_data` and `Setup_Files`. The `App_data` folder should be left alone and is required by `LogAn` to run. `Setup_Files` contains 3 files:
- `configuration_file.ini`: The user can edit this configuration file to adjust result filtering
- `false_positive_SQL_regex.txt`: See 'Advanced filtering'
- `false_positive_XSS_regex.txt`: See 'Advanced filtering'


To run `Setup.py`, enter in the terminal/command line:
```
python Setup.py -defaults
```
This will create a configuration file with settings recommended for a first scan of log files

If you would like to create a blank configuration file with all options initially set to false, run `Setup.py` without any command line arguments:
```
python Setup.py
```

## Running
Mark options in 'configuration_file.ini' to `True` to modify scan parameters, then run `LogAn.py`:
```
python LogAn.py DIRECTORY_WHERE_LOG_FILES_ARE_STORED
```
`LogAn` will produce a file named 'Results.txt' with a list of detections.

## Advanced filtering
Advanced filtering options to remove XSS and SQLi false positives are available, and custom regex can be added to 'false_positive_XSS_regex.txt' and 'false_positive_SQL_regex.txt' (these files are created after running `Setup.py`.

Do not delete any lines from the template file. New comments in the file should be prefixed with ';'. By default, the parser will escape special characters. To do this manually for a line, prefix the regular expression with the '~' character.

## Credits
This project was conducted as part of a UROP (Summer Research) placement at Imperial College London under the supervision of Dr Sergio Maffeis.