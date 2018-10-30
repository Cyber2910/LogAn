import configparser
import regex as new_re
import sys
import os

### Create message array and regex array for XSS and SQL detections
message_regex = new_re.compile(r"(?:^\s+\"?msg:)(')(.+)(')")
conf_regex = new_re.compile(r"(?:^SecRule (?:REQUEST_COOKIES|ARGS_NAMES|ARGS).*?\")([^@].+)(\")")

# Check if App_data folder exists and create it if not
if not os.path.exists("App_data"):
    os.makedirs("App_data")

# Print user warning notice
with open("App_data/App_data_README.txt", "w+") as appdat:
    appdat.write("DO NOT EDIT FILES IN THIS DIRECTORY AS THIS MAY CAUSE PROBLEMS WITH THE OPERATION OF LOGAN.PY")

# Function to parse XSS or SQL OWASP conf file. Prints regex and descriptions to outfiles and returns a list of regex descriptions
def OWASP_parser(infile, regex_outfile, description_outfile, conf_regex, message_regex):
    message_list = []
    regFound = False
    with open (infile,"r") as infile:
        with open (regex_outfile, "w+") as XSS_outfile:
            with open(description_outfile, "w+") as XSS_message_outfile:
                for line in infile:
                    regex_match = conf_regex.match(line)
                    if regex_match:
                        regFound=True
                        xss_regex = regex_match.group(1)
                        # print(xss_regex)
                        XSS_outfile.write(xss_regex + "\n")

                    message = message_regex.match(line)
                    if message and regFound:
                        # print(message.group(2))
                        message_list.append(message.group(2))
                        XSS_message_outfile.write(message.group(2)+"\n")
                        regFound=False
    return message_list

if len(sys.argv) > 1:
    command_line_argument = True
else:
    command_line_argument = False

i = -1
default_list = ['True','True','True','', 'True', '', 'True', 'True', 'True', '', 'True', '', '', '', 'True', 'True', 'True', 'True', 'True', '', '0-21', '0-13,17-29,31-33', 'True', 'True', 'True', '','True', '', '', '', '', '', '', '', '', '','', '', '']
def set_defaults(default_list, command_line_argument):
    global i
    i+=1
    if command_line_argument:
        return default_list[i]
    else:
        return ''

XSS_message_list = OWASP_parser("Filters_and_Rule_Sets/REQUEST-941-APPLICATION-ATTACK-XSS.conf", "App_data/XSS_regex.txt", "App_data/XSS_message_file.txt", conf_regex, message_regex)
SQL_message_list = OWASP_parser("Filters_and_Rule_Sets/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "App_data/SQL_regex.txt", "App_data/SQL_message_file.txt", conf_regex, message_regex)

# Create config file
config = configparser.ConfigParser(allow_no_value=True)
config.optionxform = str

config.add_section('Config')
config.set('Config', '; By default LogAn will produce a second results file with duplicate lines removed.')
config.set('Config', '; (lines which have been detected by multiple regular expressions)')
config.set('Config', '; Set options below to true to further process the second results file')
config.set('Config', r'; URL encoding replaced %xx UF8 encodings with ASCII (e.g. %2f is replaced with a space)')

config.set('Config', 'Remove_UTF-8_URL_encoding', set_defaults(default_list, command_line_argument))
config.set('Config', r'; Replace Char(int) or chr(int) expressions with characters e.g. char(88) is replaced with X')

config.set('Config', 'ASCII_encoding_in_get_requests',set_defaults(default_list, command_line_argument))

config.add_section('Display')
config.set('Display', '; Mark \'True\' any parameters you would like displayed in results')
config.set('Display', 'Line_number', set_defaults(default_list, command_line_argument))
config.set('Display', 'Information_avalibility', set_defaults(default_list, command_line_argument))
config.set('Display', 'Client_IP', set_defaults(default_list, command_line_argument))
config.set('Display', 'User_ID', set_defaults(default_list, command_line_argument))
config.set('Display', 'Time', set_defaults(default_list, command_line_argument))
config.set('Display', 'Request_line', set_defaults(default_list, command_line_argument))
config.set('Display', 'Status_code', set_defaults(default_list, command_line_argument))
config.set('Display', 'Size', set_defaults(default_list, command_line_argument))
config.set('Display', 'Referrer', set_defaults(default_list, command_line_argument))
config.set('Display', 'User_Agent', set_defaults(default_list, command_line_argument))
config.set('Display', 'Protacol', set_defaults(default_list, command_line_argument))
config.set('Display', 'Encryption', set_defaults(default_list, command_line_argument))
config.set('Display', 'Print_matched_regex', set_defaults(default_list, command_line_argument))

config.add_section('Detect')
config.set('Detect', '; Mark \'True\' any attack methods you would like logAn to scan for')
config.set('Detect', 'XSS', set_defaults(default_list, command_line_argument))
config.set('Detect', 'SQL', set_defaults(default_list, command_line_argument))
config.set('Detect', 'File_inlcusion', set_defaults(default_list, command_line_argument))
config.set('Detect', 'Email_leaks', set_defaults(default_list, command_line_argument))

config.add_section('Print all')
config.set('Print all', '; Mark \'True\' to print out a list of all log enteries that pass through filters (below)')
config.set('Print all', 'Print_all', set_defaults(default_list, command_line_argument))


config.add_section('XSS_sub')
config.set('XSS_sub', '; This XSS sub filter is only active if Detect, XSS is set to \'True\'')
config.set('XSS_sub', '##################################################################################################')
for index, description in enumerate(XSS_message_list):
    config.set('XSS_sub', '; '+ str(index) + ' ' + description)
config.set('XSS_sub', '##################################################################################################.')
config.set('XSS_sub', '; Agrressiveness of detections filters, or \'Paranoia Levels\' can be found in OWASP documentation')
config.set('XSS_sub', '; as a rough guide filters 0-5 have the lowest false positive rate')
config.set('XSS_sub', '; Enter the range which XSS filters should detect seperated by commas and dashes')
config.set('XSS_sub', '; e.g. entering \'1-5, 8\' will apply regex filter 1 though 5 and regex 8')
config.set('XSS_sub', 'XSS_range', set_defaults(default_list, command_line_argument))


config.add_section('SQL_sub')
config.set('SQL_sub', '; This SQL sub filter is only active if Detect, SQL is set to \'True\'')
config.set('SQL_sub', '##################################################################################################')
for index, description in enumerate(SQL_message_list):
    config.set('SQL_sub', '; '+ str(index) + ' ' + description)
config.set('SQL_sub', '##################################################################################################.')
config.set('SQL_sub', '; Agrressiveness of detections filters, or \'Paranoia Levels\' can be found in OWASP documentation')
config.set('SQL_sub', '; as a rough guide filters 0-13 have the lowest false positive rate')
config.set('SQL_sub', '; Enter the range which SQL filters should detect seperated by commas and dashes')
config.set('SQL_sub', '; e.g. entering \'1-5, 8\' will apply regex filter 1 though 5 and regex 8')
config.set('SQL_sub', 'SQL_range', set_defaults(default_list, command_line_argument))

config.add_section('File inclusion')
config.set('File inclusion', 'Apply_regex_search', set_defaults(default_list, command_line_argument))
config.set('File inclusion', 'OS_files_keyword_search', set_defaults(default_list, command_line_argument))
config.set('File inclusion', 'Other_suspicious_keywords_search', set_defaults(default_list, command_line_argument))
config.set('File inclusion', 'Slash_search_in_query', set_defaults(default_list, command_line_argument))
config.set('File inclusion', 'URL_and_file_extension_query', set_defaults(default_list, command_line_argument))

config.add_section('IP')
config.set('IP', '; Enter a comma seperated list of IP\'s in CIDR notation (e.g. to filter out all Imperial IP addresses enter: \'146.169.0.0/16, 155.198.0.0/16, 129.31.0.0/16, 146.179.0.0/16, 192.156.162.0/24\')')
config.set('IP',  'Filter_type', set_defaults(default_list, command_line_argument))

config.add_section('UA')
config.set('UA', '; Mark True to remove particular user agents from results')
config.set('UA', 'Bots', set_defaults(default_list, command_line_argument))
config.set('UA', 'Firefox', set_defaults(default_list, command_line_argument))
config.set('UA', 'Chrome', set_defaults(default_list, command_line_argument))
config.set('UA', 'Chromium', set_defaults(default_list, command_line_argument))
config.set('UA', 'Safari', set_defaults(default_list, command_line_argument))
config.set('UA', 'Opera', set_defaults(default_list, command_line_argument))
config.set('UA', 'Other', set_defaults(default_list, command_line_argument))

config.add_section('Time')
config.set('Time', '; Enter a comma seperated list of dates you would like to filter in the form dd/MMM/yyyy e.g. 26/Jun/2017, 27/Jun/2017')
config.set('Time', 'Date_range',set_defaults(default_list, command_line_argument))

config.set('Time', '; Enter the time range you would like to filter in the form HH:mm:ss - HH:mm:ss e.g. 01:53:59 - 02:54:03')
config.set('Time', 'Time_range', set_defaults(default_list, command_line_argument))

config.add_section('Referrer')
config.set('Referrer', '; Enter a comma seperated list of domains to exclude all other refferes e.g. entering \'google.com\' will only show results reffered by google.com/*')
config.set('Referrer', 'Ref', set_defaults(default_list, command_line_argument))

config.add_section('Status Code')
config.set('Status Code', '; Enter a comma seperated list of status codes that will be included in results, or leave blank allow all status codes')
config.set('Status Code', 'Code', set_defaults(default_list, command_line_argument))

# create setup files directory if it doesn't exist
if not os.path.exists("Setup_Files"):
    os.makedirs("Setup_Files")


# Write config file
with open("Setup_Files/configuration_file.ini", "w+") as configfile:
    config.write(configfile)

# Write false positive regex file
with open("Setup_Files/false_positive_XSS_regex.txt","w+") as f:
    f.write('; Insert regex for strings to ignore under each regex filter description\n')
    f.write('; The parser will escape special characters by default. To do this manually for a line prefix the regular expression with the \'~\' character\n')
    f.write('; Prefix any comment line with the \';\' character\n')
    for index, element in enumerate(XSS_message_list):
        f.write('# ' + str(index) + ' ' + element + '\n\n\n')
    # f.write('-----------------------------------------------\n')
    # for index, element in enumerate(SQL_message_list):
    #     f.write('# ' + str(index) + ' ' + element + '\n\n\n')
    
with open("Setup_Files/false_positive_SQL_regex.txt","w+") as f:
    f.write('; Insert regex for strings to ignore under each regex filter description\n')
    f.write('; The parser will escape special characters by default. To do this manually for a line prefix the regular expression with the \'~\' character\n')
    f.write('; Prefix any comment line with the \';\' character\n')
    for index, element in enumerate(SQL_message_list):
        f.write('# ' + str(index) + ' ' + element + '\n\n\n')