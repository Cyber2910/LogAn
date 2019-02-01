import sys
import os
import time
from ipaddress import IPv4Address, IPv4Network
from ua_parser import user_agent_parser
import regex as new_re
import urllib
from urllib.parse import urlparse
from datetime import datetime
import errno
import shutil

from configparser import SafeConfigParser
import json

## Check that a command line argument was provided
try:
    if sys.argv[1]:
        pass
except IndexError:
    print("Please enter the directory where logs are stored as a command line argument")
    exit()

parser = SafeConfigParser()
parser.read('Setup_files/configuration_file.ini')
json_data=open('Filters_and_Rule_Sets/crawler-user-agents.json').read()
bot_data = json.loads(json_data)


# Create results directory
if not os.path.exists("Results"):
    os.makedirs("Results")

results_dir = os.path.join(os.getcwd() + '/Results',datetime.now().strftime('%d-%m-%Y_%H-%M-%S'))
try:
    os.makedirs(results_dir)
except OSError as e:
    if e.errno != errno.EEXIST:
        raise  # This was not a "directory exist" error..

# Copy settings to the result directory
shutil.copytree('Setup_Files', results_dir + '/Setup_Files_used_for_run')
shutil.copytree('App_data', results_dir + '/App_data_used_for_run')

f = open(results_dir + "/Results.txt", "w+")
fp = open(results_dir + "/False_positive_results.txt", "w+")

# Parse CONFIG
URL_encoding = parser.get("Config", "Remove_UTF-8_URL_encoding")
ASCII_encoding_in_get_requests = parser.get("Config", "ASCII_encoding_in_get_requests")



# Parse DISPLAY
Line_number = parser.get("Display", "Line_number")
Client_IP = parser.get("Display", "Client_IP")
Information_avalibility = parser.get("Display", "Information_avalibility")
User_ID = parser.get("Display", "User_ID")
Time = parser.get("Display", "Time")
Request_line = parser.get("Display", "Request_line")
Status_code = parser.get("Display", "Status_code")
Size = parser.get("Display", "Size")
Ref_display = parser.get("Display", "Referrer")
User_Agent = parser.get("Display", "User_Agent")
Protacol = parser.get("Display", "Protacol")
Encryption = parser.get("Display", "Encryption")

regex_print_option = parser.get("Display", "Print_matched_regex")

# Parse DETECT
XSS = parser.get("Detect", "XSS")
SQL = parser.get("Detect", "SQL")
File_inlcusion = parser.get("Detect", "File_inlcusion")
Email_leaks = parser.get("Detect", "Email_leaks")

# Parse Print All
Print_all = parser.get("Print all","Print_all")

# Parse XSS range
XSS_range = parser.get("XSS_sub", "XSS_range")

# Parse SQL range
SQL_range = parser.get("SQL_sub", "SQL_range")
# Parse File inclusion

Apply_regex_search = parser.get("File inclusion", "Apply_regex_search")
OS_files_keyword_search = parser.get("File inclusion", "OS_files_keyword_search")
Other_suspicious_keywords_search = parser.get("File inclusion", "Other_suspicious_keywords_search")
Slash_search_in_query = parser.get("File inclusion", "Slash_search_in_query")
URL_and_file_extension_query = parser.get("File inclusion", "URL_and_file_extension_query")

# Parse IP
Filter_type = parser.get("IP", "Filter_type")

# Parse UA
Bots = parser.get("UA", "Bots")
Firefox = parser.get("UA", "Firefox")
Chrome = parser.get("UA", "Chrome")
Chromium = parser.get("UA", "Chromium")
Safari = parser.get("UA", "Safari")
Opera = parser.get("UA", "Opera")
Other = parser.get("UA", "Other")

# Parse Time
Date_range = parser.get("Time", "Date_range")
Time_range = parser.get("Time", "Time_range")

# Parse referrer
Ref = parser.get("Referrer", "Ref")

# Parse status code
user_status_string = parser.get("Status Code", "Code")






# Functions
# initiate_display_options(Client_IP,Information_avalibility,User_ID,Time,Request_line,Status_code,Size,referrer,User_Agent,Protacol,Encryption)
def initiate_display_options(*args):
    display_options = []
    for arg in args:
        display_options.append(arg)
    return display_options

def print_line(line_no_bool, line_no, display_options,*args):
    if line_no_bool:
        tempstr = "Line number " + str(line_no) + ": "
    else:
        tempstr = ""
    for j, arg in enumerate(args):
        if display_options[j]:
            tempstr = tempstr + arg + " "
    return tempstr.rstrip()

query_string_regex = new_re.compile(r"(?:.*?\?.*?=)(.+)(\")")
# Function to check if a line of get request matches specified regex. If it does, the function adds the get request line to a list
def xss_sql_attack_detect(Entry, line_no, display_options, xss = False, sql = False):
    global xss_list
    global xss_detections_list
    global sql_list
    global sql_detections_list
    global xss_false_detections_list
    global sql_false_detections_list


    match_found = query_string_regex.match(Entry.get_req)
    if match_found:
        query_string = match_found.group(1)
        if xss:
            for element in output_list:
                false_pos_flag = False
                if XSS_false_positives_list[element]:
                    for expression in XSS_false_positives_list[element]:
                        if expression.search(Entry.get_req) and xss_list[element].search(query_string):
                            xss_false_detections_list[element].append(print_line(Line_number, line_no, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
                            false_pos_flag = True
                if not false_pos_flag and xss_list[element].search(query_string):
                        xss_detections_list[element].append(print_line(Line_number, line_no, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))

        
        if sql:            
            for element in output_sql_list:
                false_pos_flag = False
                if SQL_false_positives_list[element]:
                    for expression in SQL_false_positives_list[element]:
                        if expression.search(Entry.get_req) and sql_list[element].search(query_string):
                            sql_false_detections_list[element].append(print_line(Line_number, line_no, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
                            false_pos_flag = True
                if not false_pos_flag and sql_list[element].search(query_string):
                    sql_detections_list[element].append(print_line(Line_number, line_no, display_options,Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
        
    return

# Function to detect email leaks in the string passed in
emails_detect_regex = new_re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
# mode = 1 to search for leaks in get request, mode = 2 to search for leaks in referrer
def emails_detect(mode, Entry, line_no, regex):
    if mode == 1:
        search_loc = Entry.get_req
    elif mode == 2:
        search_loc = Entry.referrer

    if regex.search(search_loc):
            return True
    return False

# Function to detect path requests in QS
path_query_regex = new_re.compile(r"(?:.+?\?.*?=)(.*?\/[^.]*)?(?:HTTP)")
def path_query(get_req, line_no, path_query_regex):
    if path_query_regex.match(get_req):
        return True
    else:
        return None

url_and_extension_regex = new_re.compile(r"(?:.+?\?.*?=)(?i:http[s]?)(.+\.(([a-b,d-z][a-z][a-z][\s])|js))")
# Function to detect URL and file in query string
def URL_and_file_extension_func(get_req):
    match_found = url_and_extension_regex.search(get_req)
    if match_found:
        return True
    else:
        return False



# Function that takes in a file containing suspicious file paths and comapres with a get request. Returns true if match. The 3rd argument is whether to search OS files(1) or other restricted files(2) )
def path_checker(get_or_post_req, option):
        if option == 1:
            for regex in os_path_regex:
                if regex.search(get_or_post_req):
                    return True
            return False
        elif option == 2:    
            for regex in restricted_files_regex:
                if regex.search(get_or_post_req):
                    return True
            return False

# Function to check get req against OWASP file inclusion regex
path_traversal_regex = new_re.compile(r"(?i)(?:\x5c|(?:%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|\/))(?:%(?:(?:f(?:(?:c%80|8)%8)?0%8|e)0%80%ae|2(?:(?:5(?:c0%25a|2))?e|%45)|u(?:(?:002|ff0)e|2024)|%32(?:%(?:%6|4)5|E)|c0(?:%[256aef]e|\.))|\.(?:%0[01]|\?)?|\?\.?|0x2e){2}(?:\x5c|(?:%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|\/))")
path_traversal_regex_disp = r"(?i)(?:\x5c|(?:%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|\/))(?:%(?:(?:f(?:(?:c%80|8)%8)?0%8|e)0%80%ae|2(?:(?:5(?:c0%25a|2))?e|%45)|u(?:(?:002|ff0)e|2024)|%32(?:%(?:%6|4)5|E)|c0(?:%[256aef]e|\.))|\.(?:%0[01]|\?)?|\?\.?|0x2e){2}(?:\x5c|(?:%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|\/))"
def path_traversal_detect(get_req, path_traversal_regex):
    if path_traversal_regex.search(get_req):
        return True


# Function to create a list of regular expressions to detect bots from the json file
def bot_regex(data):
    bot_reg = []
    for i in range(0, len(data)):
        bot_reg.append(new_re.compile(r'%s'%data[i]["pattern"]))
    return bot_reg

# Function to parse status code(s) from conf file
def parse_status_code(user_status_string):
    status_list = new_re.sub(r'\s', '', user_status_string).split(',')
    return status_list

# Function to parse user date input and create date regex
def date_regex_create(user_date):
    user_date = user_date.replace('/', '\/')
    date_regex = new_re.compile(r""+user_date)
    return date_regex

def time_filter(date_and_time, time_capture_regex, user_time_range):
  time = time_capture_regex.match(date_and_time).group(1)
  time = new_re.sub(r':','', time)
  user_time_range = new_re.sub(r'\s', '', user_time_range)
  user_time_range = new_re.sub(r':', '', user_time_range).split('-')
  if time > user_time_range[0] and time < user_time_range[1]:
    return True
  else:
    return False

def bot_detect(UA, bot_reg):
    for entry in bot_reg:
        if entry.search(UA):
            return True
    return False

ip_regex = new_re.compile(r"[\d][\d][\d]?\.[\d]?[\d]?[\d]?\.[\d]?[\d]?[\d]?\.[\d]?[\d]?[\d]?")
def ip_filter(log_ip_address, IP_list):
    if ip_regex.match(log_ip_address) is None:
        return False

    for ip in IP_list:
        if IPv4Address(log_ip_address) in IPv4Network(ip):
            return True
        else:
            return False

def ua_filter(ua_string, Chrome, Firefox, Chromium, Safari, Opera, Other):
    if Chrome or Firefox or Chromium or Safari or Opera or Other:
        parsed_string = user_agent_parser.ParseUserAgent(ua_string)['family']
        if Chrome and parsed_string == "Chrome":
            return False
        elif Firefox and parsed_string == "Firefox":
            return False
        elif Safari and parsed_string == "Safari":
            return False
        elif Opera and parsed_string == "Opera":
            return False
        elif Other and (parsed_string != "Chrome" and  parsed_string != "Firefox" and parsed_string != "Safari" and parsed_string != "Opera"):
            return 2
    return True



referrer_list = new_re.sub('\s', '', Ref).split(',')
def create_referrer_list_regex(referrer_list):
    temp_list = []
    for element in referrer_list:
        temp_list.append(new_re.compile(r""+element))
    return temp_list

referrer_list = create_referrer_list_regex(referrer_list)



def referrer_filter(referrer, referrer_list):
    for pattern in referrer_list:
        if pattern.search(referrer):
            return True
    return False

# Function to create regex for detecting false positive regex from file
def create_regex_from_file(file):
    regex_list = []
    with open(file, "r") as infile:
        for line in infile:
            regex_list.append(new_re.compile(""+line))
    return regex_list

# Function to check if a line matches particular regex
def regex_check(line, regex_list):
    for entry in regex_list:
        if entry.search(line):
            return True
        return False

# Function to apply all required filters to output. Returns true is no filters matched/if filters aren't active
def Filters(status_list, status_in_request, date_regex, date_and_time, time_capture_regex, user_time_range, UA, bot_reg, log_ip_adress, IP_list, Filter_type, referrer, referrer_list):
    bot_reg_run = False
    if status_list:
        # print("status list")
        filter = False
        for status in status_list:
            if status == status_in_request:
                filter = True
                break
        if not filter:
            return False

    if date_regex:
        # print("date regex")
        filter = False
        for date in date_regex:
            if date.search(date_and_time):
                filter = True
                break
        if not filter:
            return False

    if user_time_range:
        # print("time range")
        if time_filter(date_and_time, time_capture_regex, user_time_range) == False:
            return False
    
    if Filter_type:
        if ip_filter(log_ip_adress, IP_list):
            return False

    if Ref:
        if referrer_filter(referrer, referrer_list):
            return False

    if bot_reg:
        bot_reg_run = True
        if bot_detect(UA, bot_reg):
            return False
        
    if Chrome or Firefox or Chromium or Safari or Opera or Other:
        ua_filter_output = ua_filter(UA, Chrome, Firefox, Chromium, Safari, Opera, Other)
        if ua_filter_output == 2:
            if bot_reg_run == True:
                return False
            elif not bot_detect(UA, bot_reg):
                return False
        elif not ua_filter_output:
            return False
        
    return True

def print_detections(write_file, heading_string, detections_list, regex_print_option = False ,regex_list = None, is_nested_list = False):
        write_file.write("\n")
        write_file.write(heading_string + '\n')
        dashes = '=' * len(heading_string)
        write_file.write(dashes+ '\n')
        if is_nested_list:
            at_least_one_found = False
            for index, element in enumerate(detections_list,0):
                if len(element)>1:
                    write_file.write("\n")
                    write_file.write(str(index) + " ")
                    at_least_one_found = True
                    for i, entry in enumerate(element):
                        write_file.write(entry + '\n')
                        if i == 0:
                            if regex_print_option:
                                write_file.write(r"" + regex_list[index] + '\n')
                                write_file.write('-'*70)
                                write_file.write('\n')
                            else:
                                write_file.write('-'*(len(entry) + len(str(index) + 1)))
                                write_file.write('\n')
            if not at_least_one_found:
                write_file.write("NONE" + '\n')
        else:
            if detections_list:
                if regex_print_option:
                        write_file.write(regex_list + '\n')
                for line in detections_list:
                    write_file.write(line + '\n')
            else:
                write_file.write("NONE" + '\n')




# Create regular expressions for bot detections if bot filtering is on
if Bots:
    bot_reg = bot_regex(bot_data)
else:
    bot_reg = None

# Create list of status codes if status code filtering is on
if user_status_string:
    status_list = parse_status_code(user_status_string)
else:
    status_list = None

# Create list of ip addresses if ip filtering is on

IP_list = new_re.sub('\s', '', Filter_type).split(',')

# Create date regex if date filtering is on
user_date = Date_range
if user_date:
    date_regex = date_regex_create(user_date)
else:
    date_regex = None

# Create time regex if time filtering is on
user_time = parser.get("Time", "Time_range")
time_capture_regex = None
if user_time:
    time_capture_regex = new_re.compile(r"(?:.*?:)([\d][\d]:[\d][\d]:[\d][\d])")

# Parse XSS regex if XSS is true in config file
if XSS:
    xss_list = []
    xss_detections_list = []
    xss_false_detections_list = []
    xss_disp_list = []
    with open ("App_data/XSS_regex.txt","r") as XSS_regex_file:
        for line in XSS_regex_file:
            stripped_line = line.rstrip()
            xss_disp_list.append(stripped_line)
            xss_list.append(new_re.compile(r'%s'%stripped_line))

    with open ("App_data/XSS_message_file.txt","r") as XSS_message_file:
        for line in XSS_message_file:
            stripped_line = line.rstrip()
            xss_detections_list.append([stripped_line])
            xss_false_detections_list.append([stripped_line])
    


    # Create a list of XSS to use based on config file
    range_pattern = new_re.compile(r"(^[\d][\d]?)(?:-)([\d][\d]?)")
    #Splits the comma seperated user input into a list
    user_list = new_re.sub(r'\s', '', XSS_range).split(',')
    output_list = []
    # Checks if the user input is a range (e.g. 0-10) or a single digit and adds to a list
    for element in user_list:
        is_match = range_pattern.match(element)
        if is_match:
            start_range= int(is_match.group(1))
            end_range=int(is_match.group(2))
            output_list.extend(list(range(start_range,end_range+1)))
        else:
            a = int(element)
            output_list.append(a)
    # Remove duplicates and sort list
    output_list = sorted(set(output_list))

# Parse SQL regex if SQL is true in config file
if SQL:
    sql_list = []
    sql_detections_list = []
    sql_disp_list = []
    sql_false_detections_list = []
    with open ("App_data/SQL_regex.txt","r") as SQL_regex_file:
        for line in SQL_regex_file:
            stripped_line = line.rstrip()
            sql_list.append(new_re.compile(r'%s'%stripped_line))
            sql_disp_list.append(r'%s'%stripped_line)
    with open("App_data/SQL_message_file.txt", "r") as SQL_message_file:
        for line in SQL_message_file:
            stripped_line = line.rstrip()
            sql_detections_list.append([stripped_line])
            sql_false_detections_list.append([stripped_line])


    sql_detections_list_template = sql_detections_list.copy()

    # Choose SQL regex to use if custom configuration option chosen
    
    if SQL_range:
        range_pattern = new_re.compile(r"(^[\d][\d]?)(?:-)([\d][\d]?)")
        #Splits the comma seperated user input into a list
        user_list = new_re.sub(r'\s', '', SQL_range).split(',')
        output_sql_list = []
        # Checks if the user input is a range (e.g. 0-10) or a single digit and adds to a list
        for element in user_list:
            is_match = range_pattern.match(element)
            if is_match:
                start_range= int(is_match.group(1))
                end_range=int(is_match.group(2))
                output_sql_list.extend(list(range(start_range,end_range+1)))
            else:
                a = int(element)
                output_sql_list.append(a)
        # Remove duplicates and sort list
        output_sql_list = sorted(set(output_sql_list))
    else:
        output_sql_list = list(range(0, len(sql_detections_list)))

# Create false positives XSS list
if XSS:
    XSS_false_positives_list = [[] for i in range(len(xss_detections_list))]
    with open ("Setup_files/false_positive_XSS_regex.txt", "r") as infile:
        index = 0
        for line in infile:
            line = line.strip()
            if not line.startswith(';'):
                if line.startswith('#'):
                    index += 1
                elif line.startswith('~'):
                    line = line[1:]
                    XSS_false_positives_list[index-1].append(new_re.compile((r''+line)))
                elif line:
                    XSS_false_positives_list[index-1].append(new_re.compile(new_re.escape(r''+line)))

# Create false positives SQL list
if SQL:
    SQL_false_positives_list = [[] for i in range(len(sql_detections_list))]
    with open ("Setup_files/false_positive_SQL_regex.txt", "r") as infile:
        index = 0
        for line in infile:
            line = line.strip()
            if not line.startswith(';'):
                if line.startswith('#'):
                    index += 1
                elif line.startswith('~'):
                    line = line[1:]
                    SQL_false_positives_list[index-1].append(new_re.compile((r''+line)))
                elif line:
                    SQL_false_positives_list[index-1].append(new_re.compile(new_re.escape(line)))


# Initialise storage lists
emails_get_list = []
emails_referrer_list = []
path_list = []
os_path_list = []
restricted_files_list = []
file_inlcusion_regex_list = []
url_and_extension_list = []


 
# Parse restricted file access attemps data files
if OS_files_keyword_search:
    # Initialise lists to store regex
    os_path_regex = []
    restricted_files_regex = []
    with open ("Filters_and_Rule_Sets/lfi-os-files.data","r") as infile:
        for line in infile:
            if line[0] != "#":
                line = new_re.sub('\n', '', line)
                line = new_re.sub('\s', '%20', line)
                os_path_regex.append(new_re.compile(new_re.escape(line)))
                
if Other_suspicious_keywords_search:
    with open ("Filters_and_Rule_Sets/restricted-files.data","r") as infile:
        for line in infile:
            if line[0] != "#":
                line = new_re.sub('\n', '', line)
                line = new_re.sub('\s', '%20', line)
                restricted_files_regex.append(new_re.compile(new_re.escape(line)))


# Create class
class Entry():
    def __init__(self, ip, availibility, user_id, time, get_req, status_code, size, referrer, user_agent, protacol, encryption):
        self.ip = ip
        self.availibility = availibility
        self.user_id = user_id
        self.time = time #time at request completion
        self.get_req = get_req
        self.status_code = status_code
        self.size = size
        self.referrer = referrer
        self.user_agent = user_agent
        self.protacol = protacol
        self.encryption = encryption
file_processed = None


#Initiate display options
display_options = initiate_display_options(Client_IP,Information_avalibility,User_ID,Time,Request_line,Status_code,Size,Ref_display, User_Agent)

# Set the directory you want to start from
rootDir = '.'
if sys.argv[1].startswith('/'):
    folder = str(sys.argv[1])[1:]
else:
    folder = sys.argv[1]

pattern = new_re.compile(r'^(\S*|\S*\,\s\S+) (\S+) (\S+(?:\s+)?) (\[.+?\]) (\"(GET|HEAD|POST|PROPFIND|-|OPTIONS|PUT|PATCH|quit).*?\") (\d{3}) (\S+) ((\".*?\")) (\".*?\")')

f.write(r"""                                                                                                                                                                                                       
LLLLLLLLLLL                                                                 AAA                                 
L:::::::::L                                                                A:::A                                
L:::::::::L                                                               A:::::A                               
LL:::::::LL                                                              A:::::::A                              
  L:::::L                  ooooooooooo      ggggggggg   ggggg           A:::::::::A           nnnn  nnnnnnnn    
  L:::::L                oo:::::::::::oo   g:::::::::ggg::::g          A:::::A:::::A          n:::nn::::::::nn  
  L:::::L               o:::::::::::::::o g:::::::::::::::::g         A:::::A A:::::A         n::::::::::::::nn 
  L:::::L               o:::::ooooo:::::og::::::ggggg::::::gg        A:::::A   A:::::A        nn:::::::::::::::n
  L:::::L               o::::o     o::::og:::::g     g:::::g        A:::::A     A:::::A         n:::::nnnn:::::n
  L:::::L               o::::o     o::::og:::::g     g:::::g       A:::::AAAAAAAAA:::::A        n::::n    n::::n
  L:::::L               o::::o     o::::og:::::g     g:::::g      A:::::::::::::::::::::A       n::::n    n::::n
  L:::::L         LLLLLLo::::o     o::::og::::::g    g:::::g     A:::::AAAAAAAAAAAAA:::::A      n::::n    n::::n
LL:::::::LLLLLLLLL:::::Lo:::::ooooo:::::og:::::::ggggg:::::g    A:::::A             A:::::A     n::::n    n::::n
L::::::::::::::::::::::Lo:::::::::::::::o g::::::::::::::::g   A:::::A               A:::::A    n::::n    n::::n
L::::::::::::::::::::::L oo:::::::::::oo   gg::::::::::::::g  A:::::A                 A:::::A   n::::n    n::::n
LLLLLLLLLLLLLLLLLLLLLLLL   ooooooooooo       gggggggg::::::g AAAAAAA                   AAAAAAA  nnnnnn    nnnnnn
                                                     g:::::g                                                    
                                         gggggg      g:::::g                                                    
                                         g:::::gg   gg:::::g                                                    
                                          g::::::ggg:::::::g                                                    
                                           gg:::::::::::::g                                                     
                                             ggg::::::ggg                                                       
                                                gggggg                                                          
                                                       
""")
f.write("- Log File Analyser\n\n")
fp.write("FALSE POSITIVE RESULTS (FILTERED OUT BY REGEX FROM RESULTS.TXT\n\n")
print_all_file = open(results_dir + "/Print_all_with_filters.txt", "w+")
for dirName, subdirList, fileList in os.walk(rootDir + '/' + folder):
    print('Found directory: %s' % dirName)
    f.write("Logs Processed:\n")
    f.write("==============\n")
    fp.write("Logs Processed:\n")
    fp.write("==============\n")
    for fname in fileList:
        if not fname.endswith('.DS_Store') and not fname.endswith('.gz'):
            f.write(fname + '\n')
            fp.write(fname + '\n')
            print(folder +'/'+fname)
            with open(rootDir + '/' + folder +'/'+fname, "r") as infile:
                
                for j, line in enumerate(infile,1):
                    try:
                        match = pattern.search(line)
                        Entry.ip = match.group(1)
                        Entry.availibility = match.group(2)
                        Entry.user_id = match.group(3)
                        Entry.time = match.group(4)
                        Entry.get_req = match.group(5)
                        Entry.status_code = match.group(7)
                        Entry.size = match.group(8)
                        Entry.referrer = match.group(10)
                        Entry.user_agent = match.group(11)
                        # print(Entry.user_agent)
                        # Entry.protacol = match.group(12)
                        # Entry.encryption = match.group(13)
                        # Entry_Log.append(Entry)
                        # print(j)


                        if Filters(status_list, Entry.status_code, date_regex, Entry.time, time_capture_regex, Time_range, Entry.user_agent, bot_reg, Entry.ip, IP_list, Filter_type, Entry.referrer, referrer_list):
                            if Print_all:
                                print_all_file.write(print_line(Line_number, j, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent) + '\n')

                            xss_sql_attack_detect(Entry, j, display_options, XSS, SQL)

                            if Email_leaks:
                                if emails_detect(1, Entry, j, emails_detect_regex):
                                    emails_get_list.append(print_line(Line_number, j, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
                                if emails_detect(2, Entry, j, emails_detect_regex):
                                    emails_referrer_list.append(print_line(Line_number, j, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
                        
                            if File_inlcusion:
                                if OS_files_keyword_search and path_checker(Entry.get_req, 1):
                                    os_path_list.append(print_line(Line_number, j, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
                                if Other_suspicious_keywords_search and path_checker(Entry.get_req, 2):
                                    restricted_files_list.append(print_line(Line_number, j, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
                                if Slash_search_in_query and path_query(Entry.get_req, j, path_query_regex):
                                    path_list.append(print_line(Line_number, j, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
                                if Apply_regex_search and path_traversal_detect(Entry.get_req, path_traversal_regex):
                                    file_inlcusion_regex_list.append(print_line(Line_number, j, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
                                if URL_and_file_extension_query and URL_and_file_extension_func(Entry.get_req):
                                    url_and_extension_list.append(print_line(Line_number, j, display_options, Entry.ip, Entry.availibility, Entry.user_id, Entry.time, Entry.get_req, Entry.status_code, Entry.size, Entry.referrer, Entry.user_agent))
                
                    except AttributeError as e:
                        print(e)
                        print("Skipped line number: " + str(j))
                        print(line)


print_all_file.close()           

                        
# Prints
if XSS:
    print_detections(f,"XSS DETECTIONS", xss_detections_list,regex_print_option,xss_disp_list, True)
    print_detections(fp,"XSS DETECTIONS", xss_false_detections_list,regex_print_option,xss_disp_list, True)
    
if SQL:
    print_detections(f,"SQLi DETECTIONS", sql_detections_list,regex_print_option,sql_disp_list, True)
    print_detections(fp,"SQLi DETECTIONS", sql_false_detections_list,regex_print_option,sql_disp_list, True)

if File_inlcusion:
    if Apply_regex_search:
        print_detections(f,"File inclusion attempts that match OWASP regex", file_inlcusion_regex_list, regex_print_option, path_traversal_regex_disp)
    if OS_files_keyword_search:
        print_detections(f,"Detections for attempts to access sensitive parts of the OS", os_path_list)
    if Other_suspicious_keywords_search:
        print_detections(f,"Detections for attempts to access restricted files", restricted_files_list)
    if Slash_search_in_query:
        print_detections(f,"Paths found in query strings", path_list)
    if URL_and_file_extension_query:
        print_detections(f,"URL and file extension detected in Query strings", url_and_extension_list)
        
if Email_leaks:
    print_detections(f,"Email address leaks in GET requests", emails_get_list)
    print_detections(f,"Email address leaks in referrer", emails_referrer_list)


## Print file without duplicates
pattern = new_re.compile(r'(?:.*?)(\"(GET|HEAD|POST|PROPFIND|-|OPTIONS|PUT|PATCH|quit).*?HTTP\/[\d]\.[\d]\")')

outfile = open(results_dir + "/Results_duplicate_lines_removed.txt", "w+")
hash = {}
duplicates = 0
with open (results_dir + "/Results.txt", "r") as infile:
    for line in infile:
        if not line.startswith('-'):
            try:
                if hash[line]:
                    duplicates+=1
            except KeyError:
                hash[line] = True
                outfile.write(line)
        else:
            outfile.write(line)
print(str(duplicates) + " duplicate lines found (and removed in \'Results_duplicate_lines_removed.txt\'")
outfile.close()


if ASCII_encoding_in_get_requests or URL_encoding:
    outfile = open(results_dir + "/Results_further_processing.txt", "w+")
    with open(results_dir + "/Results_duplicate_lines_removed.txt", "r") as infile:
        print_flag = False
        match_reg = '(?:CHAR|chr)(\(.*?\))'
        pattern = new_re.compile(r'' + match_reg)
        for line in infile:
            if not ASCII_encoding_in_get_requests:
                outfile.write(urllib.parse.unquote(line))
            else:
                if line == 'XSS DETECTIONS\n' or line == 'SQLi DETECTIONS\n':
                    print_flag = True
                if not print_flag:
                    outfile.write(line)
                else:
                    match = pattern.findall(line)
                    if match:
                        # line = line.rstrip()
                        # outfile.write('\n')
                        outfile.write(line)
                        for item in match:
                            return_string = ""
                            tempstring = ""
                            for letter in item:
                                if letter == '(':
                                    return_string = return_string + letter
                                elif letter == ')':
                                    return_string = return_string + chr(int(tempstring)) + letter
                                elif letter == ',':
                                    return_string = return_string + chr(int(tempstring))
                                    tempstring = ""
                                else:
                                    tempstring = tempstring + letter
                            line = new_re.sub(match_reg, return_string, line, 1)
                        if URL_encoding:
                            outfile.write(urllib.parse.unquote(line) + '\n')
                        else:
                            outfile.write(line + '\n')
                    else:
                        if URL_encoding:
                            outfile.write(urllib.parse.unquote(line) + '\n')
                        else:
                            outfile.write(line + '\n')
    outfile.close()



f.close()
fp.close()