import os
import requests
import json
import time
import logging
from logging.handlers import RotatingFileHandler
import argparse
from urllib.parse import urlencode
import sys
from datetime import datetime
import getpass
from dotenv import load_dotenv
import re

# Issue wuth inputs conf file. This solves it if GUI is not used. Code is not active though 
def check_inputs_conf_file_splunk(inputs_conf_path="/opt/splunk/etc/system/local/inputs.conf"):
    """
    [monitor:///var/log/armorcode]
    disabled = false
    index = main
    sourcetype = armorcode_json
    whitelist = \.log$
    """
    
    # Regex for monitor file
    pattern = r"\[monitor:\/\/\/var\/log\/armorcode\]"
    matching_lines = []

    found = False
    if os.path.exists(inputs_conf_path) and os.access(inputs_conf_path, os.W_OK):
        with open(inputs_conf_path, "r") as f:
            for line in f:
                if re.search(pattern, line):
                    matching_lines.append(line.strip())
                    found = True
                    break

        if not found:
            logger.error(f"[-] Monitor File does not exist in {inputs_conf_path}, Adding data")
            create_inputs_conf_splunk_file()
    else:
        create_inputs_conf_splunk_file()

def create_inputs_conf_splunk_file(inputs_conf_path = "/opt/splunk/etc/system/local/inputs.conf"):
        logger.info(f"[+] Creating inputs.conf in {inputs_conf_path}")
        with open(inputs_conf_path, "a") as f:
            f.write("[monitor:///var/log/armorcode]\ndisabled = false index = main\nsourcetype = armorcode_json\nwhitelist = \.log$")


def calc_epoch_time(hours: int = 24) -> int:
    """
    Calculates epoch time and returns start_time and end_time
    """
    # Epoch time calculations
    end_date = int(time.time() * 1000)
    # 24 hours before
    start_date = end_date - (hours * 60 * 60 * 1000)
    return int(end_date), int(start_date)

# List of all current entity names 10/22/2025
entity_name = [ 
    "Custom Dashboard",
    "Finding Sla Configurations",
    "Organization",
    "User",
    "Report",
    "Product",
    "Global Settings",
    "Assessments",
    "Finding Sla Tiers",
    "Project",
    "Api Key",
    "Core Configuration",
    "Finding Views",
    "Runbook",
    "Sub Product",
    "Team",
    "User Session Track",
    "Out Of Box Role Default Dash Board",
    "Ticket Unified Template"
    ]

def args_time_value_exist():
    """
    Checks to see if users used --time option
    If user did it sets the epoch time based off user input
    else it defaults to the last 24 hours
    """
    if args.time:
        end_time, start_time = calc_epoch_time(args.time)
    else:
        end_time, start_time = calc_epoch_time()
    return end_time, start_time

def args_list_nargs_or_list_comma_exist():
    """
    Checks if the user specificed list_nargs or list_comma 
    If neither than defaults back to all entity names
    returns the user options
    """
    if args.list_nargs:
        args_list = args.list_nargs
    elif args.list_comma:
        args_list = args.list_comma

    else:
        # Defaults back to all entitynames 
        # This else block should not ever be hit as list nargs and list comma should have a value when this function is called
        args_list = entity_name

    logger.info(f"[+] User options {args_list}")
    return args_list

def args_size_exist():
    if args.size:
        size = args.size
    else:
        size = 10000
    return size

def args_type_exist():
    """
    Checks if --type was used and changes the entityName or revisionType based on user input
    """
    if args.type:
        entityName_or_revisionType = args.type
    else: 
        entityName_or_revisionType = "entityName"
    return entityName_or_revisionType

def args_max_log_exists() -> int:
    """
    Checks if --max_logs exist and sets the value to user value else defaults to 5
    """
    if args.max_logs:
        max_logs = args.max_logs
    else:
        max_logs = 5
    return max_logs

STATE_FILE = ".INIT-ran"
def gather_all_entity_names(entity_name = entity_name, STATE_FILE = STATE_FILE):
    """
    Gathers all entity names from ArmorCode start 
    Builds the URL with build_audit_url
    Sends it to Request URL Function.
    Creates a state file with last time it ran
    """

    if not os.path.exists(STATE_FILE):
        logger.info("[+] Gathering all data inital run")
        
        with open(STATE_FILE, "w") as f:
            end_time, start_time = calc_epoch_time()
            f.write(f"Initial ran at {end_time}")
        
        size = args_size_exist()
        for item in entity_name:
            url = build_audit_urls(size=size, key="entityName", value=item)
            request_url(url)
    else:
        logger.info(f"[+] The initial function has already ran requesting based epoch time please use --remove to uninstall the {STATE_FILE} file or manually uninstall the {STATE_FILE} file")

        end_time, start_time = args_time_value_exist()

        size = args_size_exist()
        for item in entity_name:
            url = build_audit_urls(size=size,key="entityName", value=item, start_date=start_time, end_date=end_time)
            request_url(url)

def remove_init_file():
    """
    Checks if state file exist in the same directory as the program
    """
    # In case the user does not create the /var/log/armorcode this try execpt block will handle the error
    try:
        os.remove(STATE_FILE)
        logger.info(f"[+] Removing state file {STATE_FILE}")
    except FileNotFoundError:
        logger.error(F"{STATE_FILE} does not exist in local directory. Init most likely has not run")
        exit()

def remove_env_file():
    env_file = create_env_file_secrets()
    try:
        os.remove(env_file)
        logger.info(f"[+] Removing state file {env_file}")
    except FileNotFoundError:
        logger.error(F"{env_file} does not exist in local directory. --use-env most likely has not run")
        exit()

def gather_all_entity_names_none_init(entity_name=entity_name):
    """
    Gathers all entity names when none --init is not used 
    """
    end_time, start_time = args_time_value_exist()

    size = args_size_exist()
    for item in entity_name:
        url = build_audit_urls(size=size,key="entityName", value=item, start_date=start_time, end_date=end_time)
        request_url(url)

def parse_comma_separated_list(arg_string):
    """
    Custom type function to parse a comma-separated string into a list.
    Custom validation in this function
    --list_comma flag
    """
    ALLOWED = entity_name

    items = [item.strip() for item in arg_string.split(',')]
    for item in items:
        if item not in ALLOWED:
            raise argparse.ArgumentTypeError(
                f"Invalid value '{item}'. Allowed: {','.join(ALLOWED)}"
            )
    return items


def user_options():
    """
    Takes in an input from the user list_nargs or list_comma and builds a URL
    """
    end_time, start_time = args_time_value_exist()
    entityName_or_revisionType =  args_type_exist()

    
    size = args_size_exist()
    args_list = args_list_nargs_or_list_comma_exist()
    
    for item in args_list:
        url = build_audit_urls(size=size,key=entityName_or_revisionType, value=item, start_date=start_time, end_date=end_time)
        request_url(url)

def create_env_file_secrets():
    """
    Creates .env file in current working directory
    """
    path = os.getcwd()
    FILENAME = '.env'
    secrets_file = os.path.join(path,FILENAME)
    return secrets_file

def set_file_permissions_on_env_file():
    """
    Sets the file permission (600) for env file
    Only for posix OSs
    """
    if os.name == 'posix':
        file_permissions = 0o600
        secrets_file = create_env_file_secrets()
        file_permissions_for_env = os.chmod(secrets_file, file_permissions)
        logging.info(f"[+] Setting file permission to {file_permissions}")
        return file_permissions_for_env

def check_env_file_permissions():
    secrets_file = create_env_file_secrets()
    logger.info("[+] Checking file permissions")
    if os.access(secrets_file, os.R_OK):
        logger.info(f"[+] Secrets File has read access")
    else:
        logger.error(f"[-] Secrets File does not have read access")
        set_file_permissions_on_env_file()
    
    if os.access(secrets_file, os.W_OK):
        logger.info(f"[+] Secrets File has write access")
    else:
        logger.error(f"[-] Secrets File does not have write access")
        set_file_permissions_on_env_file()

    if os.access(secrets_file, os.X_OK):
        logger.error("[-] File permissions are not set up correctly")
        set_file_permissions_on_env_file()




def write_env_secrets():
    """
    Sets file permissions to 600 and writes API key with getpass to .env file
    """
    secrets_file = create_env_file_secrets()
    
    if not os.path.exists(secrets_file):
        with open(secrets_file, 'w') as f:
            set_file_permissions_on_env_file()

            get_api_key = getpass.getpass("Enter API key: ")
            f.write("ARMORCODE_API_KEY=" + get_api_key)
    else:
        check_env_file_permissions()
        logger.info(f"[+] {secrets_file} exists on machine reading from file")        
    
def read_secrets_from_env():
    load_dotenv()
    API_KEY = os.getenv("ARMORCODE_API_KEY")
    return API_KEY

parser = argparse.ArgumentParser(description=\
    """ ArmorCode command-line Splunk Audit tool
        usage (inital run): python3 armorcode-tool.py --api_key "API_Key" --init 
        usage: python3 armorcode-tool.py --api API_Key
        """)
parser.add_argument('--api-key', required=False, help='ArmorCode API key')
parser.add_argument('--init', action='store_const', const=gather_all_entity_names, help='Gathers all data to upload to Splunk')
parser.add_argument('--time', type=int, help="Gathers data from the 24 hours as default | --time 24 ")
parser.add_argument("--size", type=int, help="How much data should be returned | --size 10 would return 10 entries from each audit item")

# Custom Validation in the parse comma separated list function
parser.add_argument('--list-comma', type=parse_comma_separated_list, help="Creates a list to objects to parse | Example --list-nargs User Team Report")
parser.add_argument('--list-nargs', type=str, nargs='+', choices=[ 
    "Custom Dashboard",
    "Finding Sla Configurations",
    "Organization",
    "User",
    "Report",
    "Product",
    "Global Settings",
    "Assessments",
    "Finding Sla Tiers",
    "Project",
    "Api Key",
    "Core Configuration",
    "Finding Views",
    "Runbook",
    "Sub Product",
    "Team",
    "User Session Track",
    "Out Of Box Role Default Dash Board",
    "Ticket Unified Template"
    ], help="Creates a list to objects to parse | Example --list_nargs User Team Report")
parser.add_argument("--type", type=str, choices=["entityName", "revisionType"], help="entityName or revisionType")
parser.add_argument("--remove", action='store_true', help="Remove init file")
parser.add_argument("--max-logs", type=int, help="Max log rotation affects armorcode-forawarder.log")
parser.add_argument("--use-env", action='store_true', help="Store and load API key from .env file")
parser.add_argument("--remove-env", action='store_true', help="Remove .env file to allow user to add new API Key")
args = parser.parse_args()


"""
https://docs.python.org/3/howto/logging.html
logging.basicConfig(format='%(asctime)s %(message)s')
"""
def detect_os_setting_variables() -> str:
    """
    Detects the OS and creates the log path depending on the OS
    """
    if os.name == 'nt':
        working_directory = os.getcwd()

        log_folder = os.path.join(working_directory,'logs')

        if not os.path.exists(log_folder):
            os.mkdir(log_folder)
        return log_folder
    elif os.name == 'posix':
        path = "/var/log/armorcode"
        return path
    else:
        print(f"Running on an unknown OS: {os.name}")
        return os.name
    
# -------- Logging Setup --------
# Create log directory
log_directory = detect_os_setting_variables()
log_file_name = "armorcode-forwarder.log"
try:
    log_file_path = os.path.join(log_directory, log_file_name)
except FileNotFoundError:
    sys.exit(f"[-] Error: {log_directory} not found can't create {log_file_name} | Log directory {log_directory} is required")

# Need to verify that log rotation works
logger = logging.getLogger('armorcode_app')
logger.setLevel(logging.INFO)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

BACKUP_COUNT = args_max_log_exists()

# log rotation at 5mbs 
handler = RotatingFileHandler(log_file_path, mode='a', maxBytes = 5 * 1024 * 1024, 
                                 backupCount=BACKUP_COUNT, encoding=None, delay=False)
handler.setFormatter(log_formatter)

logger.addHandler(handler)

# --------ArmorCode Configuration --------

def api_key_check():
    # Using --api-key can leak the API key in the processes on linux
    if args.api_key:
        API_KEY = args.api_key
    elif os.getenv("ARMORCODE_API_KEY"):
        API_KEY = os.getenv("ARMORCODE_API_KEY")
    elif args.use_env:
        write_env_secrets()
        API_KEY = read_secrets_from_env()
    else:
        logger.error("[-] ArmorCode API not provided cannot make API request")
        API_KEY = None
    return API_KEY

API_KEY = api_key_check()

def request_url(url):
    """
    Request the JSON data from ArmorCode then writes or appends the data to a todays-date-file.log 
    """
    headers = {"Authorization": f"Bearer {API_KEY}"}

    try:
        r = requests.get(url, headers=headers)

        if r.ok:
            json_data = r.json()
            # Checks if content is empty and if so skips writing it to file
            # looks for content: []
            if json_data.get("content"):
                write_json_data_from_armorcode_to_date_file(json_data)
            else:
                path = detect_os_setting_variables()
                log_path = os.path.join(path,generate_date_time_filenames())
                logger.info(f"[+] No data found in API request not logging to {log_path}")
            return json_data
        else:
            logger.error(f"[-] API Error:  {r.status_code}, {r.text}")
            return None
    except Exception as e:
        logger.error(f"[-] Request error: {e}")


def build_audit_urls(page: int = 0, size: int = 10000, audit_log_level: str = "ALL", key: str = "revisionType", value: str = "LOGGED_IN", start_date: str = 0, end_date: str = 0) -> str:
    """
    Creates the URL used to for the Audit request and returns the url as a string
    """
    base_url = "https://app.armorcode.com/user/audit/log/details/page"

    paramaters = {
        "page": page,
        "size": size,
        "auditLogLevel": audit_log_level,
        key: value,
        "startDate": start_date,
        "endDate": end_date,
    }
    url = f"{base_url}?{urlencode(paramaters)}"
    logger.info(f"[+] Created URL {url}")
    return url

def write_json_data_from_armorcode_to_date_file(json_data):
    """
    Creates a .log file based on todays date and writes data from armorcode to the file
    Appends if the file already exist.
    """
    # Sets the log path depending on OS. In case the user is running Splunk on Windows or the script on Windows
    path = detect_os_setting_variables()

    if not os.path.exists(path):
        logger.error(f"{path} does not exist please run install.sh or create {path}")

    # Checks write acess to folder in case permissions where not set correctly
    if not os.access(path, os.W_OK):
        logger.error(f"[-] No write access to {path}")
        sys.exit("No write access to folder /var/log/armorcode")


    log_path = os.path.join(path, generate_date_time_filenames())
    
    if not os.path.exists(log_path):
        logger.info(f"[+] Creating log path {log_path}")
        with open(log_path, 'w') as f:
            json.dump(json_data, f, separators=(",", ":"))
            f.write("\n")
    else:
        logger.info(f"[+] Log path exist {log_path}, appending data to file")
        with open(log_path, 'a') as f:
            json.dump(json_data, f, separators=(",", ":"))
            f.write("\n")

def generate_date_time_filenames():
    now = datetime.now()
    formatted_date = now.strftime("%Y-%m-%d")
    return f"{formatted_date}.log"

def main():
    logger.info("[+] Program is Starting")
    # Removes init and env file
    if args.remove:
        remove_init_file()
        exit()
    if  args.remove_env:
        remove_env_file()
        exit()

    # Inputs.conf may not be created properly in GUI causing it to only log armorcode-forward.log and nothing else.
    # This focuses the file to created and 
    """
    if os.name == 'posix':
        check_inputs_conf_file_splunk()
    """
    required_args = args.api_key or os.getenv("ARMORCODE_API_KEY")

    if all(required_args) and args.init:
        gather_all_entity_names()
    elif all(required_args) and (args.list_nargs):
        user_options()
    elif all(required_args) and (args.list_comma):
        logger.info("[+] User selected comma option")
        user_options()
    elif all(required_args):
        gather_all_entity_names_none_init()
    
if __name__ == "__main__":
    main()