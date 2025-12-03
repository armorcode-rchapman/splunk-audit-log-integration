ArmorCodes CLI audit tool is designed to store logs in /var/logs/armorcode in unix based Operating Systems (OS) and current directory for Microsoft Windows, which you will find a logs folder. For each OS logs are stored in Year-Month-Date.log format. The script automatically removes empty data from being written to the log files, only request with data will be written to the log files. 

## Initial Setup
Install.sh creates the /var/log/armorcode directory and expects that a user splunk exist. Once the script is ran the program will create /var/log/armorcode directory and then assign owner and group to the splunk user.
### Automated Install
```bash
sudo ./install.sh
```
### Manual Install
```bash
sudo mkdir /var/log/armorcode
```

If Splunk user is different change the command to match the user you want to own the folder.
```bash
sudo chown splunk:splunk /var/log/armorcode 
```

### Troubleshooting Common Issues

```bash
sudo apt install python3-pip
```

```bash
 pip install -r requirements.txt
```

## Usage with --api-key

### First Run of ArmorCode Logging App
Gathers all data from ArmorCode and writes it to todays-date.log. If --init is used in cron job it will default to 24 hours after the first run. Users can remove the init file created by running the --remove. It is recommend not to add the CLI command to Splunk as it will leak API if --api-key is used. The argument --size should be used to used to increased the return size of the data retrieved. The default is 10 items returned 
```bash
python ./main.py --api-key [Insert API Key here] --init
```

Increases the amount of data returned from ArmorCode to 100 items. For large organizations this number might need to higher on initial run. Then can be lowed to an expected value or can stay the higher number.
```bash
python ./main.py --api-key [Insert API Key here] --init --size 100
```

If --init is used in a cron job and the user wants to override the default 24 hours they can add --time and specify the hours. Example below would retrieve data from the last 10 hours on every run after --init.
```bash
python ./main.py --api-key [Insert API Key here] --init --time 10
```

Removes the init file which allows the --init to gather all data again. Creates a hidden file on Linux .INIT-ran, which stores the epoch time when --init first ran.
```bash
python ./main.py --api-key [Insert API Key here] --remove
```

### Customize ArmorCode Logging App Output
Gather all data from the last 24 hours. 24 hours is the default time
```bash
python3 ./main.py --api-key [Insert API Key here]
```

Gathers all data from the last 12 hours. --time expects an integer value and is based on hours
```bash
python3 ./main.py --api-key [Insert API Key here] --time 12
```

--time does not work with floats and would return an error.
```bash
# This would not work
python3 ./main.py --api-key [Insert API Key here] --time 12.1
```

--size limits the entries returned by ArmorCode. Default value is 10 and is **recommended to change this value to a higher number to not miss logs.**   
```bash
python3 ./main.py --api-key [Insert API Key here] --size 12
```

--list-nargs allows the user to specify what data points they want to log. Words must be exact with upper case letters. Logs will be created with user options.
```bash
python3 ./main.py --api-key [Insert API Key here] --list-nargs "User" "Team" "Api Key"
```

--list-comma allows the user to specify what data points they want to log. Words must be exact with upper case letters. Logs will be created with user options.
```bash
python3 ./main.py --api-key [Insert API Key here] --list-comma "User,Team,Api Key"
```

--type allows the user to specify what type of logs they want. 'revisionType' is not currently supported. 
```bash
python3 ./main.py --api-key [Insert API Key here] --type entityName
```

--max-logs allows for log rotation of the armorcode.log by default this value is 5 files at 5MB 
```bash
python3 ./main.py --api-key [Insert API Key here] --max-logs 5
```

Logs User, Team, Api Key, with a max return of 12 results in the last 10 hours 
```bash
python3 ./main.py --api-key [Insert API Key here] --list-nargs "User" "Team" "Api Key" --size 12 --time 10
```

## Usage with Exporting API Key
```bash
export ARMORCODE_API_KEY="[Insert API Key here]"
```
```bash
python3 main.py --list-nargs "User" "Team"  "Api Key" --size 12 --time 10
```

## Usage with .env File
--use-env creates a .env file if it does not exist and writes the API key to the file. File permissions by default are set to 600.

```bash
python3 ./demo.py --use-env --init
```

Changing the API key requires the --remove-env or the user has to manual delete the file. Afterwards the user can rerun the --use-env command to add the new API key to .env 
```bash
python3 ./demo.py --remove-env
```

--use-env replaces the need for --api-key. All commands run the same as using --api-key
```bash
python3 ./main.py --use-env --list-nargs "User" "Team" "Api Key" --size 12 --time 10
```
## Splunk Monitoring Setup

Use demo video I sent here



### For Developers: I did not add input validation on --use-env and anything can be passed to the .env file. It is used for the Authorization token. 
```
header {"Authorization": f"Bearer {API_KEY}"}
```
What data would like like in the .env file
```
ARMORCODE_API_KEY=<API KEY>
```
Permissions on the .env file are 600