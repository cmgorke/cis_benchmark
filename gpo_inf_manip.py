#run as administrator in cmd prompt
#to work, you must manually export policy folder to directory of the script 
#Need to figure out method for: if all values are in key, no matter the order 

#from io import open
#import csv
import os
import sys
import glob

def conc_policy_files():
    read_files = glob.glob("*.txt")
    with open("result.txt", "wb") as outfile:
        for f in read_files:
            with open(f, "rb") as infile:
                outfile.write(infile.read())

 
#function to make key value pairs from lines
def gpo_dictionary():
    print("****Group Policy is being written into dictionary*****")
    #opens the encoded data and prints line by line
    data = []
    with open('result.txt', 'r') as f:
        while True:
            x=f.readline()
            if not x:
                break
            data.append(x)

    group_policy_values = {}
    for i in data:
        item = i.split('\t')
        #IndexError comes from some indexes not containing '='
        try:
            group_policy_values[item[0].strip()] = item[1].strip().replace(' days', '').replace(' characters', '').replace(' passwords remembered', '').replace(' invalid logon attempts', '').replace(' minutes', '').replace(' logons', '')        
        except IndexError:
            continue    
    return group_policy_values                   
    #print(group_policy_values)
 
#scores based off of key value/pairs
#for now if/else statements will be the group policy checks, need to build out for cis standards
#future reference csv.dictreader may be best method to fight redundancy of if else statements.
def gpo_scoring():
    score = 0
    group_policy_values = gpo_dictionary()
    print("****Group Policy is being scored****")
    try:
        # group_policy_values['PasswordHistory'] == '0'
        if int(group_policy_values['Enforce password history']) >= 24:
            score += 1
        else:
            print("Requirement #1.1.1 failed, to score for this toggle 'Enforce password history' to 24 or more passwords")
    except KeyError:
        print("Requirement #1.1.1 failed, Program could not find policy 'Enforce password history'")
    except ValueError:
        print("Requirement #1.1.1 failed, you do not have the policy 'Enforce password history' applied'")

    try:    
        if int(group_policy_values['Maximum password age']) > 0 and int(group_policy_values['Maximum password age']) <= 60:
            score += 1
        else:
            print("Requirement #1.1.2 failed, to score for this toggle 'Maximum password age' to 60 or fewer days but more than 0")
    except KeyError:
        print("Requirement #1.1.2 failed, Program could not find policy 'Maximum password age'")
    except ValueError:
        print("Requirement #1.1.2 failed, you do not have the policy 'Maximum password age' applied'")

    try:   
        if int(group_policy_values['Minimum password age']) > 0:
            score += 1
        else:
            print("Requirement #1.1.3 failed, to score for this toggle 'Minimum password age' to 1 or more days")
    except KeyError:
        print("Requirement #1.1.3 failed, Program could not find policy 'Minimum password age'")
    except ValueError:
        print("Requirement #1.1.3 failed, you do not have the policy 'Minimum password age' applied'")
    
    try:   
        if int(group_policy_values['Minimum password length']) >= 14:
            score += 1
        else:
            print("Requirement #1.1.4 failed, to score for this toggle 'Minimum password length' to 14 or more characters")
    except KeyError:
        print("Requirement #1.1.4 failed, Program could not find policy 'Minimum password length'")
    except ValueError:
        print("Requirement #1.1.4 failed, you do not have the policy 'Minimum password length' applied'")
    
    try:   
        if group_policy_values['Password must meet complexity requirements'] == 'Enabled':
            score += 1
        else:
            print("Requirement #1.1.5 failed, to score for this toggle 'Password must meet complexity requirements' to 'Enabled'")
    except KeyError:
        print("Requirement #1.1.5 failed, Program could not find policy 'Password must meet complexity requirements'")
    except ValueError:
        print("Requirement #1.1.5 failed, you do not have the policy 'Password must meet complexity requirements'")

    try:   
        if group_policy_values['Store passwords using reversible encryption'] == 'Disabled':
            score += 1
        else:
            print("Requirement #1.1.6 failed, to score for this toggle 'Store passwords using reversible encryption' to 'Disabled'")
    except KeyError:
        print("Requirement #1.1.6 failed, Program could not find policy 'Store passwords using reversible encryption'")
    except ValueError:
        print("Requirement #1.1.6 failed, you do not have the policy 'Store passwords using reversible encryption' applied'")

    try:   
        if int(group_policy_values['Account lockout duration']) >= 15:
            score += 1
        else:
            print("Requirement #1.2.1 failed, to score for this toggle 'Account lockout duration' to 15 or more minutes")
    except KeyError:
        print("Requirement #1.2.1 failed, Program could not find policy 'Account lockout duration'")
    except ValueError:
        print("Requirement #1.2.1 failed, you do not have the policy 'Account Lockout duration' applied'")

    try:   
        if int(group_policy_values['Account lockout threshold']) <= 10:
            score += 1
        else:
            print("Requirement #1.2.2 failed, to score for this toggle 'Account lockout threshold' to 10 or fewer invalid logon attempts")
    except KeyError:
        print("Requirement #1.2.2 failed, Program could not find policy 'Account lockout threshold'")
    except ValueError:
        print("Requirement #1.2.2 failed, you do not have the policy 'Account lockout threshold' applied'")        

    try:   
        if int(group_policy_values['Reset account lockout counter after']) >= 15:
            score += 1
        else:
            print("Requirement #1.2.3 failed, to score for this toggle 'Reset account lockout counter after' to 15 or more minutes")
    except KeyError:
        print("Requirement #1.2.3 failed, Program could not find policy 'Reset account lockout counter after'")
    except ValueError:
        print("Requirement #1.2.3 failed, you do not have the policy 'Reset account lockout counter after' applied'") 

    try:   
        if group_policy_values['Access Credential Manager as a trusted caller'] == 'No One' or group_policy_values['Access Credential Manager as a trusted caller'] == '':
            score += 1
        else:
            print("Requirement #2.2.1 failed, to score for this toggle 'Access Credential Manager as a trusted caller' to 'No One' or make the setting empty")
    except KeyError:
        print("Requirement #2.2.1 failed, Program could not find policy 'Access Credential Manager as a trusted caller'")
    except ValueError:
        print("Requirement #2.2.1 failed, you do not have the policy 'Access Credential Manager as a trusted caller' applied'")        

    try:   
        if group_policy_values['Access this computer from the network'] == 'Administrators, Authenticated Users' or group_policy_values['Access this computer from the network'] == 'Administrators,Authenticated Users,ENTERPRISE DOMAIN CONTROLLERS':
            score += 1
        else:
            print("Requirement #2.2.2 failed, to score for this toggle 'Access this computer from the network' so that only 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' are able to access from network")
    except KeyError:
        print("Requirement #2.2.2 failed, Program could not find policy 'Access this computer from the network'")
    except ValueError:
        print("Requirement #2.2.2 failed, you do not have the policy 'Access this computer from the network' applied'")

    try:   
        if group_policy_values['Act as part of the operating system'] == 'No One' or group_policy_values['Act as part of the operating system'] == '':
            score += 1
        else:
            print("Requirement #2.2.3 failed, to score for this toggle 'Act as part of the operating system' to No one, or make the setting empty")
    except KeyError:
        print("Requirement #2.2.3 failed, Program could not find policy 'Act as part of the operating system'")
    except ValueError:
        print("Requirement #2.2.3 failed, you do not have the policy 'Act as part of the operating system' applied'")

    try:   
        if group_policy_values['Add workstations to domain'] == 'Administrators':
            score += 1
        else:
            print("Requirement #2.2.4 failed, to score for this toggle 'Add workstations to domain' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.4 failed, Program could not find policy 'Add workstations to domain'")
    except ValueError:
        print("Requirement #2.2.4 failed, you do not have the policy 'Add workstations to domain' applied'")

    try:   
        if group_policy_values['Adjust memory quotas for a process'] == 'Administrators,LOCAL SERVICE,NETWORK SERVICE':
            score += 1
        else:
            print("Requirement #2.2.5 failed, to score for this toggle 'Adjust memory quotas for a process' to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'")
    except KeyError:
        print("Requirement #2.2.5 failed, Program could not find policy 'Adjust memory quotas for a process'")
    except ValueError:
        print("Requirement #2.2.5 failed, you do not have the policy 'Adjust memory quotas for a process' applied'")

    try:   
        if group_policy_values['Allow log on locally'] == 'Administrators':
            score += 1
        else:
            print("Requirement #2.2.6 failed, to score for this toggle 'Allow log on locally' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.6 failed, Program could not find policy 'Allow log on locally'")
    except ValueError:
        print("Requirement #2.2.6 failed, you do not have the policy 'Allow log on locally' applied'")

    try:   
        if group_policy_values['Allow log on through Remote Desktop Services'] == 'Administrators' or group_policy_values['Allow log on through Remote Desktop Services'] == 'Administrators,Remote Desktop Users':
            score += 1
        else:
            print("Requirement #2.2.7 failed, to score for this toggle 'Allow log on through Remote Desktop Services' to 'Administrators' only for Domain Controllers, and 'Administrators, Remote Desktop Users' for Member servers")
    except KeyError:
        print("Requirement #2.2.7 failed, Program could not find policy 'Allow log on through Remote Desktop Services'")
    except ValueError:
        print("Requirement #2.2.7 failed, you do not have the policy 'Allow log on through Remote Desktop Services' applied'")

    try:   
        if group_policy_values['Back up files and directories'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.8 failed, to score for this toggle 'Back up files and directories' to 'Administrators' only")
    except KeyError:
        print("Requirement #2.2.8 failed, Program could not find policy 'Back up files and directories'")
    except ValueError:
        print("Requirement #2.2.8 failed, you do not have the policy 'Back up files and directories' applied'")

    try:   
        if group_policy_values['Change the system time'] == 'Administrators,LOCAL SERVICE' or group_policy_values['Change the system time'] == 'LOCAL SERVICE,Administrators': 
            score += 1
        else:
            print("Requirement #2.2.9 failed, to score for this toggle 'Change the system time' to 'Administrators, LOCAL SERVICE'")
    except KeyError:
        print("Requirement #2.2.9 failed, Program could not find policy 'Change the system time'")
    except ValueError:
        print("Requirement #2.2.9 failed, you do not have the policy 'Change the system time' applied'")        

    try:   
        if group_policy_values['Change the time zone'] == 'Administrators,LOCAL SERVICE' or group_policy_values['Change the time zone'] == 'LOCAL SERVICE,Administrators': 
            score += 1
        else:
            print("Requirement #2.2.10 failed, to score for this toggle 'Change the time zone' to 'Administrators, LOCAL SERVICE'")
    except KeyError:
        print("Requirement #2.2.10 failed, Program could not find policy 'Change the time zone'")
    except ValueError:
        print("Requirement #2.2.10 failed, you do not have the policy 'Change the time zone' applied'")      

    try:   
        if group_policy_values['Create a pagefile'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.11 failed, to score for this toggle 'Create a pagefile' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.11 failed, Program could not find policy 'Create a pagefile'")
    except ValueError:
        print("Requirement #2.2.11 failed, you do not have the policy 'Create a pagefile' applied'")      

    try:   
        if group_policy_values['Create a token object'] == 'No One' or group_policy_values['Create a token object'] == '': 
            score += 1
        else:
            print("Requirement #2.2.12 failed, to score for this toggle 'Create a token object' to 'No One' or make the setting empty")
    except KeyError:
        print("Requirement #2.2.12 failed, Program could not find policy 'Create a token object'")
    except ValueError:
        print("Requirement #2.2.12 failed, you do not have the policy 'Create a token object' applied'")

    try:   
        if group_policy_values['Create global objects'] == 'Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE':
            score += 1
        else:
            print("Requirement #2.2.13 failed, to score for this toggle 'Create global objects' to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'")
    except KeyError:
        print("Requirement #2.2.13 failed, Program could not find policy 'Create global objects'")
    except ValueError:
        print("Requirement #2.2.13 failed, you do not have the policy 'Create global objects' applied'")

    try:   
        if group_policy_values['Create permanent shared objects'] == 'No One' or group_policy_values['Create permanent shared objects'] == '': 
            score += 1
        else:
            print("Requirement #2.2.14 failed, to score for this toggle 'Create permanent shared objects' to 'No One' or make the setting empty")
    except KeyError:
        print("Requirement #2.2.14 failed, Program could not find policy 'Create permanent shared objects'")
    except ValueError:
        print("Requirement #2.2.14 failed, you do not have the policy 'Create permanent shared objects' applied'")

    try:   
        if group_policy_values['Create symbolic links'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.15 failed, to score for this toggle 'Create symbolic links' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.15 failed, Program could not find policy 'Create symbolic links'")
    except ValueError:
        print("Requirement #2.2.15 failed, you do not have the policy 'Create symbolic links' applied'")

    try:   
        if group_policy_values['Debug programs'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.16 failed, to score for this toggle 'Debug programs' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.16 failed, Program could not find policy 'Debug programs'")
    except ValueError:
        print("Requirement #2.2.16 failed, you do not have the policy 'Debug programs' applied'")

    try:   
        if group_policy_values['Deny access to this computer from the network'] == 'Guests,Local account': 
            score += 1
        else:
            print("Requirement #2.2.17 failed, to score for this toggle 'Deny access to this computer from the network' to 'Guest, Local account'")
    except KeyError:
        print("Requirement #2.2.17 failed, Program could not find policy 'Deny access to this computer from the network'")
    except ValueError:
        print("Requirement #2.2.17 failed, you do not have the policy 'Deny access to this computer from the network' applied'")

    try:   
        if 'Guest' in group_policy_values['Deny log on as a batch job']: 
            score += 1
        else:
            print("Requirement #2.2.18 failed, to score for this toggle 'Deny log on as a batch job' to include 'Guest'")
    except KeyError:
        print("Requirement #2.2.18 failed, Program could not find policy 'Deny log on as a batch job'")
    except ValueError:
        print("Requirement #2.2.18 failed, you do not have the policy 'Deny log on as a batch job' applied'")

    try:   
        if 'Guest' in group_policy_values['Deny log on as a service']: 
            score += 1
        else:
            print("Requirement #2.2.19 failed, to score for this toggle 'Deny log on as a service' to include 'Guest'")
    except KeyError:
        print("Requirement #2.2.19 failed, Program could not find policy 'Deny log on as a service'")
    except ValueError:
        print("Requirement #2.2.19 failed, you do not have the policy 'Deny log on as a service' applied'")

    try:   
        if 'Guest' in group_policy_values['Deny log on locally']: 
            score += 1
        else:
            print("Requirement #2.2.20 failed, to score for this toggle 'Deny log on locally' to include 'Guest'")
    except KeyError:
        print("Requirement #2.2.20 failed, Program could not find policy 'Deny log on locally'")
    except ValueError:
        print("Requirement #2.2.20 failed, you do not have the policy 'Deny log on locally' applied'")

    try:   
        if 'Guest' in group_policy_values['Deny log on through Remote Desktop Services'] and 'Local account' in group_policy_values['Deny log on through Remote Desktop Services']: 
            score += 1
        else:
            print("Requirement #2.2.21 failed, to score for this toggle 'Deny log on through Remote Desktop Services' to include 'Guest' and 'Local account'")
    except KeyError:
        print("Requirement #2.2.21 failed, Program could not find policy 'Deny log on through Remote Desktop Services'")
    except ValueError:
        print("Requirement #2.2.21 failed, you do not have the policy 'Deny log on through Remote Desktop Services' applied'")                
        
    try:   
        if group_policy_values['Enable computer and user accounts to be trusted for delegation'] == 'Administrators' or group_policy_values['Enable computer and user accounts to be trusted for delegation'] == '': 
            score += 1
        else:
            print("Requirement #2.2.22 failed, to score for this toggle 'Enable computer and user accounts to be trusted for delegation' to 'Administrators' if Domain controller or 'No one' (or leave empty) if 'Member Server'")
    except KeyError:
        print("Requirement #2.2.22 failed, Program could not find policy 'Enable computer and user accounts to be trusted for delegation'")
    except ValueError:
        print("Requirement #2.2.22 failed, you do not have the policy 'Enable computer and user accounts to be trusted for delegation' applied'")    

    try:   
        if group_policy_values['Force shutdown from a remote system'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.23 failed, to score for this toggle 'Force shutdown from a remote system' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.23 failed, Program could not find policy 'Force shutdown from a remote system'")
    except ValueError:
        print("Requirement #2.2.23 failed, you do not have the policy 'Force shutdown from a remote system' applied'")

    try:   
        if group_policy_values['Generate security audits'] == 'LOCAL SERVICE,NETWORK SERVICE': 
            score += 1
        else:
            print("Requirement #2.2.24 failed, to score for this toggle 'Generate security audits' to 'LOCAL SERVICE, NETWORK SERVICE'")
    except KeyError:
        print("Requirement #2.2.24 failed, Program could not find policy 'Generate security audits'")
    except ValueError:
        print("Requirement #2.2.24 failed, you do not have the policy 'Generate security audits' applied'")

    try:   
        if group_policy_values['Impersonate a client after authentication'] == 'Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE': 
            score += 1
        else:
            print("Requirement #2.2.25 failed, to score for this toggle 'Impersonate a client after authentication' to 'Administrators,LOCAL SERVICE, NETWORK SERVICE, SERVICE'")
    except KeyError:
        print("Requirement #2.2.25 failed, Program could not find policy 'Impersonate a client after authentication'")
    except ValueError:
        print("Requirement #2.2.25 failed, you do not have the policy 'Impersonate a client after authentication' applied'")

    try:   
        if group_policy_values['Increase scheduling priority'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.26 failed, to score for this toggle 'Increase scheduling priority' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.26 failed, Program could not find policy 'Increase scheduling priority'")
    except ValueError:
        print("Requirement #2.2.26 failed, you do not have the policy 'Increase scheduling priority' applied'")

    try:   
        if group_policy_values['Load and unload device drivers'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.27 failed, to score for this toggle 'Load and unload device drivers' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.27 failed, Program could not find policy 'Load and unload device drivers'")
    except ValueError:
        print("Requirement #2.2.27 failed, you do not have the policy 'Load and unload device drivers' applied'")

    try:   
        if group_policy_values['Lock pages in memory'] == '': 
            score += 1
        else:
            print("Requirement #2.2.28 failed, to score for this toggle 'Lock pages in memory' to 'No One' or leave setting blank")
    except KeyError:
        print("Requirement #2.2.28 failed, Program could not find policy 'Lock pages in memory'")
    except ValueError:
        print("Requirement #2.2.28 failed, you do not have the policy 'Lock pages in memory' applied'")

    try:   
        if group_policy_values['Manage auditing and security log'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.29 failed, to score for this toggle 'Manage auditing and security log' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.29 failed, Program could not find policy 'Manage auditing and security log'")
    except ValueError:
        print("Requirement #2.2.29 failed, you do not have the policy 'Manage auditing and security log' applied'")

    try:   
        if group_policy_values['Modify an object label'] == '': 
            score += 1
        else:
            print("Requirement #2.2.30 failed, to score for this toggle 'Modify an object label' to 'No One' or leave setting blank")
    except KeyError:
        print("Requirement #2.2.30 failed, Program could not find policy 'Modify an object label'")
    except ValueError:
        print("Requirement #2.2.30 failed, you do not have the policy 'Modify an object label' applied'") 

    try:   
        if group_policy_values['Modify firmware environment values'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.31 failed, to score for this toggle 'Modify firmware environment values' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.31 failed, Program could not find policy 'Modify firmware environment values'")
    except ValueError:
        print("Requirement #2.2.31 failed, you do not have the policy 'Modify firmware environment values' applied'")

    try:   
        if group_policy_values['Perform volume maintenance tasks'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.32 failed, to score for this toggle 'Perform volume maintenance tasks' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.32 failed, Program could not find policy 'Perform volume maintenance tasks'")
    except ValueError:
        print("Requirement #2.2.32 failed, you do not have the policy 'Perform volume maintenance tasks' applied'")

    try:   
        if group_policy_values['Profile single process'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.33 failed, to score for this toggle 'Profile single process' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.33 failed, Program could not find policy 'Profile single process'")
    except ValueError:
        print("Requirement #2.2.33 failed, you do not have the policy 'Profile single process' applied'")        

    try:   
        if group_policy_values['Profile system performance'] == 'Administrators,NT SERVICE\WdiServiceHost': 
            score += 1
        else:
            print("Requirement #2.2.34 failed, to score for this toggle 'Profile system performance' to 'Administrators, NT SERVICE\WdiServiceHost'")
    except KeyError:
        print("Requirement #2.2.34 failed, Program could not find policy 'Profile system performance'")
    except ValueError:
        print("Requirement #2.2.34 failed, you do not have the policy 'Profile system performance' applied'")

    try:   
        if group_policy_values['Replace a process level token'] == 'LOCAL SERVICE,NETOWORK SERVICE': 
            score += 1
        else:
            print("Requirement #2.2.35 failed, to score for this toggle 'Replace a process level token' to 'LOCAL SERVICE, NETOWORK SERVICE'")
    except KeyError:
        print("Requirement #2.2.35 failed, Program could not find policy 'Replace a process level token'")
    except ValueError:
        print("Requirement #2.2.35 failed, you do not have the policy 'Replace a process level token' applied'")

    try:   
        if group_policy_values['Restore files and directories'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.36 failed, to score for this toggle 'Restore files and directories' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.36 failed, Program could not find policy 'Restore files and directories'")
    except ValueError:
        print("Requirement #2.2.36 failed, you do not have the policy 'Restore files and directories' applied'")  

    try:   
        if group_policy_values['Shut down the system'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.37 failed, to score for this toggle 'Shut down the system' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.37 failed, Program could not find policy 'Shut down the system'")
    except ValueError:
        print("Requirement #2.2.37 failed, you do not have the policy 'Shut down the system' applied'")  

    try:   
        if group_policy_values['Synchronize directory service data'] == '': 
            score += 1
        else:
            print("Requirement #2.2.38 failed, to score for this toggle 'Synchronize directory service data' to 'No One' or leave setting blank")
    except KeyError:
        print("Requirement #2.2.38 failed, Program could not find policy 'Synchronize directory service data'")
    except ValueError:
        print("Requirement #2.2.38 failed, you do not have the policy 'Synchronize directory service data' applied'") 

    try:   
        if group_policy_values['Take ownership of files or other objects'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.2.39 failed, to score for this toggle 'Take ownership of files or other objects' to 'Administrators'")
    except KeyError:
        print("Requirement #2.2.39 failed, Program could not find policy 'Take ownership of files or other objects'")
    except ValueError:
        print("Requirement #2.2.39 failed, you do not have the policy 'Take ownership of files or other objects' applied'")  

    try:   
        if group_policy_values['Accounts: Block Microsoft accounts'] == "Users can't add or log on with Microsoft accounts": 
            score += 1
        else:
            print("Requirement #2.3.1.1 failed, to score for this set 'Accounts: Block Microsoft accounts' to 'Users can't add or log on with Microsoft accounts'")
    except KeyError:
        print("Requirement #2.3.1.1 failed, Program could not find policy 'Accounts: Block Microsoft accounts'")
    except ValueError:
        print("Requirement #2.3.1.1 failed, you do not have the policy 'Accounts: Block Microsoft accounts' applied'")  

    try:   
        if group_policy_values['Accounts: Guest account status'] == 'Disabled': 
            score += 1
        else:
            print("Requirement #2.3.1.2 failed, to score for this set 'Accounts: Guest account status' to 'Disabled'")
    except KeyError:
        print("Requirement #2.3.1.2 failed, Program could not find policy 'Accounts: Guest account status'")
    except ValueError:
        print("Requirement #2.3.1.2 failed, you do not have the policy 'Accounts: Guest account status' applied'")          

    try:   
        if group_policy_values['Accounts: Limit local account use of blank passwords to console logon only'] == 'Enabled': 
            score += 1
        else:
            print("Requirement #2.3.1.3 failed, to score for this set 'Accounts: Limit local account use of blank passwords to console logon only' to 'Enabled'")
    except KeyError:
        print("Requirement #2.3.1.3 failed, Program could not find policy 'Accounts: Limit local account use of blank passwords to console logon only'")
    except ValueError:
        print("Requirement #2.3.1.3 failed, you do not have the policy 'Accounts: Limit local account use of blank passwords to console logon only' applied'")  
    ###################################################
    ## 2.3.1.4 goes here when methodology discovered ##
    ###################################################

    ###################################################
    ## 2.3.1.5 goes here when methodology discovered ##
    ###################################################

    try:   
        if group_policy_values['Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'] == 'Enabled': 
            score += 1
        else:
            print("Requirement #2.3.2.1 failed, to score for this set 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' to 'Enabled'")
    except KeyError:
        print("Requirement #2.3.2.1 failed, Program could not find policy 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'")
    except ValueError:
        print("Requirement #2.3.2.1 failed, you do not have the policy 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' applied'") 

    try:   
        if group_policy_values['Audit: Shit down system immediately if unable to log security audits'] == 'Disabled': 
            score += 1
        else:
            print("Requirement #2.3.2.2 failed, to score for this set 'Audit: Shit down system immediately if unable to log security audits' to 'Disabled'")
    except KeyError:
        print("Requirement #2.3.2.2 failed, Program could not find policy 'Audit: Shit down system immediately if unable to log security audits'")
    except ValueError:
        print("Requirement #2.3.2.2 failed, you do not have the policy 'Audit: Shit down system immediately if unable to log security audits' applied'") 

    try:   
        if group_policy_values['Audit: Shit down system immediately if unable to log security audits'] == 'Disabled': 
            score += 1
        else:
            print("Requirement #2.3.2.2 failed, to score for this set 'Audit: Shit down system immediately if unable to log security audits' to 'Disabled'")
    except KeyError:
        print("Requirement #2.3.2.2 failed, Program could not find policy 'Audit: Shit down system immediately if unable to log security audits'")
    except ValueError:
        print("Requirement #2.3.2.2 failed, you do not have the policy 'Audit: Shit down system immediately if unable to log security audits' applied'")

    try:   
        if group_policy_values['Devices: Allowed to format and eject removable media'] == 'Administrators': 
            score += 1
        else:
            print("Requirement #2.3.4.1 failed, to score for this set 'Devices: Allowed to format and eject removable media' to 'Administrators'")
    except KeyError:
        print("Requirement #2.3.4.1 failed, Program could not find policy 'Devices: Allowed to format and eject removable media'")
    except ValueError:
        print("Requirement #2.3.4.1 failed, you do not have the policy 'Devices: Allowed to format and eject removable media' applied'")

    try:   
        if group_policy_values['Devices: Prevent users from installing printer drivers'] == 'Enabled': 
            score += 1
        else:
            print("Requirement #2.3.4.2 failed, to score for this set 'Devices: Prevent users from installing printer drivers' to 'Enabled'")
    except KeyError:
        print("Requirement #2.3.4.2 failed, Program could not find policy 'Devices: Prevent users from installing printer drivers'")
    except ValueError:
        print("Requirement #2.3.4.2 failed, you do not have the policy 'Devices: Prevent users from installing printer drivers' applied'")

    #######################
    ## total Score print ##
    #######################
    print("****************************************************************************************")
    print("********************************** score total = ", score, "**********************************")
    print("****************************************************************************************")
    print("""******** 
2.3.1.4 requires that 'Accounts: Rename administrator account' is 
configured in a maner that does not denote that the account has administrative 
or elevated acces, need to figure out method of accomplishing this benchmark
2.3.1.5 is similar, regarding Guest accounts. 
**********""")      
    
    


if __name__ == '__main__':
    print("****Combining policy files for reading*****")
    conc_policy_files()
    gpo_scoring()
    # exports group policy inf to script directory
    # but not the entirity of local policy settings, do they need to be active to work?
    #os.system('secedit /export /cfg secconfig.cfg')
    #commented out os.system command, possibly permanently, instead of grabbing seceditfiles I manualy exported individual policies.
    #gpo_dictionary()

