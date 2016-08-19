#run as administrator in cmd prompt
import os
import sys
 
#function to make key value pairs from lines
def gpo_dictionary():
    print("****Group Policy is being written into dictionary*****")
    #opens the encoded data and prints line by line
    with open('group-policy.inf', 'r', encoding='utf-16') as f:
        data = []
        while True:
            x=f.readline()
            if not x:
                break
            data.append(x) 
    group_policy_values = {}
    for i in data:
        item = i.split('=')
        #IndexError comes from some indexes not containing '='
        try:
            group_policy_values[item[0].strip()] = item[1].strip()         
        except IndexError:
            continue       
    return group_policy_values
 
#scores based off of key value/pairs
#Current error is: Line 37 | NameError: name 'foo' is not defined, though gpo_dictionary() is called.
def gpo_scoring():
    score = 0
    group_policy_values = gpo_dictionary()
    print("****Group Policy is being scored****")
 
    #score for password history size
    if group_policy_values['PasswordHistorySize'] == '0':
        score += 1
        print("score = ",score)
    else:
        print("Requirement #x.x failed, to score for this toggle 'x' to 'x'")
        print("score =",score) 
       
    if group_policy_values['Revision'] == '1': 
        score += 1
        print("score = ",score)
    else:
        print("Requirement #x.x failed, to score for this toggle 'x' to 'x'")
        print("score =",score)
    print("total score = ",score)
 
if __name__ == '__main__':
    print("****Starting export of group-policy.inf*****")
    # exports group policy inf to script directory
    os.system('secedit /export /cfg group-policy.inf /log export.log')
    gpo_scoring()
