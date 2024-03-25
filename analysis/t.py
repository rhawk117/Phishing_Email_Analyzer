import re 


import re

def extract_email_from_return_path(return_path):
    # Regular expression to find the pattern
    pattern = re.compile(r'([a-zA-Z0-9._%+-]+)=([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    match = pattern.search(return_path)
    if match:
        # Reconstruct the email from the matched groups, replacing '=' with '@'
        return f"{match.group(1)}@{match.group(2)}"
    else:
        # If no special pattern is found, return the return path as is
        return return_path

# Example usage
return_path = "bounces+5004-2bac-rhawkins1=augusta.edu@navigate.advisement.augusta.edu"
actual_email = extract_email_from_return_path(return_path)
print(actual_email)




pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')


sample = ["AU_ADA <AU_ADA@augusta.edu>", "Jennifer Youmans <jyoumans@advisement.augusta.edu>"]


for i in sample:
    match = pattern.search(i)
    if match:
        print(match.group(0))
    else:
        print("No Match")