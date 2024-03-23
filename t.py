import win32com.client

def has_email_items(folder):
    try:
        # Attempt to restrict items to "IPM.Note" to quickly check for emails
        emails = folder.Items.Restrict("[MessageClass]='IPM.Note'")
        return emails.Count > 0
    except:
        return False

def find_email_folders(folder, email_folders=None):
    if email_folders is None:
        email_folders = []
            
    email_folders.append(folder)

    for subfolder in folder.Folders:
        if not has_email_items(subfolder):
            continue
        find_email_folders(subfolder, email_folders)

    return email_folders

# Initialize Outlook and get the namespace
outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")

# Start the search from the root folder
root_folder = outlook.Folders.Item(1)  # Adjust as necessary

# Find folders that contain emails
folders_with_emails = find_email_folders(root_folder)

# Print the names of found folders
for folder in folders_with_emails:
    print(folder.Name)
