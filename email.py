import pandas as pd
import subprocess

# Load your CSV file (must have columns: name, email)
df = pd.read_csv('/Users/austinpham/Downloads/test.csv')

for _, row in df.iterrows():
    subject = "Personalized Greeting"
    # Plain text body. You can customize this however you like.
    body_text = f"Hello {row['name']},\n\nThis is a test email sent via AppleScript through Outlook on Mac.\n\nBest regards,\nAustin"

    recipient_email = row['email']
    cc_email = row['cc_email']


    # Escape double quotes in subject and body for AppleScript
    subject_escaped = subject.replace('"', '\\"')
    body_escaped = body_text.replace('"', '\\"')

    applescript = f'''
tell application "Microsoft Outlook"
    set newMessage to make new outgoing message with properties {{subject:"{subject_escaped}", content:"{body_escaped}"}}
    make new recipient at newMessage with properties {{email address:{{address:"{recipient_email}"}}}}
    make new recipient at newMessage with properties {{email address:{{address:"{cc_email}"}}, type:cc recipient}}

    send newMessage
end tell
'''

    try:
        subprocess.run(['osascript', '-e', applescript], check=True)
        print(f"Sent email to {recipient_email}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to send email to {recipient_email}: {e}")
