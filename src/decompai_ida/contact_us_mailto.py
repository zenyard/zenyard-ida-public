import webbrowser
from urllib.parse import quote


def send_email_with_mailto(recipient, subject, body):
    """
    Opens the default email client with a pre-filled email.
    """
    # URL-encode the subject and body to handle spaces and special characters
    encoded_subject = quote(subject)
    encoded_body = quote(body)

    # Construct the mailto URL with parameters
    mailto_url = (
        f"mailto:{recipient}?subject={encoded_subject}&body={encoded_body}"
    )

    # Open the URL using the default web browser (which opens the email client)
    webbrowser.open(mailto_url)


# Example usage:
EMAIL_ADDRESS = "access@zenyard.ai"
EMAIL_SUBJECT = "Zenyard trial ended - set up continued access"
EMAIL_BODY = """Hi Zenyard team,
My Zenyard trial ended and I'd like to continue.

Organization: [COMPANY NAME]
Team size: [# USERS]
Deployment: Cloud / Private cloud / On-prem / Not sure
Constraints: [air-gapped, compliance, sensitive binaries, etc.]

Thanks,
[NAME]
"""
