import email
import os
import re
import quopri
import tldextract
import ipaddress
import hashlib
from datetime import datetime
from email import policy
from bs4 import BeautifulSoup
from termcolor import colored


def format_multiple(attribute, input_list):
    """ Returns formatted strings based on the content of the variable """
    if not input_list:
        string = f'{attribute} None'
    elif len(input_list) == 1:
        string = f'{attribute} {input_list[0]}'
    else:
        string = attribute
        for element in input_list:
            string += f'\n\t- {element}'
    return string


class Email:
    def __init__(self, file_path):
        self.path = file_path
        self.filename = os.path.basename(file_path)
        self.output_path = os.path.splitext(self.path)[0]

        # Headers
        self.from_h = None
        self.sender_h = None
        self.x_sender_h = None
        self.received_spf = None
        self.to_h = None
        self.cc_h = None
        self.bcc_h = None
        self.delivered_to_h = None
        self.return_path_h = None
        self.reply_to_h = None
        self.subject_h = None
        self.date_h = None
        self.user_agent_h = None
        self.relay_full_h = None

        # Body
        self.urls = []
        self.ips = []
        self.domains = []
        self.attachments = None
        self.plain_body = None
        self.html_body = None

    def print_to_file(self):
        """ Prints analysis to file. """
        with open(os.path.join(self.output_path, "analysis.txt"), "w") as of:
            try:
                of.write(f"File name: {self.filename}\n")

                # Headers
                of.write(f"From: {self.from_h}\n")
                of.write(f"Sender: {self.sender_h}\n")
                of.write(f"X-Sender: {self.x_sender_h}\n")
                of.write(f"Received-SPF: {self.received_spf}\n")
                of.write(f"To: {self.to_h}\n")
                of.write(f"CC: {self.cc_h}\n")
                of.write(f"BCC: {self.bcc_h}\n")
                of.write(f"Delivered-To: {self.delivered_to_h}\n")
                of.write(f"Return-Path: {self.return_path_h}\n")
                of.write(f"Reply-To: {self.reply_to_h}\n")
                of.write(f"Subject: {self.subject_h}\n")
                of.write(f"Date: {self.date_h}\n")
                of.write(f"User-Agent: {self.user_agent_h}\n")
                of.write("Relay Full:")
                if self.relay_full_h:
                    of.write(f"{self.relay_full_h}\n")
                else:
                    of.write("\tNone\n")

                # Body
                of.write(f"URLs: {self.urls}\n")
                of.write(f"IPs: {self.ips}\n")
                of.write(f"Domains: {self.domains}\n")
                if self.attachments:
                    of.write("Attachments:")
                    for value in self.attachments:
                        of.write(f"\n\t- {value['filename']}")
                        of.write(f"\n\t\t- MD5: {value['MD5']}")
                        of.write(f"\n\t\t- SHA256: {value['SHA256']}")
                else:
                    of.write(f"Attachments: None")
            except (IOError, OSError):
                print(colored("Couldn't print analysis to file.", "red"))

    def print_cli(self):
        """ Prints the list of the most important analized email attributes to stdout. """
        print("File name:", self.filename)
        print("From:", self.from_h)
        print("Sender:", self.sender_h)
        print("Received-SPF:", self.received_spf)
        print(format_multiple("To:", self.to_h))
        print("CC:", self.cc_h)
        print("Return-Path:", self.return_path_h)
        print("Reply-To:", self.reply_to_h)
        print("Subject:", self.subject_h)
        print(format_multiple("URLs:", self.urls))
        print(format_multiple("IPs:", self.ips))
        print(format_multiple("Domains:", self.domains))
        if self.attachments:
            print("Attachments:")
            for value in self.attachments:
                print("\t-", value['filename'])
                print("\t\t- MD5:", value['MD5'])
        else:
            print("Attachments:", self.attachments)

    def print_cli_full(self):
        """ Prints the full list of analized email attributes to the stdout """
        print("File name:", self.filename)
        # Headers
        print("From:", self.from_h)
        print("Sender:", self.sender_h)
        print("X-Sender:", self.x_sender_h)
        print("Received-SPF:", self.received_spf)
        print(format_multiple("To:", self.to_h))
        print("CC:", self.cc_h)
        print("BCC:", self.bcc_h)
        print("Delivered-To:", self.delivered_to_h)
        print("Return-Path:", self.return_path_h)
        print("Reply-To:", self.reply_to_h)
        print("Subject:", self.subject_h)
        print("Date:", self.date_h)
        print("User-Agent:", self.user_agent_h)
        print("Relay Full:")
        if self.relay_full_h:
            for key, value in self.relay_full_h.items():
                print(f"\t{key + 1}.", value)
        else:
            print("\tNone")
        print(format_multiple("URLs:", self.urls))
        print(format_multiple("IPs:", self.ips))
        print(format_multiple("Domains:", self.domains))
        if self.attachments:
            print("Attachments:")
            for value in self.attachments:
                print("\t-", value['filename'])
                print("\t\t- MD5:", value['MD5'])
                print("\t\t- SHA256:", value['SHA256'])
        else:
            print("Attachments:", self.attachments)

    def extract_attachments(self):
        """ Extracts all attachments from the email. """
        with open(self.path, 'r') as eml_file:
            msg = email.message_from_file(eml_file, policy=policy.default)
        # Attachments
        attachments_list = []
        attach_directory = self.output_path + "/attachments"
        os.path.exists(attach_directory) or os.makedirs(attach_directory)
        for attachment in msg.iter_attachments():
            try:
                # Extract the attachment filename
                attachment_filename = attachment.get_filename()
                attachment_filename = os.path.basename(attachment_filename)
            except AttributeError:
                continue

            # If no attachments are found, skip this file
            if attachment_filename:
                if attachment.get_payload(decode=True):
                    filemd5 = hashlib.md5(attachment.get_payload(decode=True)).hexdigest()
                    filesha256 = hashlib.sha256(attachment.get_payload(decode=True)).hexdigest()
                    with open(os.path.join(attach_directory, attachment_filename), "wb") as of:
                        try:
                            of.write(attachment.get_payload(decode=True))
                        except TypeError:
                            print(f"Couldn't get payload for {attachment_filename}")
                    attachments_list.append({"filename": attachment_filename, "MD5": filemd5, "SHA256": filesha256})
        if attachments_list:
            self.attachments = attachments_list

    def extract_web_objects(self):
        """ Extract URLs, IPs and domains from the body. """
        url_pattern = r"/(?i)\b((?:https?|ftp|ipns|ipfs):\/\/\S+)\b/gm"
        ip_pattern = r"(?i)\b((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})\b"
        temp_ips = []
        # Extract IPs and URLs from the plaintext body
        if self.plain_body:
            self.urls.extend(re.findall(url_pattern, self.plain_body))
            temp_ips.extend(re.findall(ip_pattern, self.plain_body))

        # Extract IPs and URLs from the plaintext body
        if self.html_body:
            soup = BeautifulSoup(self.html_body, 'html.parser')
            urls = []
            for tag in soup.find_all('a'):
                href = tag.get('href')
                if href:
                    urls.append(href)
            for url in urls:
                self.urls.append(url)
            urls = []
            for tag in soup.find_all('img'):
                href = tag.get('src')
                if href:
                    urls.append(href)
            for url in urls:
                self.urls.append(url)
            temp_ips.extend(re.findall(ip_pattern, self.html_body))

        # Extract domains
        for url in self.urls:
            tld_cache = tldextract.TLDExtract()
            analyzeddomain = tld_cache(url).registered_domain
            if analyzeddomain:
                self.domains.append(analyzeddomain)

        # Verify IPs
        for ip in temp_ips:
            try:
                self.ips.append(str(ipaddress.ip_address(ip)))
            except ValueError:
                continue

        # Remove duplicates
        self.ips = [i for n, i in enumerate(self.ips) if i not in self.ips[:n]]
        self.urls = [i for n, i in enumerate(self.urls) if i not in self.urls[:n]]
        self.domains = [i for n, i in enumerate(self.domains) if i not in self.domains[:n]]

    def analyze_body(self):
        """ Retrieves the body of the email. """
        with open(self.path, 'r') as eml_file:
            msg = email.message_from_file(eml_file, policy=policy.default)
        # Body
        body_directory = self.output_path + "/body"
        os.path.exists(body_directory) or os.makedirs(body_directory)
        body_plain_raw = None
        body_html_raw = None
        for part in msg.walk():
            # Check if the part is the main body of the message
            content_type = part.get_content_type()

            if content_type == "text/plain":
                body_plain_raw = part.get_payload(decode=True)
                break
            elif content_type == "text/html":
                body_html_raw = part.get_payload(decode=True)
                break
        # Plain text body
        if isinstance(body_plain_raw, bytes):
            # Write to file
            self.plain_body = body_plain_raw.decode()
            with open(os.path.join(body_directory, "plain_body"), "w") as of:
                try:
                    of.write(self.plain_body)
                except TypeError:
                    print(colored("Couldn't extract plain-text body.", "red"))
        # HTML body
        if isinstance(body_html_raw, bytes):
            try:
                self.html_body = body_html_raw.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    self.html_body = self.html_body.decode('latin-1')
                except UnicodeDecodeError:
                    # Handle decoding error
                    self.html_body = quopri.decodestring(self.html_body).decode('utf-8')
            # Write to file
            with open(os.path.join(body_directory, "html_body.html"), "w") as of:
                try:
                    of.write(self.html_body)
                except TypeError:
                    print(colored("Couldn't extract HTML body.", "red"))

        # Extract IPs, URLs and Domains
        self.extract_web_objects()

    def analyze(self):
        """ Main function. Extracts headers. """
        # Create output folder if it does not exist
        os.path.exists(self.output_path) or os.makedirs(self.output_path)
        # Get eml file contents
        with open(self.path, 'r') as eml_file:
            msg = email.message_from_file(eml_file, policy=policy.default)
        # Start extracting fields
        # Headers
        self.from_h = msg['From']
        self.sender_h = msg['Sender']
        self.x_sender_h = msg['X-Sender']
        self.received_spf = msg['Received-SPF']
        self.to_h = (msg["To"]).split(", ")
        cc_list = []
        if msg["Cc"]:
            for address in msg["Cc"].split(","):
                if address:
                    cc_list.append(address)
            if cc_list:
                # Remove possible duplicates and create a numbered dictionary
                mail_cc_list = dict(zip(range(len(list(set(cc_list)))), list(set(cc_list))))
                self.cc_h = mail_cc_list
        self.bcc_h = msg['Bcc']
        self.delivered_to_h = msg["Delivered-To"]
        self.reply_to_h = msg["Reply-To"]
        self.return_path_h = msg['Return-Path']
        self.subject_h = msg['Subject']
        email_date = datetime.strptime(msg['Date'], '%a, %d %b %Y %H:%M:%S %z')
        self.date_h = email_date.strftime("%d/%m/%Y %H:%M:%S")
        self.user_agent_h = msg["User-Agent"]
        # Full Relay and IP only
        hoplist = []
        received = msg.get_all("Received")
        received.reverse()
        for line in received:
            hops = re.findall(r"from\s+(.*?)\s+by\s+(.*?)(?:\s+with\s+(.*?)\s+id\s*(.*?))?$", line, re.DOTALL | re.X)
            for hop in hops:
                if hop[0]:
                    hoplist.append(hop[0])
        if hoplist:
            self.relay_full_h = dict(zip(range(len(hoplist)), hoplist))
