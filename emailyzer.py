import argparse
from email_class import Email

# argparse
parser = argparse.ArgumentParser(
    prog='Emailyzer',
    description='Email analysis tool'
)
parser.add_argument('eml_file')
parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Prints the full analysis on stdout. Disabled by default.')
parser.add_argument('-m', '--mute', action='store_true', default=False, help='Does not print anything in the stdout.')
arguments = parser.parse_args()

filename = arguments.eml_file
email_object = Email(filename)
email_object.analyze()
email_object.analyze_body()
email_object.print_to_file()
email_object.extract_attachments()
# Print analysis to stdout
if arguments.verbose:
    email_object.print_cli_full()
elif not arguments.mute:
    email_object.print_cli()
