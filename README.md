# Checking SMB file shares (public) in Active Directory environment

## Usage:
  You can change your AD account, email, app password in config.ini
  ### Summary of <code>option</code> flag

| Option      | Description                                           | Example Command                                           |
|-------------|-------------------------------------------------------|----------------------------------------------------------|
| `-la`      | List all SMB public shares from the IP list.   | `python3 checksharefile.py -la ` |
| `-e`      | Send email alerts for detected public shares.      | `python3 checksharefile.py -la -e ` |
| `-t` | Set the interval time in seconds to run the scan automatically (or send email) | `python3 checksharefile.py -la -e -t 300` |
