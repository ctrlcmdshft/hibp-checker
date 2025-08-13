# HIBP Email & Password Checker

Python script to check if your email got breached or password was leaked. Uses the Have I Been Pwned API to dig through data breaches and paste dumps.


## Features

- Check if your email shows up in data breaches
- See if passwords have been compromised (doesn't send your actual password)
- Look through paste dumps (Pastebin, etc.) for your email
- Browse the entire HIBP database
- Search for specific breach details
- Find breaches affecting certain domains
- See what types of data get stolen in breaches
- Save results to files (cross-platform, uses pathlib)
- Basic email validation
- **Type hints** for all major functions
- **Improved error handling** and user messages
- **Automated tests** with pytest (see `tests/`)
- **New CLI options:**
  - `--quiet` : Suppress most output (only errors)
  - `--json`  : Output results as JSON
  - `--version` : Show version and exit

## Getting it running


### Requirements
- Python 3.7+
- requests
- python-dotenv
- pytest (for testing)

Install all dependencies:
```bash
pip install -r requirements.txt
```


**You need an API key** from https://haveibeenpwned.com/API/Key. Pricing (as of August 2025):

- **Pwned 1**: $4.50/month — 10 email searches per minute, up to 25 breached email addresses per domain
- **Pwned 2**: $22/month — 50 email searches per minute, up to 100 breached email addresses per domain
- **Pwned 3**: $37.50/month — 100 email searches per minute, up to 500 breached email addresses per domain
- **Pwned 4**: $163/month — 500 email searches per minute, unlimited breached email addresses per domain
- **Pwned 5**: $326/month — 1,000 email searches per minute, unlimited breached email addresses per domain, includes domain-level stealer log search
- **Ultra/Enterprise**: Up to 12,000 RPM and custom pricing for high-volume or enterprise use

See the [official HIBP pricing page](https://haveibeenpwned.com/Subscription) for the latest details.

Most personal email and password checks are free on the HIBP website, but API access for automation requires a paid subscription.



Make a `.env` file in the same folder:
```
HIBP_API_KEY=your_actual_key_here
```




## How to use it

### Interactive mode
```bash
python hibp_checker.py
```

### CLI mode
```bash
python hibp_checker.py --email test@example.com --save
python hibp_checker.py --password "yourpassword" --json
python hibp_checker.py --all-breaches --save --quiet
```

#### Additional CLI Options
- `--quiet` : Suppress most output (only errors)
- `--json`  : Output results as JSON
- `--version` : Show version and exit

You get 9 options to pick from in interactive mode:
1. **Check email for breaches** - See if your email is in any breaches
2. **Check password** - Test if password has been pwned
3. **Check both** - Do email and password at once
4. **Check email in pastes** - Look through Pastebin dumps
5. **Get all breaches** - Browse the whole HIBP database
6. **Search specific breach** - Look up Adobe, LinkedIn, etc. by name
7. **Search by domain** - Find breaches affecting gmail.com, yahoo.com, etc.
8. **View data types** - See what kinds of stuff gets stolen
9. **Exit**

## What you'll see

### Email checking
Shows you detailed breach info:
```
BREACH #1
--------------------------------------------------
Name: Adobe
Domain: adobe.com
Breach Date: 2013-10-04
Accounts Affected: 152,445,165
Data Compromised: Email addresses, Password hints, Passwords, Usernames
Verified: Yes
Description: In October 2013, 153 million Adobe accounts were breached...
```

### Password checking
Uses a secure method that doesn't send your actual password:
- Only sends first 5 characters of a hash
- Your password never leaves your computer
- Shows risk level:
  - 🚨 **CRITICAL**: Super common password, change it now
  - ⚠️ **HIGH RISK**: Very commonly used
  - ⚠️ **MEDIUM RISK**: Seen this before
  - ⚠️ **LOW RISK**: Found but not too common
  - ✅ **SECURE**: Not in the database

### Paste dumps
Finds if your email appears in data dumps:
```
PASTE #1
----------------------------------------
Source: Pastebin
ID: 8VN0a4Cl
Title: Database dump
Date: 2019-03-01
Email Count: 12,345
```

### Database browsing
- **All breaches**: See recent major breaches
- **Specific lookups**: Get full details on any breach
- **Domain search**: Check what breaches hit specific websites
- **Data types**: Browse all 30+ types of data that gets stolen


## Security Notice
- **Never use your real passwords for testing or on the command line.**
- Your API key and sensitive data should be kept private. `.env` is already in `.gitignore`.

## When stuff breaks

**"API key not found"** - Check your .env file has `HIBP_API_KEY=your_key`

**"Rate limit exceeded"** - Slow down, you're making too many requests

**Network errors** - Internet connection issues, try again later

**"Invalid API key"** - Double-check you copied the key right and subscription is active

**"Unauthorized"** - API key might be expired

## Output files

Save results to JSON files like `hibp_results_20250811_143022.json`:
```json
{
  "email": "user@example.com",
  "check_date": "2025-08-11T14:30:22.123456",
  "breach_count": 2,
  "breaches": [
    {
      "Name": "Adobe",
      "BreachDate": "2013-10-04",
      "PwnCount": 152445165,
      "DataClasses": ["Email addresses", "Passwords"]
    }
  ]
}
```


## Ways to use this

**Check your own stuff (interactive):**
```bash
python hibp_checker.py
# Pick option 3, enter your email and password
```

**Research your company (interactive):**
```bash
python hibp_checker.py
# Pick option 7, enter your company domain
```

**Look up specific breaches (interactive):**
```bash
python hibp_checker.py
# Pick option 6, search "Adobe" or "LinkedIn"
```

**Scripted/automated use (CLI):**
```bash
python hibp_checker.py --email user@example.com --save --json
python hibp_checker.py --all-breaches --quiet --json
```

## Code I borrowed

Email validation regex from: https://github.com/ianpottinger/Python3/blob/24fbc83162bc77a9a4a383be5d2c134274310ce7/regex.py (MIT License)

```python
pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
return re.match(pattern, email) is not None
```


## Testing

Run all tests:
```bash
pytest
```

## Issues

Found a bug? Got an idea? Open an issue:
[Create new issue](https://github.com/yourusername/hibp-checker/issues/new)

## License

MIT License - use it however you want.

## Attribution

This project uses the Have I Been Pwned API. Data provided by [Have I Been Pwned](https://haveibeenpwned.com/) is licensed under the [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/). Clear and visible attribution to HIBP is required in any public or commercial use of this tool or its data. See the [API documentation](https://haveibeenpwned.com/API/v3) for details.

## Don't be a creep

This is for checking your own stuff or legitimate security research. Don't:
- Check other people's emails without permission
- Abuse the API or ignore rate limits
- Use this for harassment or stalking

Be responsible about it.

## Contributing

Want to add features?
1. Fork it
2. Make a branch
3. Code something useful
4. Test it properly
5. Send a pull request

## Recent changes

**v1.0.0**
- Basic email and password checking
- Added detailed breach info
- Paste checking
- Database browsing
- File saving
- Better error handling
