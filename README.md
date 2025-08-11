# HIBP Email & Password Checker

Python script to check if your email got breached or your password was leaked. Uses the Have I Been Pwned API.

## What it does

- Check if your email shows up in data breaches
- See if passwords have been compromised (doesn't send your actual password)
- Save results to files
- Basic email validation

## Setup

You need Python 3.7+ and these packages:
```bash
pip install requests python-dotenv
```

Get an API key from https://haveibeenpwned.com/API/Key (costs about $3.50/month)

Create a `.env` file in the same folder:
```
HIBP_API_KEY=paste_your_key_here
```

## How to use it

Run the script:
```bash
python hibp_checker.py
```

You'll get a menu with 4 options:
1. Check email for breaches
2. Check password (secure)
3. Check both email and password
4. Exit

### Email checking
Type in an email and it shows you any breaches it's been in:
```
Email found in 2 breaches:
  1. Adobe - 2013-10-04 (152,445,165 accounts)
  2. LinkedIn - 2012-05-05 (164,611,595 accounts)
```

### Password checking
Enter a password (hidden input) and it checks if it's been leaked. Uses k-anonymity so your actual password never gets sent anywhere.

## Common problems

**API key not found** - Make sure your `.env` file is set up correctly

**Rate limit hit** - Wait a few minutes, the API has limits

**Network errors** - Check your connection or try again later

**Invalid API key** - Double-check the key from HIBP and make sure your subscription is active

## Output files

When you save results, you get JSON files like `hibp_results_20250811_143022.json` with all the breach details.

## Code sources

Email validation regex from: https://github.com/ianpottinger/Python3/blob/24fbc83162bc77a9a4a383be5d2c134274310ce7/regex.py (MIT License)

Used pattern:
```python
pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
return re.match(pattern, email) is not None
```

## License

MIT License - use it however you want.

## Disclaimer

This is for checking your own accounts. Don't be creepy and check other people's stuff without permission.
