import os
import json
import hashlib
import requests
import time
from dotenv import load_dotenv
from datetime import datetime

class HaveIBeenPwnedChecker:
    def __init__(self):
        # Load the environment variables from .env
        load_dotenv()
        
        # Get the API key from the environment variables
        self.API_KEY = os.getenv('HIBP_API_KEY')
        self.api_url = 'https://haveibeenpwned.com/api/v3'
        
        # Check if API key is loaded
        if not self.API_KEY:
            print("❌ Error: HIBP_API_KEY not found in environment variables")
            print("Please create a .env file with: HIBP_API_KEY=your_api_key_here")
            exit(1)
        
        # Set up headers with required User-Agent
        self.headers = {
            'hibp-api-key': self.API_KEY,
            'User-Agent': 'Python-HIBP-Checker/1.0'
        }
    
    def check_breached_account(self, email):
        """Check if an email account has been breached"""
        print(f"🔍 Checking breaches for: {email}")
        
        try:
            # Send the GET request to the HIBP API
            response = requests.get(
                f'{self.api_url}/breachedaccount/{email}', 
                headers=self.headers,
                timeout=10
            )
            
            # Check the status code of the response
            if response.status_code == 404:
                print("✅ Good news! Email not found in any data breaches")
                return []
            elif response.status_code == 401:
                print("❌ Error: Invalid or missing API key")
                return None
            elif response.status_code == 429:
                print("⚠️ Error: Rate limit exceeded. Please wait before trying again")
                return None
            elif response.status_code == 400:
                print("❌ Error: Bad request - please check the email format")
                return None
            elif response.status_code != 200:
                print(f"❌ Error checking email (Status: {response.status_code})")
                return None
            else:
                # Parse the response and extract breach information
                breaches_data = response.json()
                breach_names = [breach['Name'] for breach in breaches_data]
                
                print(f"⚠️ Email found in {len(breach_names)} breach(es):")
                for i, breach in enumerate(breaches_data[:5], 1):  # Show details for first 5
                    print(f"  {i}. {breach['Name']} - {breach['BreachDate']} ({breach['PwnCount']:,} accounts)")
                
                if len(breaches_data) > 5:
                    print(f"  ... and {len(breaches_data) - 5} more breaches")
                
                return breaches_data
                
        except requests.exceptions.Timeout:
            print("⏰ Request timed out. Please try again later")
            return None
        except requests.exceptions.ConnectionError:
            print("🌐 Connection error. Please check your internet connection")
            return None
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None
        except json.JSONDecodeError:
            print("❌ Error parsing response from API")
            return None
    
    def check_pwned_passwords(self, password):
        """Check if a password has been pwned using k-anonymity"""
        print("🔍 Checking if password has been pwned...")
        
        # Generate SHA-1 hash of password
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Use k-anonymity - only send first 5 characters
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]
        
        try:
            # Query the Pwned Passwords API
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=10
            )
            
            if response.status_code != 200:
                print(f"❌ Error checking password (Status: {response.status_code})")
                return None
            
            # Check if our password hash suffix is in the response
            hashes = response.text.splitlines()
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    count = int(count)
                    print(f"⚠️ Password has been pwned {count:,} times!")
                    return count
            
            print("✅ Password not found in pwned passwords database")
            return 0
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error checking password: {e}")
            return None
    
    def save_results_to_file(self, email, breaches, filename=None):
        """Save breach results to a JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"hibp_results_{timestamp}.json"
        
        data = {
            "email": email,
            "check_date": datetime.now().isoformat(),
            "breach_count": len(breaches) if breaches else 0,
            "breaches": breaches
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"💾 Results saved to {filename}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")
    
    def validate_email(self, email):
        """Basic email validation"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

def main():
    print("🔐 Have I Been Pwned Checker")
    print("=" * 30)
    
    checker = HaveIBeenPwnedChecker()
    
    while True:
        print("\nOptions:")
        print("1. Check email for breaches")
        print("2. Check password (secure)")
        print("3. Check both email and password")
        print("4. Exit")
        
        choice = input("\nSelect an option (1-4): ").strip()
        
        if choice == '1':
            email = input("Enter your email address: ").strip().lower()
            
            if not checker.validate_email(email):
                print("❌ Invalid email format")
                continue
            
            breaches = checker.check_breached_account(email)
            
            if breaches is not None and len(breaches) > 0:
                save_choice = input("\n💾 Save results to file? (y/n): ").strip().lower()
                if save_choice == 'y':
                    checker.save_results_to_file(email, breaches)
        
        elif choice == '2':
            import getpass
            password = getpass.getpass("Enter password (hidden): ")
            
            if len(password) < 1:
                print("❌ Password cannot be empty")
                continue
            
            checker.check_pwned_passwords(password)
        
        elif choice == '3':
            email = input("Enter your email address: ").strip().lower()
            
            if not checker.validate_email(email):
                print("❌ Invalid email format")
                continue
            
            import getpass
            password = getpass.getpass("Enter password (hidden): ")
            
            if len(password) < 1:
                print("❌ Password cannot be empty")
                continue
            
            print("\n" + "="*50)
            breaches = checker.check_breached_account(email)
            print("\n" + "-"*50)
            checker.check_pwned_passwords(password)
            
            if breaches is not None and len(breaches) > 0:
                save_choice = input("\n💾 Save breach results to file? (y/n): ").strip().lower()
                if save_choice == 'y':
                    checker.save_results_to_file(email, breaches)
        
        elif choice == '4':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid option. Please select 1-4")
        
        # Add a small delay to respect rate limits
        time.sleep(1)

if __name__ == "__main__":
    main()
