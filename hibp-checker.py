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
            # Send the GET request to the HIBP API with truncateResponse=false for full details
            response = requests.get(
                f'{self.api_url}/breachedaccount/{email}?truncateResponse=false', 
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
                
                print(f"⚠️ Email found in {len(breaches_data)} breach(es):")
                print("=" * 80)
                
                for i, breach in enumerate(breaches_data, 1):
                    print(f"\n🔴 BREACH #{i}")
                    print("-" * 50)
                    
                    # Basic info
                    print(f"Name: {breach.get('Name', 'Unknown')}")
                    print(f"Title: {breach.get('Title', 'Unknown')}")
                    print(f"Domain: {breach.get('Domain', 'Unknown')}")
                    print(f"Breach Date: {breach.get('BreachDate', 'Unknown')}")
                    print(f"Added to HIBP: {breach.get('AddedDate', 'Unknown')}")
                    print(f"Last Modified: {breach.get('ModifiedDate', 'Unknown')}")
                    
                    # Impact
                    pwn_count = breach.get('PwnCount', 0)
                    if pwn_count > 0:
                        print(f"Accounts Affected: {pwn_count:,}")
                    else:
                        print("Accounts Affected: Unknown")
                    
                    # Data types compromised
                    data_classes = breach.get('DataClasses', [])
                    if data_classes:
                        print(f"Data Compromised: {', '.join(data_classes)}")
                    else:
                        print("Data Compromised: Unknown")
                    
                    # Verification status
                    print(f"Verified: {'Yes' if breach.get('IsVerified', False) else 'No'}")
                    print(f"Fabricated: {'Yes' if breach.get('IsFabricated', False) else 'No'}")
                    print(f"Sensitive: {'Yes' if breach.get('IsSensitive', False) else 'No'}")
                    print(f"Retired: {'Yes' if breach.get('IsRetired', False) else 'No'}")
                    print(f"Spam List: {'Yes' if breach.get('IsSpamList', False) else 'No'}")
                    
                    # Description
                    description = breach.get('Description', '')
                    if description:
                        # Remove HTML tags for cleaner output
                        import re
                        clean_description = re.sub(r'<[^>]+>', '', description)
                        print(f"Description: {clean_description[:200]}{'...' if len(clean_description) > 200 else ''}")
                    
                    if i < len(breaches_data):
                        print("\n" + "="*80)
                
                # Ask if user wants detailed view for specific breach
                if len(breaches_data) > 1:
                    print(f"\n📋 Would you like detailed info on a specific breach?")
                    breach_choice = input(f"Enter breach number (1-{len(breaches_data)}) or 'n' to skip: ").strip()
                    
                    if breach_choice.isdigit() and 1 <= int(breach_choice) <= len(breaches_data):
                        self.show_detailed_breach_info(breaches_data[int(breach_choice) - 1])
                
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
    
    def show_detailed_breach_info(self, breach):
        """Show detailed information for a specific breach"""
        print("\n" + "="*80)
        print(f"🔍 DETAILED BREACH INFORMATION: {breach.get('Name', 'Unknown')}")
        print("="*80)
        
        print(f"Full Title: {breach.get('Title', 'N/A')}")
        print(f"Website Domain: {breach.get('Domain', 'N/A')}")
        print(f"Date of Breach: {breach.get('BreachDate', 'N/A')}")
        print(f"Date Added to HIBP: {breach.get('AddedDate', 'N/A')}")
        print(f"Last Updated: {breach.get('ModifiedDate', 'N/A')}")
        
        pwn_count = breach.get('PwnCount', 0)
        print(f"Total Accounts Compromised: {pwn_count:,}" if pwn_count > 0 else "Accounts Compromised: Unknown")
        
        # Logo path
        logo_path = breach.get('LogoPath', '')
        if logo_path:
            print(f"Logo: https://haveibeenpwned.com{logo_path}")
        
        # Data classes with better formatting
        data_classes = breach.get('DataClasses', [])
        if data_classes:
            print(f"\n📊 Types of Data Compromised:")
            for data_type in data_classes:
                print(f"  • {data_type}")
        
        # Status flags
        print(f"\n🏷️ Status Information:")
        print(f"  • Verified by HIBP: {'Yes' if breach.get('IsVerified', False) else 'No'}")
        print(f"  • Fabricated/Fake: {'Yes' if breach.get('IsFabricated', False) else 'No'}")
        print(f"  • Contains Sensitive Data: {'Yes' if breach.get('IsSensitive', False) else 'No'}")
        print(f"  • Retired from HIBP: {'Yes' if breach.get('IsRetired', False) else 'No'}")
        print(f"  • Spam List: {'Yes' if breach.get('IsSpamList', False) else 'No'}")
        
        # Full description
        description = breach.get('Description', '')
        if description:
            import re
            clean_description = re.sub(r'<[^>]+>', '', description)
            print(f"\n📝 Full Description:")
            print(f"{clean_description}")
    
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
                    
                    # Give security advice based on count
                    if count > 100000:
                        print("🚨 CRITICAL: This is an extremely common password!")
                    elif count > 10000:
                        print("⚠️ HIGH RISK: This password is very commonly used")
                    elif count > 1000:
                        print("⚠️ MEDIUM RISK: This password has been seen before")
                    else:
                        print("⚠️ LOW RISK: Password found but not very common")
                    
                    print("💡 Recommendation: Change this password immediately!")
                    return count
            
            print("✅ Password not found in pwned passwords database")
            print("👍 This password appears to be secure")
            return 0
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error checking password: {e}")
            return None
    
    def get_all_breaches(self):
        """Get all breaches in the HIBP database"""
        print("🔍 Fetching all breaches from HIBP database...")
        
        try:
            response = requests.get(
                f'{self.api_url}/breaches',
                headers=self.headers,
                timeout=15
            )
            
            if response.status_code != 200:
                print(f"❌ Error fetching breaches (Status: {response.status_code})")
                return None
            
            breaches = response.json()
            print(f"📊 Found {len(breaches)} total breaches in database")
            
            # Show summary
            print("\n🔴 Recent Major Breaches:")
            print("-" * 60)
            
            # Sort by date and show top 10
            sorted_breaches = sorted(breaches, key=lambda x: x.get('BreachDate', ''), reverse=True)
            for i, breach in enumerate(sorted_breaches[:10], 1):
                pwn_count = breach.get('PwnCount', 0)
                date = breach.get('BreachDate', 'Unknown')
                print(f"{i:2d}. {breach.get('Name', 'Unknown'):20} - {date} ({pwn_count:,} accounts)")
            
            return breaches
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None
    
    def get_breach_details(self, breach_name):
        """Get details for a specific breach by name"""
        print(f"🔍 Getting details for breach: {breach_name}")
        
        try:
            response = requests.get(
                f'{self.api_url}/breach/{breach_name}',
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 404:
                print(f"❌ Breach '{breach_name}' not found")
                return None
            elif response.status_code != 200:
                print(f"❌ Error fetching breach details (Status: {response.status_code})")
                return None
            
            breach = response.json()
            self.show_detailed_breach_info(breach)
            return breach
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None
    
    def get_data_classes(self):
        """Get all possible data classes from HIBP"""
        print("🔍 Fetching all data classes...")
        
        try:
            response = requests.get(
                f'{self.api_url}/dataclasses',
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code != 200:
                print(f"❌ Error fetching data classes (Status: {response.status_code})")
                return None
            
            data_classes = response.json()
            print(f"📊 Found {len(data_classes)} data class types:")
            print("=" * 50)
            
            for i, data_class in enumerate(data_classes, 1):
                print(f"{i:2d}. {data_class}")
            
            return data_classes
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None
    
    def check_pastes(self, email):
        """Check if email appears in pastes (Pastebin dumps)"""
        print(f"🔍 Checking pastes for: {email}")
        
        try:
            response = requests.get(
                f'{self.api_url}/pasteaccount/{email}',
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 404:
                print("✅ Email not found in any pastes")
                return []
            elif response.status_code != 200:
                print(f"❌ Error checking pastes (Status: {response.status_code})")
                return None
            
            pastes = response.json()
            print(f"⚠️ Email found in {len(pastes)} paste(s):")
            print("=" * 60)
            
            for i, paste in enumerate(pastes, 1):
                print(f"\n📋 PASTE #{i}")
                print("-" * 40)
                print(f"Source: {paste.get('Source', 'Unknown')}")
                print(f"ID: {paste.get('Id', 'Unknown')}")
                print(f"Title: {paste.get('Title', 'No title')}")
                print(f"Date: {paste.get('Date', 'Unknown')}")
                email_count = paste.get('EmailCount', 'Unknown')
                if isinstance(email_count, int):
                    print(f"Email Count: {email_count:,}")
                else:
                    print(f"Email Count: {email_count}")
                
                if i < len(pastes):
                    print()
            
            return pastes
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None
    
    def search_breaches_by_domain(self, domain):
        """Search for breaches affecting a specific domain"""
        print(f"🔍 Searching breaches for domain: {domain}")
        
        try:
            response = requests.get(
                f'{self.api_url}/breaches?domain={domain}',
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code != 200:
                print(f"❌ Error searching domain (Status: {response.status_code})")
                return None
            
            breaches = response.json()
            
            if not breaches:
                print(f"✅ No breaches found for domain: {domain}")
                return []
            
            print(f"⚠️ Found {len(breaches)} breach(es) affecting {domain}:")
            print("=" * 60)
            
            for i, breach in enumerate(breaches, 1):
                print(f"\n🔴 BREACH #{i}")
                print("-" * 40)
                print(f"Name: {breach.get('Name', 'Unknown')}")
                print(f"Breach Date: {breach.get('BreachDate', 'Unknown')}")
                pwn_count = breach.get('PwnCount', 0)
                print(f"Accounts: {pwn_count:,}" if pwn_count > 0 else "Accounts: Unknown")
                
                data_classes = breach.get('DataClasses', [])
                if data_classes:
                    print(f"Data: {', '.join(data_classes[:3])}{'...' if len(data_classes) > 3 else ''}")
            
            return breaches
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
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
        print("4. Check email in pastes (Pastebin dumps)")
        print("5. Get all breaches in database")
        print("6. Search specific breach details")
        print("7. Search breaches by domain")
        print("8. View all data class types")
        print("9. Exit")
        
        choice = input("\nSelect an option (1-9): ").strip()
        
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
            email = input("Enter your email address: ").strip().lower()
            
            if not checker.validate_email(email):
                print("❌ Invalid email format")
                continue
            
            checker.check_pastes(email)
        
        elif choice == '5':
            checker.get_all_breaches()
        
        elif choice == '6':
            breach_name = input("Enter breach name (e.g., Adobe, LinkedIn): ").strip()
            if breach_name:
                checker.get_breach_details(breach_name)
            else:
                print("❌ Breach name cannot be empty")
        
        elif choice == '7':
            domain = input("Enter domain (e.g., adobe.com): ").strip()
            if domain:
                checker.search_breaches_by_domain(domain)
            else:
                print("❌ Domain cannot be empty")
        
        elif choice == '8':
            checker.get_data_classes()
        
        elif choice == '9':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid option. Please select 1-9")
        
        # Add a small delay to respect rate limits
        time.sleep(1)

if __name__ == "__main__":
    main()
