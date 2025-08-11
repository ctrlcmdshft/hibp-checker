
import os
from pathlib import Path
import json
import hashlib
import requests
import time
import re
import getpass
import logging
import argparse
from dotenv import load_dotenv
from datetime import datetime
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class HaveIBeenPwnedChecker:
	def __init__(self):
		# Load the environment variables from .env
		load_dotenv()
		# Get the API key from the environment variables
		self.API_KEY = os.getenv('HIBP_API_KEY')
		self.api_url = 'https://haveibeenpwned.com/api/v3'
		# Check if API key is loaded
		if not self.API_KEY:
			logging.error("HIBP_API_KEY not found in environment variables. Please create a .env file with: HIBP_API_KEY=your_api_key_here")
			raise RuntimeError("❌ Error: HIBP_API_KEY not found in environment variables. Please create a .env file with: HIBP_API_KEY=your_api_key_here")
		# Set up headers with required User-Agent
		self.headers = {
			'hibp-api-key': self.API_KEY,
			'User-Agent': 'Python-HIBP-Checker/1.0'
		}
	def show_detailed_breach_info(self, breach: dict) -> None:
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
		logo_path = breach.get('LogoPath', '')
		if logo_path:
			print(f"Logo: https://haveibeenpwned.com{logo_path}")
		data_classes = breach.get('DataClasses', [])
		if data_classes:
			print(f"\n📊 Types of Data Compromised:")
			for data_type in data_classes:
				print(f"  • {data_type}")
		print(f"\n🏷️ Status Information:")
		print(f"  • Verified by HIBP: {'Yes' if breach.get('IsVerified', False) else 'No'}")
		print(f"  • Fabricated/Fake: {'Yes' if breach.get('IsFabricated', False) else 'No'}")
		print(f"  • Contains Sensitive Data: {'Yes' if breach.get('IsSensitive', False) else 'No'}")
		print(f"  • Retired from HIBP: {'Yes' if breach.get('IsRetired', False) else 'No'}")
		print(f"  • Spam List: {'Yes' if breach.get('IsSpamList', False) else 'No'}")
		description = breach.get('Description', '')
		if description:
			clean_description = re.sub(r'<[^>]+>', '', description)
			print(f"\n📝 Full Description:")
			print(f"{clean_description}")

	def check_pwned_passwords(self, password: str) -> int | None:
		logging.info("Checking if password has been pwned...")
		sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
		prefix = sha1_password[:5]
		suffix = sha1_password[5:]
		try:
			response = requests.get(
				f'https://api.pwnedpasswords.com/range/{prefix}',
				timeout=10
			)
			if response.status_code != 200:
				logging.error(f"Error checking password (Status: {response.status_code})")
				return None
			hashes = response.text.splitlines()
			for hash_line in hashes:
				hash_suffix, count = hash_line.split(':')
				if hash_suffix == suffix:
					count = int(count)
					print(f"⚠️ Password has been pwned {count:,} times!")
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
			logging.info("Password not found in pwned passwords database")
			logging.info("This password appears to be secure")
			return 0
		except requests.exceptions.RequestException as e:
			logging.error(f"Network error checking password: {e}")
			return None

	def get_all_breaches(self) -> list | None:
		logging.info("Fetching all breaches from HIBP database...")
		try:
			response = requests.get(
				f'{self.api_url}/breaches',
				headers=self.headers,
				timeout=15
			)
			if response.status_code != 200:
				logging.error(f"Error fetching breaches (Status: {response.status_code})")
				return None
			breaches = response.json()
			logging.info(f"Found {len(breaches)} total breaches in database")
			print("\n🔴 Recent Major Breaches:")
			print("-" * 60)
			sorted_breaches = sorted(breaches, key=lambda x: x.get('BreachDate', ''), reverse=True)
			for i, breach in enumerate(sorted_breaches[:10], 1):
				pwn_count = breach.get('PwnCount', 0)
				date = breach.get('BreachDate', 'Unknown')
				print(f"{i:2d}. {breach.get('Name', 'Unknown'):20} - {date} ({pwn_count:,} accounts)")
			return breaches
		except requests.exceptions.RequestException as e:
			logging.error(f"Network error: {e}")
			return None

	def get_breach_details(self, breach_name: str) -> dict | None:
		logging.info(f"Getting details for breach: {breach_name}")
		try:
			response = requests.get(
				f'{self.api_url}/breach/{breach_name}',
				headers=self.headers,
				timeout=10
			)
			if response.status_code == 404:
				logging.error(f"Breach '{breach_name}' not found")
				return None
			elif response.status_code != 200:
				logging.error(f"Error fetching breach details (Status: {response.status_code})")
				return None
			breach = response.json()
			self.show_detailed_breach_info(breach)
			return breach
		except requests.exceptions.RequestException as e:
			logging.error(f"Network error: {e}")
			return None

	def get_data_classes(self) -> list | None:
		logging.info("Fetching all data classes...")
		try:
			response = requests.get(
				f'{self.api_url}/dataclasses',
				headers=self.headers,
				timeout=10
			)
			if response.status_code != 200:
				logging.error(f"Error fetching data classes (Status: {response.status_code})")
				return None
			data_classes = response.json()
			print(f"📊 Found {len(data_classes)} data class types:")
			print("=" * 50)
			for i, data_class in enumerate(data_classes, 1):
				print(f"{i:2d}. {data_class}")
			return data_classes
		except requests.exceptions.RequestException as e:
			logging.error(f"Network error: {e}")
			return None

	def check_pastes(self, email: str) -> list | None:
		logging.info(f"Checking pastes for: {email}")
		try:
			response = requests.get(
				f'{self.api_url}/pasteaccount/{email}',
				headers=self.headers,
				timeout=10
			)
			if response.status_code == 404:
				logging.info("Email not found in any pastes")
				return []
			elif response.status_code != 200:
				logging.error(f"Error checking pastes (Status: {response.status_code})")
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
			logging.error(f"Network error: {e}")
			return None

	def search_breaches_by_domain(self, domain: str) -> list | None:
		logging.info(f"Searching breaches for domain: {domain}")
		try:
			response = requests.get(
				f'{self.api_url}/breaches?domain={domain}',
				headers=self.headers,
				timeout=10
			)
			if response.status_code != 200:
				logging.error(f"Error searching domain (Status: {response.status_code})")
				return None
			breaches = response.json()
			if not breaches:
				logging.info(f"No breaches found for domain: {domain}")
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
			logging.error(f"Network error: {e}")
			return None

	def save_results_to_file(self, email: str, breaches: list, filename: str = None) -> None:
		if filename is None:
			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			filename = f"hibp_results_{timestamp}.json"
		file_path = Path(filename)
		data = {
			"email": email,
			"check_date": datetime.now().isoformat(),
			"breach_count": len(breaches) if breaches else 0,
			"breaches": breaches
		}
		try:
			with file_path.open('w') as f:
				json.dump(data, f, indent=2)
			logging.info(f"Results saved to {file_path}")
		except Exception as e:
			logging.error(f"Error saving results: {e}")

	def save_pastes_to_file(self, email: str, pastes: list, filename: str = None) -> None:
		if filename is None:
			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			filename = f"hibp_pastes_{timestamp}.json"
		file_path = Path(filename)
		data = {
			"email": email,
			"check_date": datetime.now().isoformat(),
			"paste_count": len(pastes) if pastes else 0,
			"pastes": pastes
		}
		try:
			with file_path.open('w') as f:
				json.dump(data, f, indent=2)
			logging.info(f"Paste results saved to {file_path}")
		except Exception as e:
			logging.error(f"Error saving paste results: {e}")

	def save_all_breaches_to_file(self, breaches: list, filename: str = None) -> None:
		if filename is None:
			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			filename = f"hibp_all_breaches_{timestamp}.json"
		file_path = Path(filename)
		data = {
			"fetch_date": datetime.now().isoformat(),
			"total_breaches": len(breaches) if breaches else 0,
			"breaches": breaches
		}
		try:
			with file_path.open('w') as f:
				json.dump(data, f, indent=2)
			logging.info(f"All breaches saved to {file_path}")
		except Exception as e:
			logging.error(f"Error saving all breaches: {e}")

	def save_domain_breaches_to_file(self, domain: str, breaches: list, filename: str = None) -> None:
		if filename is None:
			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			safe_domain = domain.replace('.', '_').replace('/', '_')
			filename = f"hibp_domain_{safe_domain}_{timestamp}.json"
		file_path = Path(filename)
		data = {
			"domain": domain,
			"check_date": datetime.now().isoformat(),
			"breach_count": len(breaches) if breaches else 0,
			"breaches": breaches
		}
		try:
			with file_path.open('w') as f:
				json.dump(data, f, indent=2)
			logging.info(f"Domain breach results saved to {file_path}")
		except Exception as e:
			logging.error(f"Error saving domain breach results: {e}")

	def save_data_classes_to_file(self, data_classes: list, filename: str = None) -> None:
		if filename is None:
			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			filename = f"hibp_data_classes_{timestamp}.json"
		file_path = Path(filename)
		data = {
			"fetch_date": datetime.now().isoformat(),
			"total_data_classes": len(data_classes) if data_classes else 0,
			"data_classes": data_classes
		}
		try:
			with file_path.open('w') as f:
				json.dump(data, f, indent=2)
			logging.info(f"Data classes saved to {file_path}")
		except Exception as e:
			logging.error(f"Error saving data classes: {e}")

	def save_breach_details_to_file(self, breach: dict, filename: str = None) -> None:
		if filename is None:
			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			breach_name = breach.get('Name', 'unknown').replace(' ', '_').lower()
			filename = f"hibp_breach_{breach_name}_{timestamp}.json"
		file_path = Path(filename)
		data = {
			"fetch_date": datetime.now().isoformat(),
			"breach_details": breach
		}
		try:
			with file_path.open('w') as f:
				json.dump(data, f, indent=2)
			logging.info(f"Breach details saved to {file_path}")
		except Exception as e:
			logging.error(f"Error saving breach details: {e}")

	def check_breached_account(self, email: str) -> list | None:
		"""Check if an email account has been breached"""
		logging.info(f"Checking breaches for: {email}")
		try:
			response = requests.get(
				f'{self.api_url}/breachedaccount/{email}?truncateResponse=false',
				headers=self.headers,
				timeout=10
			)
			if response.status_code == 404:
				logging.info("Good news! Email not found in any data breaches")
				return []
			elif response.status_code == 401:
				logging.error("Invalid or missing API key")
				return None
			elif response.status_code == 429:
				logging.warning("Rate limit exceeded. Please wait before trying again")
				return None
			elif response.status_code == 400:
				logging.error("Bad request - please check the email format")
				return None
			elif response.status_code != 200:
				logging.error(f"Error checking email (Status: {response.status_code})")
				return None
			else:
				breaches_data = response.json()
				logging.warning(f"Email found in {len(breaches_data)} breach(es):")
				print("=" * 80)
				for i, breach in enumerate(breaches_data, 1):
					print(f"\n🔴 BREACH #{i}")
					print("-" * 50)
					print(f"Name: {breach.get('Name', 'Unknown')}")
					print(f"Title: {breach.get('Title', 'Unknown')}")
					print(f"Domain: {breach.get('Domain', 'Unknown')}")
					print(f"Breach Date: {breach.get('BreachDate', 'Unknown')}")
					print(f"Added to HIBP: {breach.get('AddedDate', 'Unknown')}")
					print(f"Last Modified: {breach.get('ModifiedDate', 'Unknown')}")
					pwn_count = breach.get('PwnCount', 0)
					if pwn_count > 0:
						print(f"Accounts Affected: {pwn_count:,}")
					else:
						print("Accounts Affected: Unknown")
					data_classes = breach.get('DataClasses', [])
					if data_classes:
						print(f"Data Compromised: {', '.join(data_classes)}")
					else:
						print("Data Compromised: Unknown")
					print(f"Verified: {'Yes' if breach.get('IsVerified', False) else 'No'}")
					print(f"Fabricated: {'Yes' if breach.get('IsFabricated', False) else 'No'}")
					print(f"Sensitive: {'Yes' if breach.get('IsSensitive', False) else 'No'}")
					print(f"Retired: {'Yes' if breach.get('IsRetired', False) else 'No'}")
					print(f"Spam List: {'Yes' if breach.get('IsSpamList', False) else 'No'}")
					description = breach.get('Description', '')
					if description:
						clean_description = re.sub(r'<[^>]+>', '', description)
						print(f"Description: {clean_description[:200]}{'...' if len(clean_description) > 200 else ''}")
					if i < len(breaches_data):
						print("\n" + "="*80)
				if len(breaches_data) > 1:
					print(f"\n📋 Would you like detailed info on a specific breach?")
					print(f"Enter breach number (1-{len(breaches_data)}), 'all' for all breaches, or 'n' to skip.")
					breach_choice = input(f"Your choice: ").strip().lower()
					if breach_choice == 'all':
						for breach in breaches_data:
							self.show_detailed_breach_info(breach)
					elif breach_choice.isdigit() and 1 <= int(breach_choice) <= len(breaches_data):
						self.show_detailed_breach_info(breaches_data[int(breach_choice) - 1])
				return breaches_data
		except requests.exceptions.Timeout:
			logging.error("Request timed out. Please try again later")
			return None
		except requests.exceptions.ConnectionError:
			logging.error("Connection error. Please check your internet connection")
			return None
		except requests.exceptions.RequestException as e:
			logging.error(f"Network error: {e}")
			return None
		except json.JSONDecodeError:
			logging.error("Error parsing response from API")
			return None

	# ...all other methods from hibp-checker.py...

	def validate_email(self, email: str) -> bool:
		pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
		return re.match(pattern, email) is not None

def main() -> None:
	parser = argparse.ArgumentParser(description="Have I Been Pwned Checker")
	parser.add_argument('--email', help='Email address to check')
	parser.add_argument('--password', help='Password to check (not recommended to use on CLI)')
	parser.add_argument('--pastes', action='store_true', help='Check email in pastes')
	parser.add_argument('--all-breaches', action='store_true', help='Get all breaches in database')
	parser.add_argument('--breach-name', help='Get details for a specific breach')
	parser.add_argument('--domain', help='Search breaches by domain')
	parser.add_argument('--data-classes', action='store_true', help='View all data class types')
	parser.add_argument('--save', action='store_true', help='Save results to file')
	parser.add_argument('--quiet', action='store_true', help='Suppress most output (only errors)')
	parser.add_argument('--json', action='store_true', help='Output results as JSON')
	parser.add_argument('--version', action='version', version='HIBP Checker 1.0.0')
	args = parser.parse_args()

	try:
		if args.quiet:
			logging.getLogger().setLevel(logging.ERROR)
		checker = HaveIBeenPwnedChecker()
		# Non-interactive CLI mode
		if args.email and not args.password and not args.pastes:
			if not checker.validate_email(args.email):
				logging.error("Invalid email format")
				return
			breaches = checker.check_breached_account(args.email)
			if breaches is None:
				print("❌ Error checking for breaches. See logs for details.")
			elif len(breaches) == 0:
				print("✅ No breaches found for this email.")
			else:
				print(f"⚠️ Found {len(breaches)} breach(es) for this email.")
			if args.json:
				print(json.dumps(breaches, indent=2))
			if args.save:
				checker.save_results_to_file(args.email, breaches or [])
		elif args.password and not args.email:
			count = checker.check_pwned_passwords(args.password)
			if args.json:
				print(json.dumps({"pwned_count": count}))
		elif args.email and args.password:
			if not checker.validate_email(args.email):
				logging.error("Invalid email format")
				return
			breaches = checker.check_breached_account(args.email)
			count = checker.check_pwned_passwords(args.password)
			if args.json:
				print(json.dumps({"breaches": breaches, "pwned_count": count}, indent=2))
			if args.save and breaches is not None and len(breaches) > 0:
				checker.save_results_to_file(args.email, breaches)
		elif args.pastes and args.email:
			if not checker.validate_email(args.email):
				logging.error("Invalid email format")
				return
			pastes = checker.check_pastes(args.email)
			if args.json:
				print(json.dumps(pastes, indent=2))
			if args.save and pastes is not None and len(pastes) > 0:
				checker.save_pastes_to_file(args.email, pastes)
		elif args.all_breaches:
			breaches = checker.get_all_breaches()
			if args.json:
				print(json.dumps(breaches, indent=2))
			if args.save and breaches is not None:
				checker.save_all_breaches_to_file(breaches)
		elif args.breach_name:
			breach = checker.get_breach_details(args.breach_name)
			if args.json:
				print(json.dumps(breach, indent=2))
			if args.save and breach is not None:
				checker.save_breach_details_to_file(breach)
		elif args.domain:
			breaches = checker.search_breaches_by_domain(args.domain)
			if args.json:
				print(json.dumps(breaches, indent=2))
			if args.save and breaches is not None and len(breaches) > 0:
				checker.save_domain_breaches_to_file(args.domain, breaches)
		elif args.data_classes:
			data_classes = checker.get_data_classes()
			if args.json:
				print(json.dumps(data_classes, indent=2))
			if args.save and data_classes is not None:
				checker.save_data_classes_to_file(data_classes)
		else:
			# Interactive mode fallback
			print("🔐 Have I Been Pwned Checker")
			print("=" * 30)
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
					pastes = checker.check_pastes(email)
					if pastes is not None and len(pastes) > 0:
						save_choice = input("\n💾 Save paste results to file? (y/n): ").strip().lower()
						if save_choice == 'y':
							checker.save_pastes_to_file(email, pastes)

				elif choice == '5':
					breaches = checker.get_all_breaches()
					if breaches is not None:
						save_choice = input("\n💾 Save all breaches to file? (y/n): ").strip().lower()
						if save_choice == 'y':
							checker.save_all_breaches_to_file(breaches)

				elif choice == '6':
					breach_name = input("Enter breach name (e.g., Adobe, LinkedIn): ").strip()
					if breach_name:
						breach = checker.get_breach_details(breach_name)
						if breach is not None:
							save_choice = input("\n💾 Save breach details to file? (y/n): ").strip().lower()
							if save_choice == 'y':
								checker.save_breach_details_to_file(breach)
					else:
						print("❌ Breach name cannot be empty")

				elif choice == '7':
					domain = input("Enter domain (e.g., adobe.com): ").strip()
					if domain:
						breaches = checker.search_breaches_by_domain(domain)
						if breaches is not None and len(breaches) > 0:
							save_choice = input("\n💾 Save domain breach results to file? (y/n): ").strip().lower()
							if save_choice == 'y':
								checker.save_domain_breaches_to_file(domain, breaches)
					else:
						print("❌ Domain cannot be empty")

				elif choice == '8':
					data_classes = checker.get_data_classes()
					if data_classes is not None:
						save_choice = input("\n💾 Save data classes to file? (y/n): ").strip().lower()
						if save_choice == 'y':
							checker.save_data_classes_to_file(data_classes)

				elif choice == '9':
					print("👋 Goodbye!")
					break

				else:
					print("❌ Invalid option. Please select 1-9")

				# Add a small delay to respect rate limits
				time.sleep(1)
	except KeyboardInterrupt:
		print("\n👋 Exiting gracefully. Goodbye!")
	except RuntimeError as e:
		print(e)

if __name__ == "__main__":
	main()
