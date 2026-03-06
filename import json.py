import json
import hashlib
import secrets
import time
from datetime import datetime

class User:
    def __init__(self, username, salt, password_hash,
                created_at=None, last_login=None,
                failed_attempts=0, lock_until=0,
                last_fail_ts=0):
            
            self.username = username
            self.salt = salt
            self.password_hash = password_hash
            self.created_at = created_at or datetime.now().isoformat()
            self.last_login = last_login
            self.failed_attempts = failed_attempts
            self.locked_until = lock_until
            self.last_fail_ts = last_fail_ts

    def to_dict(self):
          return{
                "username": self.username,
                "salt": self.salt,
                "password_hash": self.password_hash,
                "created_at": self.created_at,
                "last_login": self.last_login,
                "failed_attempts": self.failed_attempts,
                "locked_until": self.locked_until,
                "last_fail_ts": self.last_fail_ts
          }
    
    @staticmethod
    def from_dict(data):
          return User(
                username=data["username"],
                salt=data["salt"],
                password_hash=data["password_hash"],
                created_at=data.get("created_at"),
                last_login=data.get("last_login"),
                failed_attempts=data.get("failed_attempts", 0),
                locked_until=data.get("lock_until", 0),
                last_fail_ts=data.get("last_fail_ts", 0)
          )
    
class Storage:
    def __init__(self, filename="users.json"):
           self.filename = filename
      
    def load_users(self):
        try:
            with open(self.filename, "r") as f:
                data = json.load(f)
                return {u["username"]: User.from_dict(u) for u in data}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
            
    def save_users(self, users):
         with open(self.filename, "w") as f:
              json.dump([u.to_dict() for u in users.values()], f, indent=4)


class AuthService:
    def __init__(self, storage):
        self.storage = storage
        self.users = storage.load_users()
         
    def hash_password(self, password, salt):
        return hashlib.sha256((salt + password).encode()).hexdigest()
    
    def register(self, username, password):
        if username in self.users:
              print("Username already exists.")
              return False
         
        salt = secrets.token_hex(16)
        password_hash = self.hash_password(password, salt)
         
        user = User(username, salt, password_hash)
        self.users[username] = user
        self.storage.save_users(self.users)
        
        print("Registration successful.")
        return True
    
    def calculate_risk(self, username, password, user):
        risk = 0
        reasons = []

        if user:
            risk += 20 * user.failed_attempts
            if user.failed_attempts > 0:
                reasons.append(f"{user.failed_attempts} previous fails")

        if len(password) < 6:
            risk +=25
            reasons.append("short password")

        if not user:
            risk += 40
            reasons.append("unknown username")

        if user and user.last_fail_ts:
            if time.time() - user.last_fail_ts < 10:
                risk += 15
                reasons.append("attempts too fast")

        return risk, reasons
    
    def login(self, username, password):
        user = self.users.get(username)
        
        if user and time.time() < user.locked_until:
            remaining = int(user.locked_until - time.time())
            print(f"Account locked. Try again in {remaining} seconds.")
            return None
        
        risk,reasons = self.calculate_risk(username, password, user)

        if not user:
            lock_time = 0
            if 40 <= risk < 80:
                lock_time = 30
            elif risk >= 80:
                lock_time = 120

            print(f"Login failed.")
            print(f"Risk: {risk} ({', '.join(reasons)}) Lockout: {lock_time}s")
            return None
        
        password_hash = self.hash_password(password, user.salt)

        if password_hash == user.password_hash:

            user.failed_attempts = 0
            user.locked_until = 0
            user.last_login = datetime.now().isoformat()

            self.storage.save_users(self.users)

            print("Login successful.")
            return user
        else:
            user.failed_attempts += 1
            user.last_fail_ts = time.time()

            risk, reasons = self.calculate_risk(username, password, user)

            lock_time = 0
            if 40 <= risk < 80:
                lock_time = 30
            elif risk >= 80:
                lock_time = 120

            if lock_time > 0:
                user.locked_until = time.time() + lock_time

            self.storage.save_users(self.users)

            print("Login failed.")
            print(f"Risk: {risk} ({', '.join(reasons)}) Lockout: {lock_time}s")

            return None

        
def main():
    storage = Storage()
    auth = AuthService(storage)
    
    while True:
        print("\n=== MINI LOGIN SYSTEM ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        
        choice = input("Choose option: ")

        if choice == "1":
            username = input("Username: ")
            password = input("Password: ")
            auth.register(username, password)

        elif choice == "2":
            username = input("Username: ")
            password = input("Password: ")
            user = auth.login(username, password)

            if user:
                while True:
                    print("\n--- User Menu ---")
                    print("1. Profile info")
                    print("2. Logout")

                    sub_choice = input("Choose option: ")

                    if sub_choice == "1":
                        print("\n--- PROFILE INFO ---")
                        print("Username:", user.username)
                        print("Created at:", user.created_at)
                        print("Last login:", user.last_login)

                    elif sub_choice == "2":
                        print("Logged out.")
                        break
                    else:
                        print("Invalid option.")

        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()