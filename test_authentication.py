'''
Nicholas Lovera
CS2660OL1
Lab 2.0: Testing Authentication
'''
import unittest
import json
import sys

# Set maximum number of attempts to login
MAX_ATTEMPTS = 3
# Special characters to test password strength
SPECIAL_CHAR = "!@#$%^&*"
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 50

def database(un, pw) -> bool:
    """
    Database simulator function. Check user supplied credentials against
    credentials stored in json file. Return true if un/pw matches, false
    otherwise.

    :param un: str
    :param pw: str
    :return: bool
    """
    try:
        with open("database.json", "r") as f:
            credentials = json.load(f)
            if credentials[un] == pw:
                return True
            else:
                return False
    except KeyError:
        return False
    except IOError:
        print("Error reading file. Aborting...")
        sys.exit()
    except json.decoder.JSONDecodeError:
        print("Error reading file. Aborting...")
        sys.exit()

def password_strength(test_password) -> bool:
    """
    Check basic password strength. Return true if password
    meets minimum complexity criteria, false otherwise.

    :param test_password: str
    :return: bool
    """
    if test_password.isalnum() or test_password.isalpha():
        return False
    if len(test_password) < PASSWORD_MIN_LENGTH:
        return False
    if len(test_password) > PASSWORD_MAX_LENGTH:
        return False
    special_char_check = False
    has_upper = False
    has_lower = False
    has_digit = False
    for ch in test_password:
        if ch in SPECIAL_CHAR:
            special_char_check = True
        if ch.isupper():
            has_upper = True
        if ch.islower():
            has_lower = True
        if ch.isdigit():
            has_digit = True
    if not special_char_check or \
            not has_upper or \
            not has_lower or \
            not has_digit:
        return False
    else:
        return True

class TestAuthentication(unittest.TestCase):
    def test_registereduser(self):
        self.assertTrue(database('bwayne','mYpA$$166'))
        print(database('bwayne','mYpA$$166'))


    def test_unregistereduser(self):
        self.assertFalse(database('Ben', 'Ben@'))
        print(database('Ben', 'Ben@'))

    def test_wrongpassword(self):
        self.assertFalse(database('bwayne', 'LilTiny2025'))
        print(database('bwayne', 'LilTiny2025'))

    def test_passwordminlength(self):
        passwords = ['Ab1@', 'Ab12@','Abc12@', 'Abc123@@@@@', 'Abc123@@@@@' ]
        for pw in passwords:
            if len(pw) < PASSWORD_MIN_LENGTH:
                self.assertFalse(password_strength(pw))
                print(f'{pw} is under the minimum length')
            if len(pw) > PASSWORD_MIN_LENGTH:
                self.assertTrue(password_strength(pw))


    def test_passwordmaxlength(self):
        passwords = ['Password1@@@@@@@','ThisIsOverFiftyCharactersLong@ThisIsOverFiftyCharactersLong@ThisIsOverFiftyCharactersLong@'
                     'Password1@@@@@@@@', 'ThisIsOverFiftyCharactersLong@ThisIsOverFiftyCharactersLong@']
        for pw in passwords:
            if len(pw) > PASSWORD_MAX_LENGTH:
                self.assertFalse(password_strength(pw))
                print(f'{pw} goes over the max length')
            else:
                self.assertTrue(password_strength(pw))

    def test_onlycharacters(self):
        passwords = ['LilTiny2025@', 'CybersecurityIsSoCool', 'UvM2025@', 'HelloWorld']
        for pw in passwords:
            if pw.isalpha():
                self.assertFalse(password_strength(pw))
                print(f'{pw} is all letters, not valid')
            else:
                self.assertTrue(password_strength(pw))

    def test_onlynumbers(self):
        passwords = ['LilTiny2025@', '123456789', 'Ben@TheHouse1', '3740234794']
        for pw in passwords:
            if pw.isalnum():
                self.assertFalse(password_strength(pw))
                print(f'{pw} is all numbers, not valid')
            else:
                self.assertTrue(password_strength(pw))
    def test_oneuppercaseletter(self):
        passwords = ['LilTiny2025@', "nouppercaselol@2025", 'Oneuppercase@2025', 'anothernone@2025']
        for pw in passwords:
            hasupper = False
            for ch in pw:
                if ch.isupper():
                    hasupper = True

        if hasupper:
            self.assertTrue(password_strength(pw))
            print(f'{pw} has at least one uppercase letter')
        else:
            self.assertFalse(password_strength(pw))

    def test_onelowercaseletter(self):
        passwords = ['LilTiny2025@', "ALLUPPERCASE@2025", 'ValidPassword@2025', 'ANTOHERONE@2025']
        for pw in passwords:
            haslower = False
            for ch in pw:
                if ch.islower():
                    haslower = True

        if haslower:
            self.assertTrue(password_strength(pw))
            print(f'{pw} has at least one lowercase letter')
        else:
            self.assertFalse(password_strength(pw))

    def test_validpassword(self):
        passwords = ['LilTiny2025@', 'CybersecurityIsSoCool', 'UvM2025', '123445567', 'Abc123@',
                     'ThisIsOverFiftyCharactersLong@ThisIsOverFiftyCharactersLong@']

        for pw in passwords:
            if password_strength(pw):
                self.assertTrue(password_strength(pw))
            else:
                for ch in pw:
                    hasnospecialchar = True
                    if ch in SPECIAL_CHAR:
                        hasnospecialchar = False
                if hasnospecialchar:
                    self.assertFalse(password_strength(pw))
                    print(f'{pw} has no special character')
                else:
                    self.assertFalse(password_strength(pw))






if __name__ == '__main__':
    unittest.main()