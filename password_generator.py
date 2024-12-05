import random
import string

class PasswordGenerator:
    def __init__(self, length=12, use_special=True, use_upper=True):
        self.length = length
        self.use_special = use_special
        self.use_upper = use_upper

    def generate(self):
        characters = string.ascii_lowercase
        if self.use_upper:
            characters += string.ascii_uppercase
        if self.use_special:
            characters += string.punctuation
        characters += string.digits

        # Generate a random password with the specified length
        password = ''.join(random.choice(characters) for _ in range(self.length))
        return password
