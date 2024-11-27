import bcrypt

def generate_bcrypt_password(password):
    """
    Generate a bcrypt hash for the given password.

    :param password: The password to hash as bytes or string.
    :return: A bytes object containing the salt and hashed password.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password, salt)
    return hashed

def check_password(plain_password, hashed):
    """
    Check if the provided plain text password matches the hashed password.

    :param plain_password: The plain text password to check.
    :param hashed: The bcrypt hashed password from the database.
    :return: Boolean indicating if the passwords match.
    """
    if isinstance(plain_password, str):
        plain_password = plain_password.encode('utf-8')
    
    return bcrypt.checkpw(plain_password, hashed)

if __name__ == "__main__":
    # Ask user to input their password
    password = input("Enter your password: ")

    # Generate bcrypt hash
    hashed = generate_bcrypt_password(password)
    print("Hashed Password:", hashed)

    # Verify the password (this might not be necessary in a real application where you'd compare with a stored hash)
    is_correct = check_password(password, hashed)
    print("Password verification:", "Correct" if is_correct else "Incorrect")
