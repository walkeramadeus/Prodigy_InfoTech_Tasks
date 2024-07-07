import re

def assess_password_strength(password):
    # Criteria
    length_criteria = len(password) >= 8
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    digit_criteria = re.search(r'[0-9]', password) is not None
    special_char_criteria = re.search(r'[\W_]', password) is not None

    # Strength levels
    criteria_met = sum([length_criteria, lowercase_criteria, uppercase_criteria, digit_criteria, special_char_criteria])

    # Feedback
    if criteria_met == 5:
        strength = "Very Strong"
    elif criteria_met == 4:
        strength = "Strong"
    elif criteria_met == 3:
        strength = "Moderate"
    else:
        strength = "Weak"

    feedback = []
    if not length_criteria:
        feedback.append("Your password should be at least 8 characters long.")
    if not lowercase_criteria:
        feedback.append("Your password should include at least one lowercase letter.")
    if not uppercase_criteria:
        feedback.append("Your password should include at least one uppercase letter.")
    if not digit_criteria:
        feedback.append("Your password should include at least one digit.")
    if not special_char_criteria:
        feedback.append("Your password should include at least one special character.")

    return strength, feedback

# Example usage
password = input("Enter a password to assess its strength: ")
strength, feedback = assess_password_strength(password)

print(f"Password Strength: {strength}")
if feedback:
    print("Feedback:")
    for comment in feedback:
        print(f"- {comment}")
