import random
import string
import itertools
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
import subprocess
import requests
import tweepy
import gzip

# Generate password variations based on user information and additional info
def generate_password_variations(username, email, additional_info=None):
    variations = []
    base_parts = [username, email.split('@')[0]]
    years = ["2021", "2022", "2023", "2024"]
    special_characters = ["!", "@", "#", "$", "%", "&", "*"]

    for part in base_parts:
        variations.append(part)  # The username or email as is
        variations.append(part + "123")  # Appending 123
        variations.append(part + random.choice(years))  # Appending a year
        variations.append(part.capitalize())  # Capitalizing the first letter
        variations.append(part[::-1])  # Reversed
        variations.extend([part + char for char in special_characters])  # Append special characters

    additional_variations = list(itertools.product(base_parts, years, special_characters))
    for combo in additional_variations:
        variations.append("".join(combo))

    favorite_numbers = ["7", "13", "42"]
    for part in base_parts:
        variations.extend([part + num for num in favorite_numbers])
        variations.extend([char + part for char in special_characters])

    if additional_info:
        for info in additional_info:
            variations.append(info)
            variations.extend([info + char for char in special_characters])
            variations.extend([info.capitalize() + year for year in years])

    return variations

# AI-based password strength evaluation function
def password_strength_features(password):
    length = len(password)
    digits = sum(c.isdigit() for c in password)
    symbols = sum(c in string.punctuation for c in password)
    uppercase = sum(c.isupper() for c in password)
    lowercase = sum(c.islower() for c in password)
    return [length, digits, symbols, uppercase, lowercase]

def train_password_strength_model():
    X = [
        [8, 2, 1, 3, 2], [10, 3, 2, 4, 3], [12, 4, 3, 5, 4],
        [6, 1, 0, 2, 3], [14, 4, 5, 6, 4], [16, 5, 4, 7, 5]
    ]
    y = [0, 1, 1, 0, 1, 1] 
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = LogisticRegression()
    model.fit(X_scaled, y)
    return model, scaler

# Function to collect data from Twitter API
def collect_twitter_data(username):
    API_KEY = 'YOUR_TWITTER_API_KEY'
    API_SECRET_KEY = 'YOUR_TWITTER_API_SECRET_KEY'
    ACCESS_TOKEN = 'YOUR_TWITTER_ACCESS_TOKEN'
    ACCESS_TOKEN_SECRET = 'YOUR_TWITTER_ACCESS_TOKEN_SECRET'

    auth = tweepy.OAuthHandler(API_KEY, API_SECRET_KEY)
    auth.set_access_token(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)
    api = tweepy.API(auth)

    additional_info = []
    
    try:
        tweets = api.user_timeline(screen_name=username, count=5, tweet_mode='extended')
        for tweet in tweets:
            additional_info.append(tweet.full_text)

        followers = api.followers(screen_name=username, count=5)
        for follower in followers:
            additional_info.append(follower.screen_name)

    except Exception as e:
        print(f"Error fetching data from Twitter: {e}")

    return additional_info

# Function to collect data from Instagram API
def collect_instagram_data(user_id):
    access_token = 'YOUR_INSTAGRAM_ACCESS_TOKEN'
    
    additional_info = []
    
    try:
        url = f"https://graph.instagram.com/{user_id}/media?fields=id,caption&access_token={access_token}"
        response = requests.get(url)
        data = response.json()

        if 'data' in data:
            for item in data['data']:
                if 'caption' in item:
                    additional_info.append(item['caption'])

    except Exception as e:
        print(f"Error fetching data from Instagram: {e}")

    return additional_info

# Combined function to collect social media data using real APIs
def collect_social_media_data(username):
    additional_info = []
    
    twitter_data = collect_twitter_data(username)
    additional_info.extend(twitter_data)

    user_id = "YOUR_INSTAGRAM_USER_ID"
    
    instagram_data = collect_instagram_data(user_id)
    additional_info.extend(instagram_data)

    return additional_info

# Function to remove duplicates from the password list
def remove_duplicates(passwords):
    return list(set(passwords))

# Function to write passwords in batches to file
def write_passwords_in_batches(passwords, file_name, batch_size=100):
    with open(file_name, "w") as file:
        for i in range(0, len(passwords), batch_size):
            batch = passwords[i:i + batch_size]
            file.write("\n".join(batch) + "\n")

# Function to write compressed passwords to a .gz file
def write_compressed_passwords(passwords, file_name):
    with gzip.open(file_name, 'wt', encoding='utf-8') as file:
        file.write("\n".join(passwords) + "\n")

# Function to generate passwords for each user and evaluate strength
def generate_passwords_for_company(usernames_emails, model, scaler):
    all_passwords = []
    strong_passwords = []

    for user_info in usernames_emails:
        username, email = user_info

        # Collect additional info from social media
        additional_info = collect_social_media_data(username)

        # Generate password variations
        password_variations = generate_password_variations(username, email, additional_info)

        all_passwords.extend(password_variations)

        # Evaluate the strength of each password
        for password in password_variations:
            features = password_strength_features(password)
            features_scaled = scaler.transform([features])
            strength = model.predict(features_scaled)

            if strength == 1:
                strong_passwords.append(password)

    # Remove duplicates from the generated passwords
    unique_passwords = remove_duplicates(all_passwords)
    strong_unique_passwords = remove_duplicates(strong_passwords)

    return unique_passwords, strong_unique_passwords

if __name__ == "__main__":
    model, scaler = train_password_strength_model()

    usernames_emails = []

    num_users = int(input("Enter the number of users you want to provide: "))

    for i in range(num_users):
        username = input(f"Enter username for user {i+1}: ")
        email = input(f"Enter email for user {i+1}: ")
        usernames_emails.append((username, email))

    # Generate passwords and evaluate them using social media information and tools
    all_generated_passwords, strong_generated_passwords = generate_passwords_for_company(
        usernames_emails, model, scaler
    )

    # Write the unique passwords in batches
    write_passwords_in_batches(all_generated_passwords, "generated_passwords.txt", batch_size=100)
    write_passwords_in_batches(strong_generated_passwords, "strong_passwords.txt", batch_size=100)

    # Write the compressed version of the files
    write_compressed_passwords(all_generated_passwords, "generated_passwords.txt.gz")
    write_compressed_passwords(strong_generated_passwords, "strong_passwords.txt.gz")

    print(f"Generated {len(all_generated_passwords)} potential passwords and saved them to 'generated_passwords.txt'.")
    print(f"Generated {len(strong_generated_passwords)} strong passwords and saved them to 'strong_passwords.txt'.")
