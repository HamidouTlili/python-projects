Hamidou Password Generator
Overview
The Hamidou Password Generator is an advanced Python tool for generating potential passwords based on user information, evaluating password strength using an AI-based model, and collecting additional information from social media to generate more secure passwords.

Features
Generates password variations based on username, email, and social media information.
AI-based password strength evaluation.
Collects additional information from Twitter and Instagram to enhance password generation.
Removes duplicates and writes generated passwords in batches to a file.
Compresses passwords and saves them in .gz format.
Requirements
Python 3.x
scikit-learn for AI-based password strength evaluation
tweepy for collecting Twitter data
requests for collecting Instagram data
Install the required dependencies using the following command:

bash
Copier le code
pip install scikit-learn tweepy requests
How to Use
Running the Script:

Run the script and enter the number of users, their usernames, and emails:


python hamidopass.py
Example:


Enter the number of users you want to provide: 5
Enter username for user 1: samara145
Enter email for user 1: samaranano@example.com
Generated Passwords:

The script generates potential passwords, evaluates their strength, and saves them to two files:

generated_passwords.txt for all generated passwords.
strong_passwords.txt for passwords identified as strong.
The files are also compressed and saved as .gz files.

Social Media Integration:

The tool can collect additional user information from social media (Twitter and Instagram) to enhance password generation.

License
This project is licensed under the MIT License.
