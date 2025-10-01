# ANSSI Alerts Recovery, Processing, and Notification System

## Project Overview
The primary goal of this project is to automate the retrieval of security alerts (advisories and alerts) issued by the French National Cybersecurity Agency (ANSSI) and to notify potentially affected users based on their preferences and identified vulnerabilities.

## Installation
No specific installation is required. All necessary libraries are directly imported into your IDE.

## Project Structure
- **`projetv4.py`**: The main script that runs the program.
- **`images/`**: Directory containing images used in emails.
- **`data/`**: Directory containing various data files required for the program to run smoothly:
  - **`users.csv`**: Contains user information (email, preferences, software).
    - To add users, simply append a new line following the format of the first user:
      ```
      email_address,Software1-Software2-...-SoftwareN,TYPE1-...-TYPEN
      ```
    - Types can be: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, or `ALL`.
  - **`feed.csv`**: Contains RSS feed links and their last retrieval dates.
    - If you want to verify the algorithm's functionality, ensure the RSS feed retrieval date in the file does not already match the last update date on the site. Otherwise, you may not retrieve any entries.
  - **`donnees_cybersec.csv`**: Contains all alerts and advisories from the ANSSI website. **DO NOT MODIFY**.

## Usage

### Important Note
On the first run, your machine may not find the files at the specified paths. This is because the machine is not looking in the correct directory. Please add the following lines at the beginning of the program to specify the correct path:

```python
import os
# Absolute path to the new working directory
new_working_directory = r"your_project_directory_path"

# Change the current directory
os.chdir(new_working_directory)
```

Replace `your_project_directory_path` with the path leading to the project folder named "Projet".

## Future Improvements
- **Enhanced User Interface**: Develop a web-based dashboard for easier interaction and visualization of alerts.
- **Automated Updates**: Implement a cron job or scheduled task to automatically fetch and process new alerts at regular intervals.
- **Integration with SIEM**: Connect the system with Security Information and Event Management (SIEM) tools for real-time monitoring and response.
- **Multi-language Support**: Add support for multiple languages in notifications and user interfaces.
- **Advanced Filtering**: Allow users to set more granular filters for the types of alerts they receive.

## License
This project is licensed under the MIT License.

## Video Demo
A demo video is available [here](https://www.canva.com/design/DAGcjl92Tds/030gckNti1Ik_9mSAH8doA/watch?utm_content=DAGcjl92Tds&utm_campaign=designshare&utm_medium=link2&utm_source=uniquelinks&utlId=hda551ef468).
