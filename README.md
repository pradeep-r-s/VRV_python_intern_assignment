VRV Python Intern Assignment

This repository contains a Python script for analyzing server logs to extract insights like IP request counts, most accessed endpoints, and identifying suspicious activities based on failed login attempts.

Features
1) Request Count Analysis    : Track the number of requests made by each IP address.
2) Most Accessed Endpoint    : Identify the most accessed endpoint in the logs.
3) Suspicious Activity Detection    : Flag IPs exceeding a threshold of failed login attempts.

Installation

1. Clone the Repository:
  
   git clone https://github.com/pradeep-r-s/VRV_python_intern_assignment.git
   cd VRV_python_intern_assignment
 

2. Install Python:
   Ensure Python 3.6 or higher is installed on your system. 

3. Run the Script:
   The script uses only built   in Python libraries. You can execute it directly:
   python log_analysis.py

Usage
1. Place your log file in the same directory as the script and name it `sample.log` (or update the `LOG_FILE` constant in the script).
2. Run the script. The output will be displayed in the terminal and saved in a file named `log_analysis_results.csv`.

Example Output
PS C:\Users\prade\Desktop\vrv_python> python -u "c:\Users\prade\Desktop\vrv_python\log_analysis.py"

Requests per IP:
192.168.1.1     10
203.0.113.5     8
10.0.0.2        6
198.51.100.23   11
192.168.1.100   5

Most Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
203.0.113.5     8

Results saved to log_analysis_results.csv

And Csv file as follows:
IP Address	Request Count
192.168.1.1	    10
203.0.113.5    	8
10.0.0.2	      6
198.51.100.23  	11
192.168.1.100	  5
	
Most Accessed Endpoint	Access Count
/login	13
	
IP Address	Failed Login Attempts
203.0.113.5	8
![image](https://github.com/user-attachments/assets/6006c82c-6198-4eb4-ac31-cc9fab0e82b6)


Configuration

You can modify the following constants in the script:
LOG_FILE: The name of the log file to be analyzed.
OUTPUT_CSV: The name of the CSV file to save the results.
FAILED_LOGIN_THRESHOLD: The threshold for detecting suspicious activity based on failed login attempts.
