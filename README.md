# Automated APK analyzer 

## Main purpose and tool description

Mobile penetration testing can be a time-consuming and complex process, particularly when it comes to static analysis of the code, identifying the correct scripts, and framework and library identification can further extend the testing duration, as different frameworks have distinct security implementations and libraries. Automation can significantly alleviate these challenges by streamlining the identification of the framework and associated libraries, and by providing tailored Frida scripts for bypassing security measures. 


## Tool focused on automate the mobile penetration testing methodology and consists on analyze an APK file that will provide

  1. **Frameworks**: It will detect the framework used to determine the effectiveness of the Frida script. For example, different libraries for Root Detection may be utilized across various frameworks, so identifying the framework will help us pinpoint the specific libraries and provide an appropriate script. 

  2. **Directories**: Understanding the directory structure of mobile app frameworks is crucial for penetration testers as it helps locate key files, such as configuration files, source code, and resources, which may contain sensitive information or security vulnerabilities. It enables testers to analyze build artifacts like APKs or IPAs for insecure code or debug settings, assess third-party libraries for vulnerabilities, and review custom scripts for potential weaknesses.

  3. **Security Mechanisms enabled**: At the moment, the detected security mechanisms are Certificate Pinning and Root Detection. Knowing this information, the tester can identify which mechanisms are enabled, focus on one to start the test, and work on bypassing the security measure with the scripts provided
     
  4. **Frida bypass scripts**: The system will offer a comprehensive collection of scripts designed to bypass Certificate Pinning and Root Detection, tailored to the specific frameworks identified during the analysis. Each script will be categorized based on the framework it supports, such as Flutter, Xamarin, React Native, or Cordova. Additionally, the tool will provide a menu, allowing individuals to select and download the exact script they need. This functionality ensures that users can efficiently access and utilize the necessary tools for their penetration testing needs, streamlining the process of overcoming security measures in different mobile app frameworks.

## Usage

Once you have an APK file downloaded:
 1. Run the main.py and provide the APK file path
 2. Once analyzed, select the security mechanism
 3. It will provide a list of scripts related to the framework analyzed, select the script that you want to download
 4. Downloaded and ready to use in your Frida environment!


## Authors
This project is a creation of the 2024 X-Force Red Internship

Katherine Tello

Dylan Calderon
