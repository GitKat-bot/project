import warnings
warnings.filterwarnings('ignore')
import os
import zipfile
import requests
import subprocess

class FrameWork:
    FLUTTER = "Flutter"
    REACT_NATIVE = "React Native"
    CORDOVA = "Cordova"
    XAMARIN = "Xamarin"

class Technology:
    def __init__(self, framework, directories, cert_pinning, root_detection):
        self.framework = framework
        self.directories = directories
        self.cert_pinning = cert_pinning
        self.root_detection = root_detection

# Global list of technology configurations
tech_list = [
    Technology(FrameWork.FLUTTER, ["libflutter.so"], True, True),
    Technology(FrameWork.REACT_NATIVE, ["libreactnativejni.so", "assets/index.android.bundle"], True, True),
    Technology(FrameWork.CORDOVA, ["assets/www/index.html", "assets/www/cordova.js", "assets/www/cordova_plugins.js"], True, True),
    Technology(FrameWork.XAMARIN, ["/assemblies/Sikur.Monodroid.dll", "/assemblies/Sikur.dll", "/assemblies/Xamarin.Mobile.dll", "/assemblies/mscorlib.dll", "libmonodroid.so", "libmonosgen-2.0.so"], True, True)
]

def unzip_apk(apk_path):
    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(os.path.dirname(apk_path))
        print("APK unzipped successfully.")
    except Exception as e:
        print(f"Error unzipping APK: {e}")

def get_app_type(apk_path):
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk:
            for file in apk.namelist():
                if any(directory in file for directory in ["lib/", "assets/", "res/"]):
                    if 'libflutter.so' in file:
                        return FrameWork.FLUTTER
                    elif 'libreactnativejni.so' in file or 'index.android.bundle' in file:
                        return FrameWork.REACT_NATIVE
                    elif 'Sikur.Monodroid.dll' in file or 'Xamarin.Mobile.dll' in file:
                        return FrameWork.XAMARIN
                    elif 'cordova.js' in file or 'cordova_plugins.js' in file:
                        return FrameWork.CORDOVA
                    elif 'www/' in file or 'res/' in file:
                        return FrameWork.CORDOVA
    except Exception as e:
        print(f"Error analyzing APK: {e}")
    return 'Unknown'

def check_security_features(detected_framework):
    for tech in tech_list:
        if detected_framework == tech.framework:
            print(f"Detected framework: {detected_framework}")
            print(f"Associated directories: {', '.join(tech.directories)}")
            print(f"Certificate pinning: {'Yes' if tech.cert_pinning else 'No'}")
            print(f"Root detection: {'Yes' if tech.root_detection else 'No'}")
            return
    print(f"No specific directories found for the {detected_framework} framework.")

def list_files_in_github_repo(framework, folder_type):
    owner = 'GitKat-bot'
    repo = 'project'
    path = f'frameworks/{framework.lower()}/{folder_type}'
    url = f'https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref=main'
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Failed to fetch contents from {url}. Error: {e}")
        return []

def download_file(file_url, file_name):
    try:
        response = requests.get(file_url)
        response.raise_for_status()
        with open(file_name, 'wb') as file:
            file.write(response.content)
        print(f"Downloaded {file_name} successfully.")
    except requests.RequestException as e:
        print(f"Failed to download {file_name}. Error: {e}")

def execute_frida_scripts(pinning_script, root_detection_script, app_id):
    try:
        command = ["frida", "-U", "-f", app_id]
        if pinning_script:
            command += ["-l", pinning_script]
        if root_detection_script:
            command += ["-l", root_detection_script]

        print(f"Executing Frida command: {' '.join(command)}")
        result = subprocess.run(command, check=True, text=True, capture_output=True)

        print("Frida command output:")
        print(result.stdout)
        if result.stderr:
            print("Frida command errors:")
            print(result.stderr)
        
        # Log output for further inspection if needed
        with open('frida_output.log', 'w') as log_file:
            log_file.write(result.stdout)
            if result.stderr:
                log_file.write(result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Frida command failed with exit code {e.returncode}")
        print(f"Error message: {e.stderr}")
    except Exception as e:
        print(f"Failed to execute Frida scripts. Error: {e}")

def choose_script(files, script_type):
    while True:
        print(f"\nSelect a {script_type} script to download:")
        for index, file in enumerate(files, start=1):
            print(f"{index}. {file['name']}")
        
        file_choice = input("Enter your choice: ").strip()
        
        if file_choice.isdigit():
            file_choice = int(file_choice) - 1
            if 0 <= file_choice < len(files):
                file_url = files[file_choice]['download_url']
                script_name = files[file_choice]['name']
                return file_url, script_name
            else:
                print("Invalid choice. Please select a number from the list.")
        else:
            print("Invalid input. Please enter a number corresponding to a choice.")

def analyze_apk():
    while True:
        apk_path = input("Please enter the APK file path: ").strip()
        if not os.path.isfile(apk_path):
            print("The specified file does not exist. Please enter a valid APK file path.")
            continue
        unzip_apk(apk_path)
        detected_framework = get_app_type(apk_path)
        check_security_features(detected_framework)
        
        pinning_script = None
        root_detection_script = None
        if detected_framework in [FrameWork.CORDOVA, FrameWork.REACT_NATIVE, FrameWork.XAMARIN, FrameWork.FLUTTER]:
            if any(tech.cert_pinning for tech in tech_list if tech.framework == detected_framework):
                folder_type = 'certificate_pinning'
                files = list_files_in_github_repo(detected_framework, folder_type)
                if files:
                    file_url, pinning_script = choose_script(files, "certificate pinning")
                    download_file(file_url, pinning_script)
                else:
                    print("No files found for certificate pinning.")
            if any(tech.root_detection for tech in tech_list if tech.framework == detected_framework):
                folder_type = 'root_detection'
                files = list_files_in_github_repo(detected_framework, folder_type)
                if files:
                    file_url, root_detection_script = choose_script(files, "root detection")
                    download_file(file_url, root_detection_script)
                else:
                    print("No files found for root detection.")
            
            # Ask if user wants to execute the downloaded scripts
            execute_choice = input("Do you want to execute the downloaded scripts now? (yes/no): ").strip().lower()
            if execute_choice == 'yes':
                app_id = input("Enter the app ID for Frida: ").strip()
                execute_frida_scripts(pinning_script, root_detection_script, app_id)
            
        else:
            print(f"Framework {detected_framework} not supported or no security features detected.")
        
        while True:
            continue_choice = input("Do you want to analyze another APK? (yes/no): ").strip().lower()
            if continue_choice == 'no':
                print("Exiting the program.")
                return
            elif continue_choice == 'yes':
                break
            else:
                print("Invalid input. Please enter 'yes' or 'no'.")

# Start the APK analysis process
analyze_apk()
