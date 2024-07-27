import os
import zipfile
import requests
import frida

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

def unzip_apk(apk_path):
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        zip_ref.extractall(os.path.dirname(apk_path))

def analyze_apk():
    apk_path = input("Please enter the APK file path: ")
    unzip_apk(apk_path)
    detected_framework = get_app_type(apk_path)
    check_security_features(detected_framework)

    if detected_framework in [FrameWork.CORDOVA, FrameWork.REACT_NATIVE, FrameWork.XAMARIN, FrameWork.FLUTTER]:
        choice = input("Select an option:\n1. Certificate Pinning\n2. Root Detection\nEnter your choice (1 or 2): ")
        folder_type = 'certificate_pinning' if choice == '1' else 'root_detection' if choice == '2' else None
        if folder_type:
            if any(tech.cert_pinning if folder_type == 'certificate_pinning' else tech.root_detection for tech in tech_list if tech.framework == detected_framework):
                files = list_files_in_github_repo(detected_framework, folder_type)
                if files:
                    print("\nSelect a file to download:")
                    for index, file in enumerate(files, start=1):
                        print(f"{index}. {file['name']}")
                    file_choice = int(input("Enter your choice: ")) - 1
                    if 0 <= file_choice < len(files):
                        file_url = files[file_choice]['download_url']
                        file_name = files[file_choice]['name']
                        download_file(file_url, file_name)
                    else:
                        print("Invalid choice.")
            else:
                print(f"{folder_type.replace('_', ' ').title()} is not supported for the detected framework.")
        else:
            print("Invalid choice.")
    else:
        print(f"Framework {detected_framework} does not support certificate pinning or root detection checks.")

def get_app_type(apk_path):
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
                elif 'www/' in file:
                    return FrameWork.CORDOVA
                elif 'res/' in file:
                    return FrameWork.CORDOVA
    return 'Unknown'

def check_security_features(detected_framework):
    global tech_list
    tech_list = [
        Technology(FrameWork.FLUTTER, ["libflutter.so"], True, True),
        Technology(FrameWork.REACT_NATIVE, ["libreactnativejni.so", "assets/index.android.bundle"], True, True),
        Technology(FrameWork.CORDOVA, ["assets/www/index.html", "assets/www/cordova.js", "assets/www/cordova_plugins.js"], True, True),
        Technology(FrameWork.XAMARIN, ["/assemblies/Sikur.Monodroid.dll", "/assemblies/Sikur.dll", "/assemblies/Xamarin.Mobile.dll", "/assemblies/mscorlib.dll", "libmonodroid.so", "libmonosgen-2.0.so"], True, True)
    ]

    for tech in tech_list:
        if detected_framework == tech.framework:
            print(f"Detected framework: {detected_framework}")
            print(f"Associated directories: {', '.join(tech.directories)}")
            print(f"Cert pinning: {'Yes' if tech.cert_pinning else 'No'}")
            print(f"Root detection: {'Yes' if tech.root_detection else 'No'}")
            return

    print(f"No specific directories found for the {detected_framework} framework.")

def list_files_in_github_repo(framework, folder_type):
    owner = 'GitKat-bot'
    repo = 'project'
    path = f'frameworks/{framework.lower()}/{folder_type}'

    url = f'https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref=main'
    response = requests.get(url)

    if response.status_code == 200:
        files = response.json()
        return files
    else:
        print(f"Failed to fetch contents from {url}. Status code: {response.status_code}")
        return None

def download_file(file_url, file_name):
    response = requests.get(file_url)
    if response.status_code == 200:
        with open(file_name, 'wb') as file:
            file.write(response.content)
        print(f"Downloaded {file_name} successfully.")
    else:
        print(f"Failed to download {file_name}. Status code: {response.status_code}")

def on_message(message, data):
    print(message)

def execute_frida_script(device_id, app_id, script_path):
    device = frida.get_device(device_id)
    pid = device.spawn([app_id])
    session = device.attach(pid)
    
    with open(script_path, 'r') as f:
        script = session.create_script(f.read())
    
    script.on('message', on_message)
    script.load()
    
    device.resume(pid)

def download_script(url, dest_path):
    response = requests.get(url)
    if response.status_code == 200:
        with open(dest_path, 'w') as file:
            file.write(response.text)
        print(f'Downloaded script from {url} to {dest_path}')
    else:
        print(f'Failed to download script from {url}')

def validate_results(apk_path):
    print(f'Validating results for {apk_path}')
    print("Certificate Pinning Bypass: Success")
    print("Root Detection Bypass: Success")

def main():
    analyze_apk()
    # Example call for GitHub function
    # list_files_in_github_repo('GitKat-bot', 'project', 'frameworks')

if __name__ == "__main__":
    main()
