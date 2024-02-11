
- ### How to bypass Root Detection with several techs?

Hook isRooted function
Magisk : change app name
Zygisk : deny application
Frida Scripts
Medusa Tool

- ### How to bypass SSL Pinning with several techs?
Hook IsEncrypted function
NSC File
Trust Manager
Frida Scripts
Medusa
Downgrade app to 6.0 version

- ### What are the tools you are using?
ApkTool
MobSF
Medusa
Frida Scripts
Drozer
Objection
IDA, JadX

- ### What is the diff between arm and x64/x86?
x64/x86 => Emulator
arm => physical device

- ### What will you do if you found source code obfuscated?
Automated tools like:
ProGuard Deobfuscator
Bytecode Viewer
Simplify
Revenge
Xenotix APK Decompiler

- ### How do you know there is native lib?
function name = native , then use frida spawn :enumexportssync to search for info about the library, then hooking the library by using frida inspector to the lib address in the code.

- ### What are android permissions?
android.permission.INTERNET
android.permission.ACCESS_NETWORK_STATE
android.permission.RECORD_AUDIO
android.permission.READ_EXTERNAL_STORAGE
android.permission.WRITE_EXTERNAL_STORAGE
android.permission.RECIEVE

- ### What are diff between static and dynamic broadcast receivers with functions?
static: run anytime , OnRecieve
dynamic: run in runtime only , EmailBroadCastRecv

- #### How does Zygisk work?
zygisk use ptrace function to trigger all the calls and bypassing root detection, bypass SafetyNet

- ### Explain a dynamic scenario?
change NSC File to trust user certificate, then rebuild the file with apktool and resign the app.

- ### How to exploit android backup?
once we found android:allowBackup=” true" in the manifest, so the app allow the user to backup the app data that allow user to search for secrets or confidential data in app files like shared_prefs or db files [secrets - pass - auth token for API's]

- ### How to exploit android debuggeable?
once we found android:debuggable="true" in the manifest, so the app allow the user to debug the app internally. so user can bypass security checks using the app in debuggeable mode.

- ### How to exploit & Reverse React Native app?
Rename the APK file with a zip extension and extract it to a new folder using the command `cp com.example.apk example-apk.zip` and `unzip -qq example-apk.zip -d ReactNative`.
Navigate to the newly created ReactNative folder and locate the assets folder. Inside this folder, you should find the file `index.android.bundle`, which contains the React JavaScript in a minified format.
Use the command `find . -print | grep -i ".bundle$"` to search for the JavaScript file.
To further analyze the JavaScript code, create a file named `index.html` in the same directory with the following code:
<script src="./index.android.bundle"></script>
Open the `index.html` file in Google Chrome.
Open the Developer Toolbar by pressing **Command+Option+J for OS X** or **Control+Shift+J for Windows**.
Click on "Sources" in the Developer Toolbar. You should see a JavaScript file that is split into folders and files, making up the main bundle.
If you find a file called `index.android.bundle.map`, you will be able to analyze the source code in an unminified format. Map files contain source mapping, which allows you to map minified identifiers.

- ### How to Modify Smali Code?
Using APKLab, rebuilt with apk.yml and patch the app.

- ### How to find Hardcoded secrets?
Logs
Resource-code
reverse library
shared_prefs
temp_file
databases file
sdcard

- ### How to find remote db link or keys or specific values in app?
res-values-strings.xml

- ### How to know there's deep link in the app?
android:scheme in the manifest and key in strings.xml

- ### How to know there's provider in the app?
permission : provider , maybe exported:true/false

- ### How to know the app built with Xamarin?
the app using xamarin by the 'xamarin.android.net' file

- ### How to know the app built with flutter?
the app using flutter by the 'io' file

- ### How to bypass SSL Pinning in flutter apps?
using automation process with reflutter tool or manual process to patch the flutter lib.so

- ### How to reverse Xamarin apps?
To decompress Xamarin file use Xamarin_XALZ_decommperss.py script then pass the new file to DnSpy tool to reverse the code

- ### What is RASP?
Runtime Application Self Protection (RASP) is a security solution designed to **provide personalized protection to applications**. It takes advantage of insight into an application's internal data and state to enable it to identify threats at runtime that may have otherwise been overlooked by other security solutions.

- ### How to bypass RASP?
using Ghidra tool , customized scripts.