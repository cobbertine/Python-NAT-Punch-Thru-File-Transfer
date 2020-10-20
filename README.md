# NAPUFIT - (NA)T (PU)NCH-THRU (FI)LE (T)RANSFER

## Requirements
This was developed with Python 3.8.2; any OS running this version of Python should work.

For Windows users, the .exe is intended to be standalone and should have no pre-requisites.

## Usage

("lan" OR "net") AND ("upload" OR "download") ...

* if upload:
    * path_of_file_to_upload
* if download:
    * unique_id_here [-p path_of_optional_download_folder]

Note: Windows users can probably just use "python", while Linux users will likely need to use "python3" when typing the following commands in a terminal.

```
python3 napufit.py lan upload ./picture.jpg (NAPUFIT will generate a unique ID which needs to be shared with the person downloading)

python3 napufit.py lan download abcd1234 -p /home/user/Downloads

python3 napufit.py net upload ./picture.jpg (NAPUFIT will generate a unique ID which needs to be shared with the person downloading)

python3 napufit.py net download abcd1234 (wihout -p, the file is downloaded to the current folder)
```

## Configuration
* (All users) In the "app" folder there is a "config.json" file where you can set the URL of the facilitator server and the port number used for LAN discovery
* (Docker users only): In the "docker_app" folder, there is another "config.json" file where you can set what port number the local webserver will run on

Note: Docker users should ensure these files are correct when building their container

## Server-side setup
* Find a hosting provider that offers a web server and a MySQL database.
* Edit the "facilitator.php" file and set the global "$db_" variables
* Upload the "facilitator.php" file to the web server
* Using a database management tool, run the SQL command found in "create_table.sql" to create a compatible table for napufit
* (Optional) Using a database management tool, run the SQL command found in "delete_old_connections.sql". This will ensure the database routinely cleans up old connections that were not removed correctly.

## Client-side setup

### Python standard
* Open up a terminal and clone the repo
* Change to the repo's folder
* Type "pip install -r requirements.txt"
* Change to the "app" folder
* Run napufit.py using the information in the **Usage** section

### Python virtual environment
* Open up a terminal and clone the repo
* Change to the repo's folder
* Type "pip install pipenv" (Some users may need to use "pip3" instead of "pip")
* Type "pipenv install --ignore-pipfile"
* After successful installation, type "pipenv shell" (NAPUFIT will only work inside a pipenv shell)
* Change to the "app" folder
* Run napufit.py using the information in the **Usage** section

### Docker
Note: **Linux Only**. This docker setup uses the "host" network driver which is not supported on Windows at this time. **Windows users can use VirtualBox or VMWare with a Linux guest using bridged mode if they wish to run NAPUFIT in a virtual environment.**

* Install Docker and Docker Compose. Go to the official Docker website for instructions.
* Open up a terminal and clone the repo
* Change to the repo's folder
* Type: "docker-compose up --build -d"
* This will automatically create two folders in the repo folder: "docker_mount_downloads" and "docker_mount_uploads". Files you wish to share should be put in uploads, and files you receive will go to downloads
* Go to your browser and type "http://127.0.0.1:33647" in the URL bar
* Use the Web GUI to interact with NAPUFIT

### .exe (Windows Only)
Note: This .exe was created by using "nuitka" which compiles python scripts into .exes

* Go to the releases tab on this website and download napufit-win.zip
* Open up a file explorer and navigate to the downloaded file
* Unzip the file
* View the unzipped files 
* Hold down shift and right click anywhere in the window
* In the pop-up menu, an item saying "Open Powershell/Command Prompt window here" should be available. Click it.
* Type ".\napufit.exe" followed by the parameters described in the **Usage** section
