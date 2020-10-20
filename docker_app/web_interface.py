import bottle
import subprocess
import functools
import os.path
import json
import threading
import time
import queue

class ConfigHandler():
    def __init__(self):
        with open("config.json") as f:
            config = json.load(f)
            self.WEB_PORT = config["web_port"]


class EmptySTDOut(Exception):
    def __str__(self):
        return "Empty NAPUFIT stdout"

class IOHandler:

    IO_WAIT_TIME = 1

    # List of all input and output text
    # When /output/(line_count) is called, io_log is accessed.
    io_log = []
    LOCK_OUTPUT = threading.RLock()

    # Text that is sent to NAPUFIT stdin.
    # Queue apparently handles concurrency
    queue_input_buffer = queue.Queue()

    process_napufit = None
    thread_write = None
    thread_read = None

    def append_io_log(self, text):
        with self.LOCK_OUTPUT:
            self.io_log.append(text)

    def append_input_buffer(self, text):
        self.queue_input_buffer.put(text)

    def get_io_log_tail(self, startIndex):
        with self.LOCK_OUTPUT:
            return self.io_log[startIndex:]

    # Can raise an Empty exception
    def get_fifo_input_buffer(self):
        return self.queue_input_buffer.get(block=False)

    def clear_io_log(self):
        with self.LOCK_OUTPUT:
            self.io_log.clear()

    def clear_input_buffer(self):
        while not self.queue_input_buffer.empty():
            self.queue_input_buffer.get(block=False)

    # It is possible stdin may block, therefore this has been put into its own thread
    # It will monitor the input_buffer and write it to stdin when it has content.
    def write_stdin(self):
        while self.process_napufit.poll() is None:
            try:
                self.process_napufit.stdin.write(self.get_fifo_input_buffer())
                self.process_napufit.stdin.flush()
            except:
                # Pipe has broken or queue is empty.
                # If pipe has broken, process is dead so while loop will exit after this sleep.
                time.sleep(self.IO_WAIT_TIME)
            
    def read_stdout(self):
        # The intermediate buffer is the text read from stdout so far.
        # It is saved to io_log once a newline character is found.
        intermediate_buffer = ""
        last_update_intermediate_buffer = time.monotonic()

        # If NAPUFIT does not output a newline (this happens when it prompts for user input), then stdout.read will block. 
        # In such a scenario, we can detect if it's been blocking and inject a newline character and commit the message to the io_log
        def monitor_block():
            nonlocal intermediate_buffer
            nonlocal last_update_intermediate_buffer
            while self.process_napufit.poll() is None:
                with self.LOCK_OUTPUT:
                    if time.monotonic() - last_update_intermediate_buffer > self.IO_WAIT_TIME and len(intermediate_buffer) > 0:
                        self.append_io_log(intermediate_buffer + "\n")
                        intermediate_buffer = ""
                        last_update_intermediate_buffer = time.monotonic()
                time.sleep(self.IO_WAIT_TIME)

        thread_monitor = threading.Thread(target=monitor_block)
        thread_monitor.daemon = True
        thread_monitor.start()

        while self.process_napufit.poll() is None or thread_monitor.is_alive():
            try:
                # Read one byte at a time, because a newline character may never come.
                byte = self.process_napufit.stdout.read(1)
                with self.LOCK_OUTPUT:
                    intermediate_buffer = intermediate_buffer + byte
                    if byte == "\n":
                        # Save output if it's not just a blank line.
                        # Clear out the buffer either way.
                        if len(intermediate_buffer.rstrip()) > 0:
                            self.append_io_log(intermediate_buffer)
                        intermediate_buffer = ""
                    # At this point, the buffer has been updated in some way.
                    last_update_intermediate_buffer = time.monotonic()
            except:
                # File descriptor potentially closed
                time.sleep(self.IO_WAIT_TIME)

    def communicate(self, process_napufit):
        # If new process provided
        if self.process_napufit is not process_napufit:
            # And there already exists a process terminating/terminated...
            if self.process_napufit is not None:
                # Wait for the IO threads to terminate.
                while self.thread_read.is_alive() or self.thread_write.is_alive():
                    time.sleep(self.IO_WAIT_TIME)
                self.process_napufit = None
                
            # At this point, no other thread are running except the main thread.
            # There is no risk at this point for anything to interfere with this IO object.
            #     
            # Clear out the IO lists, reference the new process and restart the IO threads:
            self.clear_io_log()
            self.clear_input_buffer()
            self.process_napufit = process_napufit
            self.thread_read = threading.Thread(target=self.read_stdout)
            self.thread_read.daemon = True
            self.thread_write = threading.Thread(target=self.write_stdin)
            self.thread_write.daemon = True
            self.thread_read.start()
            self.thread_write.start()


io_handler_singleton = IOHandler()

config = ConfigHandler()
BOTTLE_BIND_PORT = config.WEB_PORT

# Text object in output window
HTML_OUTPUT_OBJECT = '''
<div class="io_output_object_div">
    <span class="io_output_object_span">Output: </span>{output}
</div>\n
'''

# parent of all available files, easy to clear list this way
HTML_FILE_LIST_PARENT_OBJECT = '''
<optgroup label="Files" id="files_found">
    {html_file_object}
</optgroup>\n
'''

# child of HTML_FILE_LIST_PARENT_OBJECT
HTML_FILE_OBJECT = '''
<option value="{file_name}">{file_name}</option>\n
'''

FILE_NAPUFIT = "napufit.py"
FILE_HOMEPAGE = "homepage.html"
FILE_JAVASCRIPT = "homepage.js"
FILE_CSS = "homepage.css"

FILE_RELATIVE_PATH_TO_UPLOADABLE_FILES = "/docker_mount_uploads" 
FILE_RELATIVE_PATH_TO_DOWNLOADED_FILES = "/docker_mount_downloads"
FILE_RELATIVE_PATH_FROM_DOCKER_TO_NAPUFIT = "../app"

REQUEST_KEY_NETWORK_TYPE = "network_type"
REQUEST_KEY_TRANSFER_TYPE = "transfer_type"
REQUEST_KEY_UNIQUE_ID = "unique_id"
REQUEST_KEY_FILE_NAME = "file_name"
REQUEST_KEY_INPUT_TEXT = "send_input"
REQUEST_VAL_TRANSFER_TYPE_DOWNLOAD = "download"
REQUEST_VAL_TRANSFER_TYPE_UPLOAD = "upload"

# Singleton process returned by Popen
process_napufit = None

# Homepage
@bottle.get("/")
def get_homepage():
    response_object = bottle.static_file(FILE_HOMEPAGE, root=".")
    response_object.set_header('Cache-Control', 'no-store')
    response_object.set_header('Pragma', 'no-cache')
    return response_object

@bottle.get("/homepage.js")
def get_javascript():
    response_object = bottle.static_file(FILE_JAVASCRIPT, root=".")
    response_object.set_header('Cache-Control', 'no-store')
    response_object.set_header('Pragma', 'no-cache')
    return response_object

@bottle.get("/homepage.css")
def get_css():
    response_object = bottle.static_file(FILE_CSS, root=".")
    response_object.set_header('Cache-Control', 'no-store')
    response_object.set_header('Pragma', 'no-cache')
    return response_object    

# Start Service
@bottle.post("/start")
def start_service():
    global process_napufit

    if process_napufit is not None and process_napufit.poll() is None:
        bottle.abort(500, "Process already running")

    network_type = bottle.request.forms.get(REQUEST_KEY_NETWORK_TYPE)
    transfer_type = bottle.request.forms.get(REQUEST_KEY_TRANSFER_TYPE)

    if transfer_type == REQUEST_VAL_TRANSFER_TYPE_DOWNLOAD:
        transfer_parameter = bottle.request.forms.get(REQUEST_KEY_UNIQUE_ID)
        optional_download_path_arg_value = ["-p", os.path.abspath(FILE_RELATIVE_PATH_TO_DOWNLOADED_FILES)]
    elif transfer_type == REQUEST_VAL_TRANSFER_TYPE_UPLOAD:
        file_to_upload = bottle.request.forms.get(REQUEST_KEY_FILE_NAME)
        transfer_parameter = os.path.abspath(os.path.join(FILE_RELATIVE_PATH_TO_UPLOADABLE_FILES, file_to_upload)) if len(file_to_upload) else ""
        # Upload action does not need download action related arguments.
        optional_download_path_arg_value = []
    else:
        return

    LAUNCH_NAPUFIT = ["python3", FILE_NAPUFIT, network_type, transfer_type, transfer_parameter] + optional_download_path_arg_value
    # subprocess.PIPE means we can write to NAPUFIT's stdin and read its stdout. Text=true means text I/O rather than bytes
    process_napufit = subprocess.Popen(LAUNCH_NAPUFIT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=FILE_RELATIVE_PATH_FROM_DOCKER_TO_NAPUFIT, text=True)
    io_handler_singleton.communicate(process_napufit)

# Quit Service
@bottle.post("/quit")
def quit_service():
    # SIGTERM 15
    process_napufit.terminate()
    # Wait for process to end and close all FDs.
    process_napufit.communicate()

# Service Status
@bottle.get("/status")
def get_status():
    try:
        # poll() returns a number when the process has died, otherwise None.
        return "true" if process_napufit.poll() is None else "false"
    except:
        # singleton is null
        return "false"

# Get available files for upload.
# Only the file names are returned, their full paths are kept server-side.
@bottle.get("/files")
def get_files():
    files = os.listdir(FILE_RELATIVE_PATH_TO_UPLOADABLE_FILES)
    html_option_list = list()
    for file in files:
        html_option_list.append(HTML_FILE_OBJECT.format(file_name=file))
    if len(html_option_list) > 0:
        html_option_string = functools.reduce(lambda s1, s2 : s1+s2, html_option_list)
        return HTML_FILE_LIST_PARENT_OBJECT.format(html_file_object=html_option_string)
    else:
        return ""

# Get Service Output
# <line_count> is how many lines the client currently has.
@bottle.get("/output/<line_count>")
def get_output(line_count):
    line_count = int(line_count)
    required_lines = io_handler_singleton.get_io_log_tail(line_count)
    returned_lines = len(required_lines)
    if returned_lines > 0:
        formatted_output_list = []
        for line in required_lines:
            formatted_output_list.append(HTML_OUTPUT_OBJECT.format(output=line))
        # Website shows io_log in reverse order. 
        # New elements appear at bottom of container, but must appear at top of HTML document.
        formatted_output_list = formatted_output_list[::-1]
        formatted_output_string = functools.reduce(lambda s1, s2: s1+s2, formatted_output_list)
        return {"line_length":returned_lines, "data":formatted_output_string}
    else:
        return {"line_length":returned_lines, "data":""}

# Send Input
@bottle.post("/input")
def send_input():
    input_text = bottle.request.forms.get(REQUEST_KEY_INPUT_TEXT)
    # Save input_text to queue input buffer so the other thread can handle it. 
    # Ensure it has a newline character as NAPUFIT does not know input is complete until it sees a  newline
    io_handler_singleton.append_input_buffer(input_text + "\n" if "\n" not in input_text else "")
    io_handler_singleton.append_io_log("Input: " + input_text)
    
bottle.run(host="127.0.0.1", port=BOTTLE_BIND_PORT)