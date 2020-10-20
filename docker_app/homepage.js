const NULL_SELECT_VALUE = "";
const FORM_START = "start_form";
const FORM_QUIT = "quit_form";
const FORM_INPUT = "input_form";
const FORM_INPUT_BOX = "send_input";
const BUTTON_START = "start_button";
const BUTTON_QUIT = "quit_button";
const BUTTON_REFRESH_FILE_LIST = "refresh_file_list_button";
const SELECTION_NETWORK_TYPE = "network_type"
const SELECTION_TRANSFER_TYPE = "transfer_type";
const OPTION_TRANSFER_TYPE_UPLOAD = "upload";
const OPTION_TRANSFER_TYPE_DOWNLOAD = "download";
const FILE_LIST_SECTION = "file_name_section";
const FILE_LIST_SELECT = "file_name";
const FILE_LIST_CONTENT= "files_found";
const FILE_LIST_PLACEHOLDER = "file_list_top_anchor";
const INPUT_UNIQUE_ID = "unique_id_section";
const ATTRIBUTE_CUSTOM_FORCE_HIDE = "custom_force_hide";
const FLEX_OUTPUT_PARENT = "flex_output_parent";
const KEY_RETURNED_LINE_LEN = "line_length";
const KEY_RETURNED_LINE_DATA = "data";
const RUNNING_STATUS = "app_status";
const DIV_TRANSFER_TYPE = "transfer_type_section";
const DIV_BUTTON_START = "start_button_section"
const STYLE_CLASS_OUTPUT_GREY = "io_output_object_div_grey";

// How many rows have been printed by the client. Server uses this number to return remaining lines.
var console_log_row_count = 0; 

// Alternate output with white and light grey
var output_object_colour_switch = true;

// All my XMLHTTPRequest's route through here as I only care once it has succeeded.
function is_successful_response(xhr)
{
    return xhr.readyState === 4 && xhr.status == 200;
}

// Periodically called to check the status of the service and also to display all IO.
function update()
{
    let xhr = new XMLHttpRequest();

    // Checks the status of the service
    function read_response()
    {
        if(is_successful_response(this))
        {
            // If the service is running, say so and hide start functionality and display intereaction functionality.
            // If the service is not running, say so and show start functionality and hide interaction functionality.

            if(this.responseText.toLowerCase() === "true")
            {
                document.getElementById(FORM_START).setAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE, true);
                document.getElementById(FORM_QUIT).removeAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE);
                document.getElementById(FORM_INPUT).removeAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE);
                document.getElementById(RUNNING_STATUS).innerText = "Running";
            }
            else if(this.responseText.toLowerCase() === "false")
            {
                document.getElementById(FORM_START).removeAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE);
                document.getElementById(FORM_QUIT).setAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE, true);
                document.getElementById(FORM_INPUT).setAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE, true);
                document.getElementById(RUNNING_STATUS).innerText = "Not Running";
            }
            else
            {
                console.error("non-boolean response " + this.responseText);
            }

            // Regardless of if the service is running, grab and show the IO logs.
            let xhr = new XMLHttpRequest();
            function read_response()
            {
                if(is_successful_response(this))
                {
                    json_response = JSON.parse(this.responseText);
                    // Update how many lines the client is aware of
                    let returned_lines = json_response[KEY_RETURNED_LINE_LEN];
                    console_log_row_count += returned_lines;
                    // Insert returned lines into the Output Box.
                    let output_parent = document.getElementById(FLEX_OUTPUT_PARENT);
                    let output_data = json_response[KEY_RETURNED_LINE_DATA];

                    if(output_data.length > 0)
                    {
                        output_parent.insertAdjacentHTML("afterbegin", output_data);
                    }
                    
                    let output_objects = output_parent.children;
                    // New lines are added in reverse order, so for correct colour switching, must iterate from the last added child to the first.
                    for(let i = returned_lines - 1; i >= 0; i--)
                    {
                        if(!output_object_colour_switch)
                        {
                            let current_class = output_objects[i].getAttribute("class");
                            output_objects[i].setAttribute("class", current_class + " " + STYLE_CLASS_OUTPUT_GREY);
                        }
                        output_object_colour_switch = !output_object_colour_switch;
                    }
                }
            }
            xhr.onload = read_response;
            // Tells the server how many lines the client has printed so far, server returns remaining lines.
            xhr.open("GET", "/output/".concat(console_log_row_count.toString()));
            xhr.send();
        }
    }

    xhr.onload = read_response;
    xhr.open("GET", "/status");
    xhr.send();
}

function on_network_type_selected()
{
    let transfer_type_section = document.getElementById(DIV_TRANSFER_TYPE);
    let options_list = document.getElementById(SELECTION_NETWORK_TYPE).options;
    let selected_value = options_list[options_list.selectedIndex].value;

    if(selected_value != NULL_SELECT_VALUE)
    {
        transfer_type_section.removeAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE);
    }
    else
    {
        transfer_type_section.setAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE, true);
    }
}

// This is used to display the relevant action based on the transfer type chosen.
// If Upload is chosen, show the file picker.
// Else if Download is chosen, show the Unique ID input.
function on_transfer_type_selected()
{
    // Collect the available actions and the associated HTML elements that become available when choosing the action
    let available_actions = {};
    available_actions[OPTION_TRANSFER_TYPE_UPLOAD] = document.getElementById(FILE_LIST_SECTION);
    available_actions[OPTION_TRANSFER_TYPE_DOWNLOAD] = document.getElementById(INPUT_UNIQUE_ID);

    // Hide the actions first
    for (const key in available_actions) {
        if (available_actions.hasOwnProperty(key)) {
            const element = available_actions[key];
            element.setAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE, true);
        }
    }

    // Get what transfer type is selected.
    // The value will correspond to one of the keys saved in available_actions
    let options_list = document.getElementById(SELECTION_TRANSFER_TYPE).options;
    let selected_value = options_list[options_list.selectedIndex].value;
    let start_button_section = document.getElementById(DIV_BUTTON_START);

    if(selected_value != NULL_SELECT_VALUE)
    {
        // use selected_value to access the correspoding element to make it visible
        available_actions[selected_value].removeAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE);
        start_button_section.removeAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE);
    }
    else
    {
        start_button_section.setAttribute(ATTRIBUTE_CUSTOM_FORCE_HIDE, true);
    }
}

// Called when a user refreshes the file list. File list is only visible in upload mode.
function populate_file_list()
{
    let refresh_button = document.getElementById(BUTTON_REFRESH_FILE_LIST);
    refresh_button.setAttribute("disabled", true);
    let file_list = document.getElementById(FILE_LIST_CONTENT);

    // Delete the parent node that contains the file list options, if it exists.
    if (file_list)
    {
        file_list.remove();
    }

    // Placeholder item exists outside of file list options, used as a status indicator.
    let placeholder_item = document.getElementById(FILE_LIST_PLACEHOLDER);
    placeholder_item.innerText = "Loading ... "; 

    let xhr = new XMLHttpRequest();
    function read_response()
    {
        if(is_successful_response(this))
        {
            // Insert the option group containing the file options.
            placeholder_item.insertAdjacentHTML("afterend", this.responseText);
            placeholder_item.innerText = "Select";
            refresh_button.removeAttribute("disabled");
        }
    }
    xhr.onload = read_response;
    xhr.open("GET", "/files");
    xhr.send();
}

// Called once the config options are chosen and the user is ready to start
// Will submit a request with the correct values to be used as arguments to launch the service.
function start()
{
    let submit_button = document.getElementById(BUTTON_START);
    submit_button.setAttribute("disabled", true);
    // Gets the form containing all the required info. This form is sent with XMLHttpRequest.
    let start_form = new FormData(document.getElementById(FORM_START));
    let xhr = new XMLHttpRequest();
    function read_response()
    {
        if(is_successful_response(this))
        {
            submit_button.removeAttribute("disabled");
            // Clear the output box of old logs.
            let output_box = document.getElementById(FLEX_OUTPUT_PARENT);
            while (output_box.firstChild)
            {
                output_box.removeChild(output_box.lastChild);
            }
            console_log_row_count = 0;
        }
    }
    xhr.onload = read_response;
    xhr.open("POST", "/start");
    xhr.send(start_form);
}

// Quit while service is running.
function quit()
{
    let quit_button = document.getElementById(BUTTON_QUIT);
    quit_button.setAttribute("disabled", true);
    let xhr = new XMLHttpRequest();
    function read_response()
    {
        if(is_successful_response(this))
        {
            quit_button.removeAttribute("disabled");
        }
    }
    xhr.onload = read_response;
    xhr.open("POST", "/quit");
    xhr.send();
}

// This function is called when a user submits a value in the input box.
// Value is sent to the server to handle.
function send_command()
{
    let input_box = document.getElementById(FORM_INPUT_BOX);
    let input_form = new FormData(document.getElementById(FORM_INPUT));
    let xhr = new XMLHttpRequest();
    function read_response()
    {
        if(is_successful_response(this))
        {
            input_box.value = "";
        }
    }
    xhr.onload = read_response;
    xhr.open("POST", "/input");
    xhr.send(input_form);
}

// Related to the input box. Overrides default <input> behaviour, ensures hitting the enter key calls the send_command.
// kb.repeat ensures that this function is not called more than once accidentally.
function handle_enter_key_input_form(kb)
{
    if(kb.key === "Enter" && kb.repeat === false)
    {
        send_command();
    }
}

function handle_enter_key_start_form(kb)
{
    if(kb.key === "Enter" && kb.repeat === false)
    {
        start();
    }
}

function page_init()
{
    console.log("Begin");
    document.getElementById(FORM_INPUT).addEventListener("keydown", handle_enter_key_input_form);
    document.getElementById(FORM_START).addEventListener("keydown", handle_enter_key_start_form);
    update();
    setInterval(update, 1000);
}

window.onload = page_init;