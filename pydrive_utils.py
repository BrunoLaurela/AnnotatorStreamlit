import os
import json
from itertools import groupby
from datetime import datetime, timedelta
#from io import BytesIO, StringIO
import base64
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from oauth2client.service_account import ServiceAccountCredentials

import tempfile

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle

from googleapiclient.discovery import build
SCOPES = ['https://www.googleapis.com/auth/drive']


def get_drive(path_to_json):
    """Get the Drive instance from the service account keys.
    
    Parameters
    ----------
    path_to_json : str
        Path to the json file that contains the service account credentials.

    Returns
    -------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.

    """
    # Set scope. This particular choice makes sure to give full access.
    scope = ["https://www.googleapis.com/auth/drive"]

    # Authorization instance.
    gauth = GoogleAuth()
    gauth.auth_method = 'service'
    gauth.credentials = ServiceAccountCredentials.from_json_keyfile_name(
        path_to_json, 
        scope
    )

    # Get drive.
    drive = GoogleDrive(gauth)
    
    # Return drive.
    return drive
"""def get_drive_oauth(client_secrets,token_json_b64):
    gauth = GoogleAuth()

    # Decodificar base64 a JSON string
    client_secrets_json = base64.b64decode(token_json_b64).decode("utf-8")

    # Guardar el JSON decodificado en un archivo temporal
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as temp_file:
        temp_file.write(client_secrets_json)
        temp_file.flush()
        temp_path = temp_file.name

    # Cargar configuración OAuth desde el archivo temporal
    gauth.LoadClientConfigFile(temp_path)

    # Definir ruta para guardar credenciales en carpeta temporal
    creds_path = os.path.join(tempfile.gettempdir(), "mycreds.txt")

    # Intentar cargar credenciales guardadas (tokens)
    try:
        gauth.LoadCredentialsFile(creds_path)
    except Exception:
        pass

    if gauth.credentials is None:
        gauth.LocalWebserverAuth()  # login
    elif gauth.access_token_expired:
        gauth.Refresh()             # renovar token
        gauth.Authorize()           # usar token existente

    # Guardar credenciales para próxima vez en la ruta temporal
    gauth.SaveCredentialsFile(creds_path)

    drive = GoogleDrive(gauth)
    return drive    """
import base64
import tempfile
import os
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive

def get_drive_oauth(client_secrets_str, token_json_b64):
    gauth = GoogleAuth()

    # Guardar client_secrets en archivo temporal
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as temp_file:
        temp_file.write(client_secrets_str)
        temp_file.flush()
        client_secrets_path = temp_file.name

    gauth.LoadClientConfigFile(client_secrets_path)

    # Decodificar token base64
    token_json_str = base64.b64decode(token_json_b64).decode("utf-8")

    # Guardar token en archivo temporal
    creds_path = os.path.join(tempfile.gettempdir(), "mycreds.txt")
    with open(creds_path, "w") as token_file:
        token_file.write(token_json_str)

    # Intentar cargar credenciales (token)
    gauth.LoadCredentialsFile(creds_path)

    if gauth.credentials is None:
        # Aquí agregamos para que solicite refresh_token
        gauth.settings['get_refresh_token'] = True
        gauth.settings['access_type'] = 'offline'
        gauth.settings['prompt'] = 'consent'

        gauth.LocalWebserverAuth()  # login manual si no hay token
    elif gauth.access_token_expired:
        gauth.Refresh()             # renovar token
        gauth.Authorize()

    gauth.SaveCredentialsFile(creds_path)

    drive = GoogleDrive(gauth)
    return drive
def get_drive_oauth_(secrets):
    gauth = GoogleAuth()

    client_config = {
        "installed": {
            "client_id": secrets["oauth_client"]["client_id"],
            "client_secret": secrets["oauth_client"]["client_secret"],
            "redirect_uris": secrets["oauth_client"]["redirect_uris"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
        }
    }

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as f:
        json.dump(client_config, f)
        f.flush()
        client_secrets_path = f.name

    gauth.LoadClientConfigFile(client_secrets_path)

    token_json_b64 = secrets["oauth_client"]["token_json_base64"]
    token_json_str = base64.b64decode(token_json_b64).decode("utf-8")

    creds_path = os.path.join(tempfile.gettempdir(), "mycreds.txt")
    with open(creds_path, "w") as token_file:
        token_file.write(token_json_str)

    gauth.LoadCredentialsFile(creds_path)

    if gauth.credentials is None:
        gauth.LocalWebserverAuth()
    elif gauth.access_token_expired:
        gauth.Refresh()
        gauth.Authorize()

    gauth.SaveCredentialsFile(creds_path)

    drive = GoogleDrive(gauth)
    return drive

def get_dicts(drive, todo_name, toreview_name, done_name, discarded_name, parent_folder_id=None):
    """Get dictionaries for to-do, to-review, done, and discarded files with metadata.

    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    todo_name : str
        Name of the to-do folder.
    toreview_name : str
        Name of the to-review folder.
    done_name : str
        Name of the done folder.
    discarded_name : str
        Name of the discarded folder.
    parent_folder_id : str, optional
        ID of the parent folder to search within (default is None).

    Returns
    -------
    tuple
        A tuple containing folder_dict, todo_dict, toreview_dict, done_dict, discarded_dict.
    """
    # Query to find folders
    query = f"trashed=false and mimeType='application/vnd.google-apps.folder'"
    if parent_folder_id:
        query += f" and '{parent_folder_id}' in parents"
    # Comprobar que todas las carpetas existen

    
    # Buscar todas las carpetas visibles que coincidan
    found_folders = drive.ListFile({"q": query}).GetList()

    # Crear diccionario con las carpetas encontradas por nombre
    folder_dict = {
        gfile['title']: gfile
        for gfile in found_folders
        if gfile['title'] in [todo_name, toreview_name, done_name, discarded_name]
    }

    """folder_dict = {
        fname: gfile 
        for gfile in drive.ListFile({"q": query}).GetList() 
        for fname in [todo_name, toreview_name, done_name, discarded_name] 
        if gfile['title'] == fname
    }"""
    
    required_folders = [todo_name, toreview_name, done_name, discarded_name]
    missing_folders = [name for name
    in required_folders if name not in folder_dict]
    if missing_folders:
        raise ValueError(f"Las siguientes carpetas no se encontraron en Drive: {missing_folders}")
    
    # Crear diccionario con carpetas encontradas por nombre
    nombres_buscados = [todo_name, toreview_name, done_name, discarded_name]

    folder_dict = {}
    for folder in found_folders:
        title = folder['title']
        if title in nombres_buscados:
            print(f"✅ Carpeta '{title}' existe en Drive.")
            folder_dict[title] = folder
    # Helper function to create dictionaries for each folder
    def create_dict(folder_id):
        # List all files in the folder and include metadata in the query
        file_list = drive.ListFile({
            "q": f"trashed=false and '{folder_id}' in parents",
            "fields": "items(id, title, mimeType, lastModifyingUser/displayName, modifiedDate)"
        }).GetList()

        # Group files by their base name (without extension)
        grouped_files = {}
        for file in file_list:
            base_name = os.path.splitext(file['title'])[0]
            if base_name not in grouped_files:
                grouped_files[base_name] = []
            grouped_files[base_name].append(file)

        # Sort the dictionary by file name (key) alphabetically
        return dict(sorted(grouped_files.items()))

    todo_dict = create_dict(folder_dict[todo_name]['id'])
    toreview_dict = create_dict(folder_dict[toreview_name]['id'])
    done_dict = create_dict(folder_dict[done_name]['id'])
    discarded_dict = create_dict(folder_dict[discarded_name]['id'])

    return folder_dict, todo_dict, toreview_dict, done_dict, discarded_dict

def move_file(drive, file_id, folder_id):
    """Moves file to a specific folder.
    
    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    file_id : str
        Id of the file to be moved, obtained from it's associated 
        ``GoogleDriveFile`` instance.
    folder_id : str
        Destination folder's id, obtained from it's associated 
        ``GoogleDriveFile`` instance.

    """
    # Create GoogleDriveFile instance using file id.
    file = drive.CreateFile({'id': file_id})
    # Set parents using folder id.
    file['parents'] = [{"kind": "drive#parentReference", 
                         "id": folder_id}]
    # Update file.
    file.Upload()

# The idea here is to use this function's output with the read_points function.
def get_gdrive_csv_path(drive, file_list, dir, name='zdummy'):
    """Download csv file from GoogleDrive.
    
    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    file_list : list of GoogleDriveFile
        List containing ``GoogleDriveFile`` instances for files that
        share the same file name as the csv file. For instance, if the
        csv has the name `myfile.csv`, `file_list` should be 
        `todo_dict['myfile'].

    Returns
    -------
    dummy_path : str
        Path to csv file.

    Raises
    ------
    FileNotFoundError
        If the csv file doesn't exist.
    """
    # Filter file.
    gfile = next(
        filter(lambda x: x['mimeType'] == 'text/csv', file_list), None
    )

    # Check file.
    if gfile is None:
        raise FileNotFoundError(f"Specified csv file doesn't exist.")

    # Get extension without the dot
    file_extension = os.path.splitext(gfile["title"])[1].lstrip(".")  

    # Construct the path for the downloaded file
    dummy_path = f'{dir}/{name}.{file_extension}' 

    # Download the csv file to the specified path
    drive.CreateFile({'id': gfile['id']}).GetContentFile(dummy_path) 

    return dummy_path

def get_gdrive_json_path(drive, file_list):
    """Download json file from GoogleDrive.
    
    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    file_list : list of GoogleDriveFile
        List containing ``GoogleDriveFile`` instances for files that
        share the same file name as the csv file. For instance, if the
        json has the name `myfile.json`, `file_list` should be 
        `todo_dict['myfile'].

    Returns
    -------
    dummy_path : str
        Path to json file.

    Raises
    ------
    FileNotFoundError
        If the json file doesn't exist.
    """
    # Filter file.
    gfile = next(
        filter(lambda x: x['mimeType'] == 'application/json', file_list), None
    )

    # Check file.
    if gfile is None:
        raise FileNotFoundError(f"Specified json file doesn't exist.")

    dummy_path = f'zdummy.{gfile["fileExtension"]}'
    # Download csv file to dummy path.
    drive.CreateFile({'id': gfile['id']}).GetContentFile(dummy_path)

    return dummy_path

def get_gdrive_image_path(drive, file_list, dir, name='zdummy'):
    """Download image file from GoogleDrive.
    
    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    file_list : list of GoogleDriveFile
        List containing ``GoogleDriveFile`` instances for files that
        share the same file name as the image file. For instance, if the
        image has the name `myfile.png`, `file_list` should be 
        `todo_dict['myfile'].

    Returns
    -------
    dummy_path : str
        Path to image file.

    Raises
    ------
    FileNotFoundError
        If the image file doesn't exist.
    """   
    # Filter file.
    gfile = next(
        filter(
            lambda x: x["mimeType"] in ["image/jpeg", "image/png"], file_list
        ),
        None,
    ) # For image maybe x['mimeType'].startswith('image/')? To handle all img types?

    # Check file.
    if gfile is None:
        raise FileNotFoundError(f"Specified image file doesn't exist.")

    # print(file_list)

    # Get extension without the dot
    file_extension = os.path.splitext(gfile["title"])[1].lstrip(".")  

    # Construct the path for the downloaded file
    dummy_path = f'{dir}/{name}.{file_extension}' 

    # Download the image file to the specified path
    drive.CreateFile({'id': gfile['id']}).GetContentFile(dummy_path) 

    return dummy_path

def get_gdrive_csv_bytes(drive, file_list):
    """Download csv file from GoogleDrive.
    
    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    file_list : list of GoogleDriveFile
        List containing ``GoogleDriveFile`` instances for files that
        share the same file name as the csv file. For instance, if the
        csv has the name `myfile.csv`, `file_list` should be 
        `todo_dict['myfile'].

    Returns
    -------
    csv_bytes : bytes
        A bytes object containing the csv file.

    Raises
    ------
    FileNotFoundError
        If the csv file doesn't exist.
    """
    # Filter file.
    gfile = next(
        filter(lambda x: x['mimeType'] == 'text/csv', file_list), None
    )

    # Check file.
    if gfile is None:
        raise FileNotFoundError(f"Specified csv file doesn't exist.")

    # Download csv file to bytes.
    csv_bytes = (
        drive.CreateFile({"id": gfile["id"]})
        .GetContentIOBuffer(mimetype=gfile["mimeType"])
        .read()
    )

    return csv_bytes

def get_gdrive_json_bytes(drive, file_list):
    """Download json file from GoogleDrive.
    
    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    file_list : list of GoogleDriveFile
        List containing ``GoogleDriveFile`` instances for files that
        share the same file name as the json file. For instance, if the
        json has the name `myfile.json`, `file_list` should be 
        `todo_dict['myfile'].

    Returns
    -------
    json_bytes : bytes
        A bytes object containing the json file.

    Raises
    ------
    FileNotFoundError
        If the json file doesn't exist.
    """
    # Filter file.
    gfile = next(
        filter(lambda x: x['mimeType'] == 'application/json', file_list), None
    )

    # Check file.
    if gfile is None:
        raise FileNotFoundError(f"Specified json file doesn't exist.")

    # Download json file to bytes.
    json_bytes = (
        drive.CreateFile({"id": gfile["id"]})
        .GetContentIOBuffer(mimetype=gfile["mimeType"])
        .read()
    )

    return json_bytes

def get_gdrive_image_bytes(drive, file_list):
    """Download image file from GoogleDrive.
    
    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    file_list : list of GoogleDriveFile
        List containing ``GoogleDriveFile`` instances for files that
        share the same file name as the image file. For instance, if the
        image has the name `myfile.png`, `file_list` should be 
        `todo_dict['myfile'].

    Returns
    -------
    img_bytes : bytes
        A bytes object containing the image file.

    Raises
    ------
    FileNotFoundError
        If the image file doesn't exist.
    """   
    # Filter file.
    gfile = next(
        filter(
            lambda x: x["mimeType"] in ["image/jpeg", "image/png"], todo_dict["todo"]
        ),
        None,
    ) # For image maybe x['mimeType'].startswith('image/')? To handle all img types?

    # Check file.
    if gfile is None:
        raise FileNotFoundError(f"Specified image file doesn't exist.")

    # Download image file to bytes.
    img_bytes = (
        drive.CreateFile({"id": gfile["id"]})
        .GetContentIOBuffer(mimetype=gfile["mimeType"])
        .read()
    )

    return img_bytes

def update_gdrive_csv(drive, file_list, x_coords, y_coords, labels):
    """Update csv file from GoogleDrive.
    
    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    file_list : list of GoogleDriveFile
        List containing ``GoogleDriveFile`` instances for files that
        share the same file name as the csv file. For instance, if the
        csv has the name `myfile.csv`, `file_list` should be 
        `todo_dict['myfile'].
    x_coords : array-like
        For each point, x-coordinates.
    y_coords : array-like
        For each point, y-coordinates.
    labels : array-like
        For each point, label.

    Raises
    ------
    FileNotFoundError
        If the csv file doesn't exist.
    """
    # Get string csv.
    result = [["X", "Y", "Label"]] + [
        [str(x), str(y), str(l)] for x, y, l in zip(x_coords, y_coords, labels)
    ]
    # (Comma separated)
    result_str = '\n'.join([','.join(row) for row in result])
    
    # Filter old file.
    gfile = next(
        filter(lambda x: x['mimeType'] == 'text/csv', file_list), None
    )

    # Check file.
    if gfile is None:
        raise FileNotFoundError(f"Specified csv file doesn't exist.")

    # Get old file by id.
    csvfile = drive.CreateFile({"id": gfile["id"]})

    # Modify content.
    csvfile.SetContentString(result_str)
    
    # Upload.
    csvfile.Upload()

def update_gdrive_json(drive, file_list, json_dict):
    # json dict as made here (#L162): 
    # https://github.com/Digpatho1/ki67/blob/main/Segmentator/generate_masks.py
    """Update json file from GoogleDrive.
    
    Parameters
    ----------
    drive : GoogleDrive
        Drive as a PyDrive2 ``GoogleDrive`` object.
    file_list : list of GoogleDriveFile
        List containing ``GoogleDriveFile`` instances for files that
        share the same file name as the json file. For instance, if the
        json has the name `myfile.json`, `file_list` should be 
        `todo_dict['myfile'].
    json_dict : dict
        Dictionary to save as json file.
    
    Raises
    ------
    FileNotFoundError
        If the json file doesn't exist.
    """
    # Get json string.
    result_str = json.dumps(json_dict)
    
    # Filter old file.
    gfile = next(
        filter(lambda x: x['mimeType'] == 'application/json', file_list), None
    )

    # Check file.
    if gfile is None:
        raise FileNotFoundError(f"Specified json file doesn't exist.")

    # Get old file by id.
    jsonfile = drive.CreateFile({"id": gfile["id"]})
    
    # Modify content.
    jsonfile.SetContentString(result_str)
    
    # Upload.
    jsonfile.Upload()

def upload_file_to_gdrive(drive, file_path, folder_id):
    """Uploads a local file to Google Drive in the specified directory.

    Parameters
    ----------
    drive : GoogleDrive
        Instance of GoogleDrive from PyDrive2.
    file_path : str
        Path to the local file to be uploaded.
    folder_id : str
        ID of the destination directory in Google Drive.
    """
    file_name = os.path.basename(file_path)
    gfile = drive.CreateFile({'title': file_name, 'parents': [{'id': folder_id}]})
    gfile.SetContentFile(file_path)
    gfile.Upload()
    
    """file_name = os.path.basename(file_path)

    # usar unidades compartidas (Shared Drives)
    gfile = drive.CreateFile({
        'title': file_name,
        'parents': [{'id': folder_id}],
        'supportsAllDrives': True
    })

    gfile.SetContentFile(file_path)

    #  este parámetro evita el error 403
    gfile.Upload(param={'supportsAllDrives': True})"""

def get_credentials():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token_file:
            creds = pickle.load(token_file)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('client_secrets.json', SCOPES)
            creds = flow.run_local_server(port=0)  # Cambiar a run_console() si no tenés navegador

        with open('token.pickle', 'wb') as token_file:
            pickle.dump(creds, token_file)

    return creds

# Ejecutar
if __name__ == '__main__':
    # Path to keys.
    path_to_json_key = 'anotadorstreamlit.json'
    #creds = get_credentials()
    creds = get_credentials()
    service = build('drive', 'v3', credentials=creds)

    print("Credenciales obtenidas correctamente.",creds)
    # Folders where done and to-do images, csvs and jsons are stored.
    # Nombres de las carpetas en Google Drive
    """
    todo_name = 'F1'
    toreview_name = 'ToReview'
    done_name = 'F2'
    discarded_name = 'Discarded' 
    """
    todo_name = 'anotaciones_a_hacer'
    toreview_name = 'anotaciones_a_revisar'
    done_name = 'anotaciones_ok'
    discarded_name = 'anotaciones_descartadas'
    # Conectarse al drive
    drive = get_drive(path_to_json_key)

    # Obtener los diccionarios
    folder_dict, todo_dict, toreview_dict, done_dict, discarded_dict = get_dicts(
        drive, todo_name, toreview_name, done_name, discarded_name
    )
    
    # Drive info.
    about = drive.GetAbout()
    
    # Print some info.
    print('Current user name: {}'.format(about['name']))
    print('Root folder ID: {}'.format(about['rootFolderId']))
    print('Total quota (bytes): {}'.format(about['quotaBytesTotal']))
    print('Used quota (bytes): {}'.format(about['quotaBytesUsed']))
