import os
import json
from itertools import groupby
from datetime import datetime, timedelta
#from io import BytesIO, StringIO
import base64
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from oauth2client.service_account import ServiceAccountCredentials
from google.oauth2 import service_account

import tempfile

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle

from googleapiclient.discovery import build


import streamlit as st
import json
# Importaciones para PyDrive2
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from oauth2client.service_account import ServiceAccountCredentials # Necesario para ServiceAccountCredentials

# Importaciones para google-api-python-client (si aún las necesitas para otras APIs, si no, se pueden quitar)
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
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
"""def get_drive_oauth_(secrets):
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

    import tempfile, json, base64, os

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
    return drive"""
# --- Advertencia importante sobre el token ---
import streamlit as st
import base64
import json
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


def get_drive_service_account_(_secrets):
    """
    Inicializa y devuelve el servicio de Google Drive usando una Cuenta de Servicio.
    Los secretos se cargan directamente de st.secrets.
    """
    try:
        # Cargar las credenciales de la cuenta de servicio desde st.secrets
        # El JSON de las credenciales está almacenado como una cadena multi-línea en secrets.toml
        credentials_json_str = _secrets["service_account"]["credentials"]
        credentials_info = json.loads(credentials_json_str)

        st.success("Credenciales de Cuenta de Servicio cargadas correctamente.")

        # Definir los scopes necesarios (permisos)
        # 'https://www.googleapis.com/auth/drive' para acceso completo a Drive
        # 'https://www.googleapis.com/auth/drive.readonly' para solo lectura
        SCOPES = ['https://www.googleapis.com/auth/drive']

        # Crear el objeto de credenciales de la cuenta de servicio
        creds = service_account.Credentials.from_service_account_info(
            credentials_info, scopes=SCOPES
        )
        st.success("Objeto de credenciales de Cuenta de Servicio creado.")

        # Construir el servicio de Google Drive
        service = build('drive', 'v3', credentials=creds)
        st.success("Servicio de Google Drive inicializado.")
        return service

    except KeyError as e:
        st.error(f"Error al cargar secretos de la Cuenta de Servicio: {e}. "
                 "Asegúrate de que tu `secrets.toml` tenga la sección `[service_account]` "
                 "y la clave `credentials`.")
        return None
    except json.JSONDecodeError as e:
        st.error(f"Error al decodificar el JSON de las credenciales de la Cuenta de Servicio: {e}. "
                 "Verifica el formato JSON en tu `secrets.toml`.")
        return None
    except Exception as e:
        st.error(f"Ocurrió un error inesperado al inicializar el servicio de Drive con Cuenta de Servicio: {e}")
        return None





"""def get_drive_service_account(secrets):
     # El JSON viene como string, parsearlo a dict
    creds_json_str = secrets["service_account"]["credentials"]
    creds_dict = json.loads(creds_json_str)
    
    # Crear archivo temporal con las credenciales
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as f:
        json.dump(creds_dict, f)
        f.flush()
        creds_path = f.name

    gauth = GoogleAuth()
    gauth.settings['client_config_backend'] = 'service'
    gauth.settings['service_config'] = {
        'client_json_file_path': creds_path,
    }

    gauth.ServiceAuth()  # Autentica con service account
    drive = GoogleDrive(gauth)
    return drive"""

def get_drive_service_account(secrets):
    # Extraer las credenciales como string
    creds_json_str = secrets["oauth_client"]["credentials"]

    # Convertir el string a dict
    creds_dict = json.loads(creds_json_str)

    # Guardar el dict como archivo temporal
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as f:
        json.dump(creds_dict, f)
        f.flush()
        creds_path = f.name

    # Autenticación con cuenta de servicio
    gauth = GoogleAuth()
    gauth.settings["client_config_backend"] = "service"
    gauth.settings["service_config"] = {
        "client_json_file_path": creds_path,
        "client_user_email": creds_dict["client_email"]  # IMPORTANTE
    }
    gauth.ServiceAuth()

    # Crear el objeto Google Drive autenticado
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



st.title("Acceso a Google Drive con Cuenta de Servicio (usando PyDrive2)")
st.write("Demostración de cómo acceder a Google Drive usando una Cuenta de Servicio desde secretos de Streamlit Cloud con PyDrive2.")

# --- Instrucciones importantes para el secreto ---
st.info(
    "**¡IMPORTANTE!** Para que esta aplicación funcione, tu archivo `.streamlit/secrets.toml` "
    "debe contener las credenciales de tu Cuenta de Servicio de Google Drive. "
    "Debe tener una sección `[service_account]` con la clave `credentials` "
    "que contenga el JSON completo de tu clave de cuenta de servicio."
    "\n\n**Ejemplo de secrets.toml:**\n"
    "```toml\n"
    "[google_drive]\n"
    "parent_folder_id = \"0AJUJP-MkkGuoUk9PVA\"\n"
    "\n"
    "[service_account]\n"
    "credentials = '''\n"
    "{\n"
    "  \"type\": \"service_account\",\n"
    "  \"project_id\": \"tu-project-id\",\n"
    "  \"private_key_id\": \"tu-private-key-id\",\n"
    "  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n\",\n"
    "  \"client_email\": \"tu-cuenta-de-servicio@tu-project-id.iam.gserviceaccount.com\",\n"
    "  \"client_id\": \"tu-client-id\",\n"
    "  \"auth_uri\": \"[https://accounts.google.com/o/oauth2/auth](https://accounts.google.com/o/oauth2/auth)\",\n"
    "  \"token_uri\": \"[https://oauth2.googleapis.com/token](https://oauth2.googleapis.com/token)\",\n"
    "  \"auth_provider_x509_cert_url\": \"[https://www.googleapis.com/oauth2/v1/certs](https://www.googleapis.com/oauth2/v1/certs)\",\n"
    "  \"client_x509_cert_url\": \"[https://www.googleapis.com/robot/v1/metadata/x509/tu-cuenta-de-servicio%40tu-project-id.iam.gserviceaccount.com](https://www.googleapis.com/robot/v1/metadata/x509/tu-cuenta-de-servicio%40tu-project-id.iam.gserviceaccount.com)\",\n"
    "  \"universe_domain\": \"googleapis.com\"\n"
    "}\n"
    "'''\n"
    "```\n"
    "Asegúrate de que la clave de tu cuenta de servicio esté entre tres comillas simples (`'''`) "
    "para manejar correctamente las nuevas líneas y comillas internas."
)


@st.cache_resource
def get_drive_from_secrets(_secrets): # Cambiado el nombre de la función y el argumento para cache
    """
    Obtiene la instancia de GoogleDrive de PyDrive2 utilizando las credenciales
    de la cuenta de servicio directamente desde los secretos de Streamlit.
    """
    try:
        # Cargar las credenciales de la cuenta de servicio desde st.secrets
        credentials_json_str = _secrets["service_account"]["credentials"]
        credentials_info = json.loads(credentials_json_str)

        st.success("Credenciales de Cuenta de Servicio cargadas correctamente.")

        # Set scope. This particular choice makes sure to give full access.
        scope = ["https://www.googleapis.com/auth/drive"]

        # Authorization instance.
        gauth = GoogleAuth()
        gauth.auth_method = 'service'
        # Usar from_json_keyfile_dict para pasar el diccionario directamente
        gauth.credentials = ServiceAccountCredentials.from_json_keyfile_dict(
            credentials_info,
            scope
        )

        # Get drive.
        drive = GoogleDrive(gauth)
        st.success("Instancia de GoogleDrive (PyDrive2) inicializada.")
        return drive

    except KeyError as e:
        st.error(f"Error al cargar secretos de la Cuenta de Servicio: {e}. "
                 "Asegúrate de que tu `secrets.toml` tenga la sección `[service_account]` "
                 "y la clave `credentials`.")
        return None
    except json.JSONDecodeError as e:
        st.error(f"Error al decodificar el JSON de las credenciales de la Cuenta de Servicio: {e}. "
                 "Verifica el formato JSON en tu `secrets.toml`.")
        return None
    except Exception as e:
        st.error(f"Ocurrió un error inesperado al inicializar el servicio de Drive con Cuenta de Servicio: {e}")
        return None

def setup_drive(session_state):
    """
    Configura el servicio de Google Drive (usando PyDrive2) y lo almacena en el estado de la sesión.
    Utiliza la autenticación de Cuenta de Servicio.
    """
    if "drive_instance" not in session_state or session_state.drive_instance is None:
        st.info("Inicializando servicio de Google Drive (PyDrive2) con Cuenta de Servicio...")
        # Llama a la función que usa la cuenta de servicio
        drive = get_drive_from_secrets(st.secrets)
        session_state.drive_instance = drive # Almacenar la instancia de PyDrive2
    else:
        st.success("Servicio de Google Drive (PyDrive2) ya inicializado en la sesión.")
    return session_state.drive_instance


# --- Ejecución principal de la aplicación Streamlit ---
# Llama a setup_drive para obtener o inicializar el servicio de Drive
drive_instance = setup_drive(st.session_state)

# Obtener el ID de la carpeta padre desde los secretos
try:
    PARENT_FOLDER_ID = st.secrets["google_drive"]["parent_folder_id"]
    st.info(f"ID de la carpeta padre configurado: `{PARENT_FOLDER_ID}`")
except KeyError:
    st.warning("No se encontró 'parent_folder_id' en la sección '[google_drive]' de `secrets.toml`. "
               "Algunas operaciones podrían no funcionar correctamente.")
    PARENT_FOLDER_ID = None


if drive_instance:
    st.header("Operaciones de Google Drive (usando PyDrive2)")

    # --- Listar archivos ---
    st.subheader("Listar Archivos en Mi Drive")
    if st.button("Listar Archivos"):
        try:
            # PyDrive2 usa un formato de consulta diferente (q)
            # Para listar todos los archivos:
            # file_list = drive_instance.ListFile({'q': "'root' in parents and trashed=false"}).GetList()
            # Para listar archivos en una carpeta específica:
            query = f"'{PARENT_FOLDER_ID}' in parents and trashed=false" if PARENT_FOLDER_ID else "'root' in parents and trashed=false"
            file_list = drive_instance.ListFile({'q': query}).GetList()


            if not file_list:
                st.write('No se encontraron archivos.')
            else:
                st.write('Archivos:')
                for file_item in file_list:
                    st.write(f"- {file_item['title']} (ID: {file_item['id']}, Tipo: {file_item['mimeType']})")
        except Exception as e:
            st.error(f"Ocurrió un error al listar archivos: {e}")
            st.info("Asegúrate de que la cuenta de servicio tiene permisos de lectura en Drive.")

    # --- Crear un archivo de texto ---
    st.subheader("Crear un Archivo de Texto")
    file_name = st.text_input("Nombre del archivo a crear:", "mi_archivo_streamlit_pydrive.txt")
    file_content = st.text_area("Contenido del archivo:", "Hola desde Streamlit Cloud con PyDrive2!")

    if st.button("Crear Archivo"):
        try:
            # Crear un nuevo archivo de PyDrive2
            file_obj = drive_instance.CreateFile({'title': file_name, 'mimeType': 'text/plain'})
            file_obj.SetContentString(file_content)

            if PARENT_FOLDER_ID:
                file_obj['parents'] = [{'id': PARENT_FOLDER_ID}]

            file_obj.Upload() # Subir el archivo
            st.success(f"Archivo '{file_name}' creado con ID: {file_obj['id']}")
            if PARENT_FOLDER_ID:
                st.info(f"Creado en la carpeta con ID: `{PARENT_FOLDER_ID}`")
        except Exception as e:
            st.error(f"Ocurrió un error al crear el archivo: {e}")
            st.info("Asegúrate de que la cuenta de servicio tiene permisos de escritura en la carpeta especificada en Drive.")

    # --- Eliminar un archivo (solo para demostración, ¡usar con precaución!) ---
    st.subheader("Eliminar un Archivo (¡Precaución!)")
    file_id_to_delete = st.text_input("ID del archivo a eliminar (¡CUIDADO!):")
    if st.button("Eliminar Archivo", help="Esto eliminará permanentemente el archivo con el ID proporcionado."):
        if st.checkbox("Confirmar eliminación"):
            try:
                # Obtener el archivo por ID y luego eliminarlo
                file_to_delete = drive_instance.CreateFile({'id': file_id_to_delete})
                file_to_delete.Delete()
                st.success(f"Archivo con ID '{file_id_to_delete}' eliminado correctamente.")
            except Exception as e:
                st.error(f"Ocurrió un error al eliminar el archivo: {e}")
                st.info("Asegúrate de que el ID es correcto y la cuenta de servicio tiene permisos de eliminación.")
        else:
            st.warning("Por favor, marca la casilla de confirmación para eliminar el archivo.")
