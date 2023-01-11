# pip install pysnmp
# pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib

import os.path
from pysnmp.hlapi import *
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
SAMPLE_SPREADSHEET_ID = 'ID_PLANILHA_GOOGLE'
RANGE_IPS_MODELOS = 'Impressoras!C5:E111' # Colunas: NOME, IP, MODELO
RANGE_GRAVACOES = 'Contadores!A2:D150' # Colunas: NOME, IP, MODELO, CONTADOR

# Autenticar no google com oauth
def autorizar_acesso():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
       
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
            
    return creds

# Busca as impressoras e os modelos da planilha
def listar_impressoras(creds):
    try: 
        service = build('sheets', 'v4', credentials=creds)
        
        sheet = service.spreadsheets()
        result = sheet.values().get(spreadsheetId=SAMPLE_SPREADSHEET_ID,
                                    range=RANGE_IPS_MODELOS).execute()
        values = result.get('values', [])
        
        if not values:
            print('No data found.')
            return
        
        return values
            
    except HttpError as err:
        print(err)

# para impressoras Kyocera e Canon - Auth no Priv
def captura_contador_auth_nopriv(ip, oid): # para Kyocera e Canon
    iterator = getCmd(
        SnmpEngine(),
        UsmUserData('usuario', 'senha'), # usuario, senha
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        return f"Erro: {errorIndication}"
    elif errorStatus:
        return f"Erro: {errorStatus}"
    else:
        for varBind in varBinds:
            value = str(varBind)
            return value[value.find('=')+1:]

# para impressoras Samsung, OKI, Xerox, Brother e HP - Auth e Priv
def captura_contador_auth_priv(ip, oid): 
    iterator = getCmd(
        SnmpEngine(),
        UsmUserData('usuario', 'senha', 'senha_privacidade'), # usuario, senha, privacidade
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        return f"Erro: {errorIndication}"
    elif errorStatus:
        return f"Erro: {errorStatus}"
    else:
        for varBind in varBinds:
            value = str(varBind)
            return value[value.find('=')+1:]

# Percorre a lista de impressoras para verificar o modelo/marca
# Cada marca possui um OID específico para capturar o contador
def verifica_modelo(impressoras):
    lista_contadores = []
    
    for imp in impressoras:
        if imp[1].find('\\') < 0:
            print(f"Capturando contador da impressora {imp[0]} - {imp[1]}")
            if imp[2].find('Xerox') >= 0:
                ip = imp[1]
                oid = '.1.3.6.1.4.1.253.8.53.13.2.1.6.1.20.34'
                contador = captura_contador_auth_priv(ip, oid)
                imp.append(contador)
                lista_contadores.append(imp)            
            elif imp[2].find('Kyocera') >= 0:
                ip = imp[1]
                oid = '.1.3.6.1.4.1.1347.43.10.1.1.12.1.1'
                contador = captura_contador_auth_nopriv(ip, oid)
                imp.append(contador)
                lista_contadores.append(imp)  
            elif imp[2].find('Samsung') >= 0:
                ip = imp[1]
                oid = '.1.3.6.1.4.1.236.11.5.11.53.11.1.2.0'
                contador = captura_contador_auth_priv(ip, oid)
                imp.append(contador)
                lista_contadores.append(imp)  
            elif imp[2].find('Canon') >= 0:
                ip = imp[1]
                oid = '.1.3.6.1.4.1.1602.1.11.2.1.1.3.1'
                contador = captura_contador_auth_nopriv(ip, oid)
                imp.append(contador)
                lista_contadores.append(imp)       
            elif imp[2].find('HP') >= 0:
                ip = imp[1]
                oid = '.1.3.6.1.4.1.236.11.5.11.53.11.1.2.0'
                contador = captura_contador_auth_priv(ip, oid)
                imp.append(contador)
                lista_contadores.append(imp)  
            elif imp[2].find('Brother') >= 0:
                ip = imp[1]
                oid = '.1.1.1.1.1.1' # Não tenho o oid correto, então ainda não funciona para essa marca
                contador = captura_contador_auth_priv(ip, oid)
                imp.append(contador)
                lista_contadores.append(imp)  
            elif imp[2].find('OKI') >= 0:
                ip = imp[1]
                oid = '.1.1.1.1.1.1' # Não tenho o oid correto,  então ainda não funciona para essa marca
                contador = captura_contador_auth_priv(ip, oid)
                imp.append(contador)
                lista_contadores.append(imp)  
            
    return lista_contadores

def grava_informacoes(creds, lista):
    try:
        service = build('sheets', 'v4', credentials=creds)
        sheet = service.spreadsheets()
        values = lista
        body = {
            'values': values
        }
        result = service.spreadsheets().values().update(
            spreadsheetId=SAMPLE_SPREADSHEET_ID, range=RANGE_GRAVACOES,
            valueInputOption="USER_ENTERED", body=body).execute()
        
        print(f"{result.get('updatedCells')} cells updated.")
        return 
        
    except HttpError as error:
        return f"Erro: {error}"
    

# Executa
if __name__ == '__main__':
    creds = autorizar_acesso()
    impressoras = listar_impressoras(creds)
    lista_contadores = verifica_modelo(impressoras)
    grava_informacoes(creds, lista_contadores)